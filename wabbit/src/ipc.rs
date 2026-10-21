use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
};

const RUN_REQUEST: u8 = 0b01;
const RECONFIGURE_REQUEST: u8 = 0b10;
const COMPLETED_RESPONSE: u8 = 0b01;
const FAILED_RESPONSE: u8 = 0b10;
const RECONFIGURED_RESPONSE: u8 = 0b11;

#[derive(Debug)]
enum Request<'a> {
    Run(RunTask<'a>),
    Reconfigure(Reconfigure<'a>),
}

#[derive(Debug)]
struct RunTask<'a> {
    program: &'a str,
    args: &'a [String],
}

#[derive(Debug)]
struct Reconfigure<'a> {
    configuration: &'a crate::filesystem::RootFSConfig,
}

#[derive(Debug)]
pub struct TaskOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
enum Response {
    Completed(CompletedTask),
    Failed(TaskError),
    Reconfigured,
}

#[derive(Debug)]
struct CompletedTask {
    output: TaskOutput,
}

#[derive(Debug)]
struct TaskError {
    message: String,
}

pub struct NamespaceIpc {
    socket_path: PathBuf,
}

impl NamespaceIpc {
    pub fn connect(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub async fn run_task<I, S>(&self, program: &str, args: I) -> Result<TaskOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let request = encode_request(&Request::Run(RunTask {
            program,
            args: &args,
        }))?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .context("connecting to namespace server")?;
        stream.write_all(&request).await?;
        stream.shutdown().await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        match decode_response(&response)? {
            Response::Completed(completed) => Ok(completed.output),
            Response::Failed(error) => bail!(error.message),
            Response::Reconfigured => bail!("unexpected filesystem response"),
        }
    }

    pub async fn reconfigure_filesystems(
        &self,
        configuration: &crate::filesystem::RootFSConfig,
    ) -> Result<()> {
        let request = encode_request(&Request::Reconfigure(Reconfigure { configuration }))?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .context("connecting to namespace server")?;
        stream.write_all(&request).await?;
        stream.shutdown().await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        match decode_response(&response)? {
            Response::Reconfigured => Ok(()),
            Response::Failed(error) => bail!(error.message),
            Response::Completed(_) => bail!("unexpected task response"),
        }
    }
}

pub async fn run_server(
    socket_path: PathBuf,
    configuration: crate::filesystem::RootFSConfig,
) -> Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding IPC socket {}", socket_path.display()))?;
    let configuration = Arc::new(Mutex::new(configuration));
    loop {
        let (stream, _) = listener.accept().await?;
        let configuration = Arc::clone(&configuration);
        tokio::spawn(async move {
            if let Err(error) = handle_task(stream, configuration).await {
                log::error!("IPC task failed: {error:#}");
            }
        });
    }
}

async fn handle_task(
    stream: UnixStream,
    configuration: Arc<Mutex<crate::filesystem::RootFSConfig>>,
) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut request = Vec::new();
    read_half.read_to_end(&mut request).await?;
    let response = match decode_request(&request) {
        Ok(RequestOwned::Run(request)) => match Command::new(&request.program)
            .args(&request.args)
            .output()
            .await
        {
            Ok(output) => encode_response(&Response::Completed(CompletedTask {
                output: TaskOutput {
                    status: output.status.code(),
                    stdout: output.stdout,
                    stderr: output.stderr,
                },
            }))?,
            Err(error) => encode_response(&Response::Failed(TaskError {
                message: error.to_string(),
            }))?,
        },
        Ok(RequestOwned::Reconfigure(request)) => {
            let mut current = configuration
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem configuration lock poisoned"))?;
            match crate::filesystem::apply_rootfs_config(&request.configuration, true) {
                Ok(()) => {
                    *current = request.configuration;
                    encode_response(&Response::Reconfigured)?
                }
                Err(error) => encode_response(&Response::Failed(TaskError {
                    message: format!("reconfiguring filesystems: {error}"),
                }))?,
            }
        }
        Err(error) => encode_response(&Response::Failed(TaskError {
            message: format!("invalid task request: {error}"),
        }))?,
    };
    write_half.write_all(&response).await?;
    Ok(())
}

#[derive(Debug)]
enum RequestOwned {
    Run(RunTaskOwned),
    Reconfigure(ReconfigureOwned),
}

#[derive(Debug)]
struct RunTaskOwned {
    program: String,
    args: Vec<String>,
}

#[derive(Debug)]
struct ReconfigureOwned {
    configuration: crate::filesystem::RootFSConfig,
}

fn encode_request(request: &Request<'_>) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    match request {
        Request::Run(task) => {
            output.push(RUN_REQUEST);
            put_string(&mut output, task.program)?;
            put_u32(&mut output, task.args.len())?;
            for arg in task.args {
                put_string(&mut output, arg)?;
            }
        }
        Request::Reconfigure(request) => {
            output.push(RECONFIGURE_REQUEST);
            let configuration = serde_json::to_string(request.configuration)?;
            put_string(&mut output, &configuration)?;
        }
    }
    Ok(output)
}

fn decode_request(bytes: &[u8]) -> Result<RequestOwned> {
    let mut cursor = Cursor::new(bytes);
    match cursor.byte()? {
        RUN_REQUEST => {
            let program = cursor.string()?;
            let count = cursor.u32()?;
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                args.push(cursor.string()?);
            }
            cursor.finish()?;
            Ok(RequestOwned::Run(RunTaskOwned { program, args }))
        }
        RECONFIGURE_REQUEST => {
            let configuration = serde_json::from_str(&cursor.string()?)
                .context("invalid filesystem configuration")?;
            cursor.finish()?;
            Ok(RequestOwned::Reconfigure(ReconfigureOwned {
                configuration,
            }))
        }
        _ => bail!("unknown IPC request"),
    }
}

fn encode_response(response: &Response) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    match response {
        Response::Completed(task) => {
            output.push(COMPLETED_RESPONSE);
            match task.output.status {
                Some(status) => {
                    output.push(1);
                    put_i32(&mut output, status);
                }
                None => output.push(0),
            }
            put_bytes(&mut output, &task.output.stdout)?;
            put_bytes(&mut output, &task.output.stderr)?;
        }
        Response::Failed(error) => {
            output.push(FAILED_RESPONSE);
            put_string(&mut output, &error.message)?;
        }
        Response::Reconfigured => output.push(RECONFIGURED_RESPONSE),
    }
    Ok(output)
}

fn decode_response(bytes: &[u8]) -> Result<Response> {
    let mut cursor = Cursor::new(bytes);
    let response = match cursor.byte()? {
        COMPLETED_RESPONSE => Response::Completed(CompletedTask {
            output: TaskOutput {
                status: match cursor.byte()? {
                    0 => None,
                    1 => Some(cursor.i32()?),
                    _ => bail!("invalid process status marker"),
                },
                stdout: cursor.bytes()?,
                stderr: cursor.bytes()?,
            },
        }),
        FAILED_RESPONSE => Response::Failed(TaskError {
            message: cursor.string()?,
        }),
        RECONFIGURED_RESPONSE => Response::Reconfigured,
        _ => bail!("unknown IPC response"),
    };
    cursor.finish()?;
    Ok(response)
}

fn put_u32(output: &mut Vec<u8>, value: usize) -> Result<()> {
    output.extend_from_slice(&u32::try_from(value)?.to_le_bytes());
    Ok(())
}

fn put_i32(output: &mut Vec<u8>, value: i32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    put_u32(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    put_bytes(output, value.as_bytes())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.position)
            .context("truncated IPC message")?;
        self.position += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<usize> {
        let mut value = [0; 4];
        value.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(value).try_into()?)
    }

    fn i32(&mut self) -> Result<i32> {
        let mut value = [0; 4];
        value.copy_from_slice(self.take(4)?);
        Ok(i32::from_le_bytes(value))
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let length = self.u32()?;
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?).context("IPC string is not UTF-8")
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("IPC message length overflow")?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .context("truncated IPC message")?;
        self.position = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            bail!("trailing bytes in IPC message")
        }
    }
}
