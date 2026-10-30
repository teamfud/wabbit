//! The IPC server: how a running wabbit takes orders.
//!
//! Every request is a **signed command** (see
//! [`wabbit_common::ipc_command`] for the wire layout, and `wabbit-ipc`
//! for the client that produces them). Three gates stand between a
//! request and its execution, in order:
//!
//! 1. **the signature** — Ed25519, verified against the compiled-in
//!    policy keys (the deployment's signing key signs policies *and*
//!    commands; a tampered or foreign-signed command is rejected);
//! 2. **the boot id** — the command names the boot it was minted for,
//!    and a command minted for another boot never matches this one;
//! 3. **the command id** — strictly increasing per boot, burned on
//!    acceptance, so the exact bytes of a command that already ran are
//!    rejected by construction: replaying a captured request, or
//!    double-clicking the client, gets "command id N was already used".
//!
//! Unsigned requests are refused outright (the message names the
//! client to use). The socket itself still decides *who may connect* —
//! set its ownership and permissions for the operator class you want;
//! the signature decides what a connected client may make wabbit do.
//!
//! Two commands exist:
//!
//! * **run** — execute a program in this namespace, capturing output;
//! * **reconfigure** — apply a complete *signed policy file*, which the
//!   server verifies *again*, against the same keys, before applying
//!   any of it. A reconfigure is double-signed by construction.

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
};
use wabbit_common::ipc_command::{
    self, BOOT_ID_LEN, HEADER_LEN, KIND_RECONFIGURE, KIND_RUN, SIGNATURE_LEN,
};

use crate::policy::{self, Policy};

/// The responses (the request kinds are all signed now; the old unsigned
/// ones are refused by name).
const COMPLETED_RESPONSE: u8 = 0b01;
const FAILED_RESPONSE: u8 = 0b10;
const RECONFIGURED_RESPONSE: u8 = 0b11;

/// Everything a command has to pass, kept for the server's whole life.
pub struct IpcState {
    /// The policy `reconfigure` merges into, section by section.
    active_policy: Mutex<Policy>,
    /// This boot's id, read once at startup; commands minted for any
    /// other boot never run.
    boot_id: [u8; BOOT_ID_LEN],
    /// The last command id accepted this boot. Strictly increasing, so a
    /// replayed command can never pass; burned on acceptance, so even a
    /// command whose execution later fails cannot come back.
    last_command_id: AtomicU64,
    /// The public keys a command may be signed with: the compiled-in
    /// policy keys (injected rather than read, so the tests can run the
    /// real verification with their own keys).
    public_keys: Vec<VerifyingKey>,
}

/// The server's state for a real run: the compiled-in policy keys, this
/// boot's id, and the given starting policy. Call once at startup.
pub fn server_state(policy: Policy) -> Result<Arc<IpcState>> {
    Ok(Arc::new(IpcState {
        active_policy: Mutex::new(policy),
        boot_id: read_boot_id()?,
        last_command_id: AtomicU64::new(0),
        public_keys: crate::trust::compiled_public_keys()?,
    }))
}

/// This boot's id from `/proc/sys/kernel/random/boot_id` — the canonical
/// 36-byte UUID the commands carry, dashes included, no newline.
fn read_boot_id() -> Result<[u8; BOOT_ID_LEN]> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("reading /proc/sys/kernel/random/boot_id")?;
    let bytes = text.trim().as_bytes();
    if bytes.len() != BOOT_ID_LEN || !ipc_command::is_canonical_boot_id(bytes) {
        bail!("this machine's boot id {text:?} is not a canonical UUID");
    }
    Ok(bytes.try_into().expect("the length was just checked"))
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
    policy: Policy,
}

/// Run the IPC server on `socket_path` until the process exits.
pub async fn run_server(socket_path: PathBuf, state: Arc<IpcState>) -> Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding IPC socket {}", socket_path.display()))?;
    log::info!("IPC server listening at {}", socket_path.display());
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle_task(stream, state).await {
                log::error!("IPC task failed: {error:#}");
            }
        });
    }
}

async fn handle_task(stream: UnixStream, state: Arc<IpcState>) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut request = Vec::new();
    read_half.read_to_end(&mut request).await?;
    let response = match decode_signed_command(&request, &state) {
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
            let mut current = state
                .active_policy
                .lock()
                .map_err(|_| anyhow::anyhow!("policy lock poisoned"))?;
            // Apply every section the policy contains; omitted sections are left alone.
            let applied = match &request.policy.rootfs {
                Some(rootfs) => crate::filesystem::apply_rootfs_config(rootfs, true),
                None => Ok(()),
            };
            match applied {
                Ok(()) => {
                    current.merge(request.policy);
                    encode_response(&Response::Reconfigured)?
                }
                Err(error) => encode_response(&Response::Failed(TaskError {
                    message: format!("reconfiguring filesystems: {error}"),
                }))?,
            }
        }
        Err(error) => encode_response(&Response::Failed(TaskError {
            message: format!("{error:#}"),
        }))?,
    };
    write_half.write_all(&response).await?;
    Ok(())
}

/// The three gates (see the module docs): signature, boot id, command
/// id — then the command itself. The id burns only after everything
/// before it passed.
fn decode_signed_command(bytes: &[u8], state: &IpcState) -> Result<RequestOwned> {
    let mut cursor = Cursor::new(bytes);
    let kind = cursor.byte()?;
    if kind != ipc_command::SIGNED_REQUEST {
        bail!(
            "unsigned IPC requests are not accepted; commands are signed \
             (use the wabbit-ipc client)"
        );
    }
    let signature: [u8; SIGNATURE_LEN] = cursor
        .take(SIGNATURE_LEN)?
        .try_into()
        .context("the signature is not 64 bytes")?;
    let signature = Signature::from_bytes(&signature);
    let signed = cursor.rest();

    // Gate 1: the signature, against any compiled-in key.
    let verified = state
        .public_keys
        .iter()
        .any(|key| key.verify(signed, &signature).is_ok());
    if !verified {
        bail!("the command's signature does not verify against this wabbit's keys");
    }

    // Gate 2: the boot id.
    let header = ipc_command::decode_header(signed)
        .map_err(|error| anyhow::anyhow!("decoding the command envelope: {error:?}"))?;
    if header.boot_id != state.boot_id {
        bail!("the command was minted for another boot; this boot never accepts it");
    }

    // The command itself, decoded before the id burns: a command that
    // fails to parse never reaches execution, so its signer can fix and
    // resend without wasting the id.
    let payload = signed
        .get(HEADER_LEN..)
        .context("the command envelope is shorter than its header")?;
    let decoded = match header.kind {
        KIND_RUN => {
            let mut fields = Cursor::new(payload);
            let program = fields.string()?;
            let count = fields.u32()?;
            let mut args = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                args.push(fields.string()?);
            }
            fields.finish()?;
            RequestOwned::Run(RunTaskOwned { program, args })
        }
        KIND_RECONFIGURE => {
            let mut fields = Cursor::new(payload);
            let policy = policy::from_bytes(&fields.bytes()?).context("invalid policy")?;
            fields.finish()?;
            RequestOwned::Reconfigure(ReconfigureOwned { policy })
        }
        other => bail!("unknown command kind {other}"),
    };

    // Gate 3: the command id — strictly greater than the last accepted,
    // and burned here, on acceptance.
    let id = header.command_id;
    state
        .last_command_id
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
            (id > last).then_some(id)
        })
        .map_err(|last| {
            anyhow::anyhow!(
                "command id {id} was already used this boot (last accepted: {last}); \
                 a command runs exactly once — mint a fresh one"
            )
        })?;

    Ok(decoded)
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

#[derive(Debug)]
pub struct TaskOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
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

    /// The remainder of the message, from here to its end.
    fn rest(&self) -> &'a [u8] {
        self.bytes
            .get(self.position..)
            .expect("the position never exceeds the length")
    }

    fn finish(&self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            bail!("trailing bytes in IPC message")
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use wabbit_common::ipc_command::CommandHeader;

    use super::*;

    fn test_state(keys: &[VerifyingKey], last_command_id: u64) -> Arc<IpcState> {
        Arc::new(IpcState {
            active_policy: Mutex::new(Policy::default()),
            boot_id: read_boot_id().expect("the test host has a boot id"),
            last_command_id: AtomicU64::new(last_command_id),
            public_keys: keys.to_vec(),
        })
    }

    /// A signed request, exactly as the client builds them, with full
    /// control over the header fields the gates check.
    fn signed_request(
        signing_key: &SigningKey,
        kind: u8,
        boot_id: [u8; BOOT_ID_LEN],
        command_id: u64,
        blob: &[u8],
    ) -> Vec<u8> {
        let header = CommandHeader {
            kind,
            boot_id,
            command_id,
        };
        let payload = &blob[1..];
        let mut signed = vec![0u8; CommandHeader::signed_len(payload.len())];
        header.encode(payload, &mut signed).unwrap();
        let signature = signing_key.sign(&signed);
        let mut request = vec![ipc_command::SIGNED_REQUEST];
        request.extend_from_slice(&signature.to_bytes());
        request.extend_from_slice(&signed);
        request
    }

    fn run_blob(program: &str, args: &[&str]) -> Vec<u8> {
        let mut blob = vec![KIND_RUN];
        put_string(&mut blob, program).unwrap();
        put_u32(&mut blob, args.len()).unwrap();
        for arg in args {
            put_string(&mut blob, arg).unwrap();
        }
        blob
    }

    fn test_boot_id() -> [u8; BOOT_ID_LEN] {
        read_boot_id().unwrap()
    }

    #[test]
    fn a_signed_command_decodes() {
        let signing_key = SigningKey::from_bytes(&[1; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        let request = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            1,
            &run_blob("sh", &["-c", "uptime"]),
        );
        match decode_signed_command(&request, &state).unwrap() {
            RequestOwned::Run(task) => {
                assert_eq!(task.program, "sh");
                assert_eq!(task.args, ["-c", "uptime"]);
            }
            RequestOwned::Reconfigure(_) => panic!("expected a run command"),
        }
        assert_eq!(state.last_command_id.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_replayed_command_is_rejected_by_its_id() {
        let signing_key = SigningKey::from_bytes(&[2; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        let request = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            1,
            &run_blob("true", &[]),
        );
        decode_signed_command(&request, &state).unwrap();
        let replay = decode_signed_command(&request, &state)
            .unwrap_err()
            .to_string();
        assert!(replay.contains("command id 1 was already used"), "{replay}");

        // Ids must strictly increase: a stale counter is refused too.
        let stale = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            1,
            &run_blob("true", &[]),
        );
        assert!(decode_signed_command(&stale, &state).is_err());
        let fresh = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            2,
            &run_blob("true", &[]),
        );
        decode_signed_command(&fresh, &state).unwrap();
    }

    #[test]
    fn a_command_from_another_boot_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        let mut foreign_boot_id = test_boot_id();
        foreign_boot_id[0] = foreign_boot_id[0].wrapping_add(1);
        let request = signed_request(
            &signing_key,
            KIND_RUN,
            foreign_boot_id,
            1,
            &run_blob("true", &[]),
        );
        let error = decode_signed_command(&request, &state)
            .unwrap_err()
            .to_string();
        assert!(error.contains("another boot"), "{error}");
        // And the id did not burn: the gate refused before acceptance.
        assert_eq!(state.last_command_id.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_foreign_signature_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[4; 32]);
        let other_key = SigningKey::from_bytes(&[5; 32]);
        let state = test_state(&[other_key.verifying_key()], 0);
        let request = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            1,
            &run_blob("true", &[]),
        );
        let error = decode_signed_command(&request, &state)
            .unwrap_err()
            .to_string();
        assert!(error.contains("signature"), "{error}");
        assert_eq!(state.last_command_id.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unsigned_requests_are_refused_by_name() {
        let signing_key = SigningKey::from_bytes(&[6; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        // The old unsigned wire format: a request kind byte plus fields.
        let request = run_blob("true", &[]);
        let error = decode_signed_command(&request, &state)
            .unwrap_err()
            .to_string();
        assert!(error.contains("wabbit-ipc"), "{error}");
    }

    #[test]
    fn a_reconfigure_command_carries_a_policy_the_server_re_verifies() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        // The envelope is fine; the policy inside is garbage, and the
        // second signature check (the policy format's own) refuses it.
        let mut blob = vec![KIND_RECONFIGURE];
        put_bytes(&mut blob, b"not a signed policy").unwrap();
        let request = signed_request(&signing_key, KIND_RECONFIGURE, test_boot_id(), 1, &blob);
        let error = decode_signed_command(&request, &state)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid policy"), "{error}");
    }

    #[test]
    fn tampering_with_the_command_breaks_the_signature() {
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        let mut request = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            1,
            &run_blob("true", &[]),
        );
        // Flip a byte inside the signed payload: the program name.
        let last = request.len() - 1;
        request[last] ^= 0xff;
        assert!(decode_signed_command(&request, &state).is_err());
    }

    /// The end-to-end proof: the real server on a real socket, taking
    /// commands from the real client — including the replay rejection.
    /// Multi-threaded, because the client is deliberately synchronous
    /// (std sockets, no runtime) and must not starve the server task.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_real_server_takes_commands_from_the_real_client() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);

        let directory = std::env::temp_dir().join(format!("wabbit-ipc-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let socket_path = directory.join("socket");
        let counter_path = directory.join("counter");
        let server = tokio::spawn(run_server(socket_path.clone(), state));

        let client =
            wabbit_ipc::CommandClient::connect(socket_path.clone(), &[9; 32], counter_path.clone())
                .unwrap();

        // Wait for the socket to exist, then run a real program through
        // the whole stack: counter, envelope, signature, verification,
        // execution, response.
        for _ in 0..100 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let outcome = client.run("sh", ["-c", "echo through-the-wire"]).unwrap();
        match outcome {
            wabbit_ipc::CommandOutcome::Completed(output) => {
                assert_eq!(output.status, Some(0));
                assert_eq!(output.stdout, b"through-the-wire\n");
            }
            wabbit_ipc::CommandOutcome::Reconfigured => panic!("expected a run"),
        }

        // The exact same request bytes, sent again: the replay gate.
        let command = wabbit_ipc::encode_run("sh", &["-c".into(), "echo nope".into()]).unwrap();
        let request = client.request_bytes(&command).unwrap();
        client.send_request(&request).unwrap();
        let replay = client.send_request(&request).unwrap_err().to_string();
        assert!(replay.contains("already used"), "{replay}");

        // And a fresh command still goes through after the replay: the
        // server is alive and the counter moved on.
        let outcome = client.run("true", std::iter::empty::<&str>()).unwrap();
        assert!(matches!(outcome, wabbit_ipc::CommandOutcome::Completed(_)));

        server.abort();
        std::fs::remove_dir_all(&directory).ok();
    }
}
