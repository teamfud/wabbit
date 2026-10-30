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
    path::{Path, PathBuf},
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

use crate::{
    policy::{self, Policy},
    runs::{self, RunAuthorizer},
};

/// The responses (the request kinds are all signed now; the old unsigned
/// ones are refused by name).
const COMPLETED_RESPONSE: u8 = 0b01;
const FAILED_RESPONSE: u8 = 0b10;
const RECONFIGURED_RESPONSE: u8 = 0b11;

/// Everything a command has to pass, kept for the server's whole life.
pub struct IpcState {
    /// The policy `reconfigure` merges into, section by section — and
    /// the one class-naming runs resolve their authorization from, so
    /// a reconfigure rotates classes without a reboot.
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
    /// The guard's run-cgroup half: creates and authorizes the
    /// ephemeral cgroup each run executes in (`crate::runs`).
    authorizer: Arc<dyn RunAuthorizer>,
}

/// The server's state for a real run: the compiled-in policy keys, this
/// boot's id, the given starting policy, and the guard's run
/// authorizer. Call once at startup.
pub fn server_state(policy: Policy, authorizer: Arc<dyn RunAuthorizer>) -> Result<Arc<IpcState>> {
    Ok(Arc::new(IpcState {
        active_policy: Mutex::new(policy),
        boot_id: read_boot_id()?,
        last_command_id: AtomicU64::new(0),
        public_keys: crate::trust::compiled_public_keys()?,
        authorizer,
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
    /// The class this run asked for, when it named one: the
    /// authorization profile its ephemeral cgroup receives (`None` =
    /// the classless floor, deny-by-default). Carried inside the
    /// signature, so the class a command runs under is exactly the
    /// class its signer chose.
    class: Option<String>,
    /// The command's anti-replay id — also the run cgroup's name, so
    /// no two runs share a cgroup and no leftover can collide with a
    /// fresh one.
    command_id: u64,
}

#[derive(Debug)]
struct ReconfigureOwned {
    policy: Policy,
}

/// Run the IPC server on `socket_path` until the process exits.
pub async fn run_server(socket_path: PathBuf, state: Arc<IpcState>) -> Result<()> {
    // The socket's parent (e.g. `/run/wabbit`) cannot be created at
    // install time — `/run` is tmpfs and a reboot wipes it — so it is
    // created here, at bind time, by the process that knows the boot
    // is real.
    if let Some(parent) = socket_path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        log::warn!(
            "could not create the IPC socket's parent {}: {error}",
            parent.display()
        );
    }
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
        Ok(RequestOwned::Run(run)) => match execute_run(run, &state).await {
            Ok(output) => encode_response(&Response::Completed(CompletedTask {
                output: TaskOutput {
                    status: output.status.code(),
                    stdout: output.stdout,
                    stderr: output.stderr,
                },
            }))?,
            Err(error) => encode_response(&Response::Failed(TaskError {
                message: format!("{error:#}"),
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

/// Execute one run command in its own ephemeral cgroup — never in
/// wabbit's own (that cgroup is trusted; a program there would outrank
/// the whole model). See `crate::runs` for the shape of the cgroup and
/// [`resolve_class`] for how the class name becomes the authorization
/// the run receives.
async fn execute_run(run: RunTaskOwned, state: &Arc<IpcState>) -> Result<std::process::Output> {
    // The class's compiled entry, resolved from the *active* policy:
    // the policy crate folds `[[class]]` blocks into authorization
    // entries at `<wabbit-cgroup>/class/<name>`, and that convention
    // path is all the runtime ever knows about classes.
    let class = match &run.class {
        Some(name) => Some(resolve_class(
            &state.active_policy,
            &state.authorizer,
            name,
        )?),
        None => None,
    };

    let prepared = state
        .authorizer
        .prepare_run(class.as_ref(), run.command_id)
        .context("preparing the run cgroup")?;

    // **Self-migration before exec**: the child writes its own pid into
    // the run cgroup's `cgroup.procs` from `pre_exec`, which runs
    // between fork and exec — so the program's first instruction after
    // exec executes *inside* the run cgroup, with no window at all. A
    // rendezvous the parent could win (the self-test's held-stdin
    // trick) only works for programs that block on stdin; `modprobe`
    // does not, and a run that finished in wabbit's own, trusted
    // cgroup was measured doing exactly that (a module loaded,
    // unclassified). The pre_exec closure runs after fork in a
    // multithreaded process: only async-signal-safe calls (open,
    // write, close, getpid) and no allocation — the path is a ready
    // CString built before the fork, the pid formats into a stack
    // buffer.
    let procs = std::ffi::CString::new(
        prepared
            .cgroup
            .join("cgroup.procs")
            .to_str()
            .context("the run cgroup path is UTF-8")?,
    )
    .map_err(|_| anyhow::anyhow!("the cgroup.procs path is not C-stringable"))?;
    let mut command = Command::new(&run.program);
    command
        .args(&run.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut digits = [0u8; 20];
            let pid = libc::getpid() as u64;
            let mut length = digits.len();
            let mut rest = pid;
            loop {
                length -= 1;
                digits[length] = b'0' + (rest % 10) as u8;
                rest /= 10;
                if rest == 0 {
                    break;
                }
            }
            let written = libc::write(
                fd,
                digits[length..].as_ptr().cast::<libc::c_void>(),
                digits.len() - length,
            );
            let written = if written < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            };
            libc::close(fd);
            written
        });
    }
    let child = command.spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            state.authorizer.release_run(&prepared);
            return Err(error).with_context(|| format!("running {}", run.program));
        }
    };
    // EOF on stdin: the program proceeds, in its cgroup, under its class.
    drop(child.stdin.take());

    let output = child.wait_with_output().await;
    // The cgroup dies with the run — its authorization leaves the maps
    // and the directory goes, whatever the outcome was.
    state.authorizer.release_run(&prepared);
    output.context("waiting for the run")
}

/// Resolve a class name to its compiled entry in the active policy: a
/// path lookup, nothing more. The name is validated before any path is
/// built (it came off the wire, signature notwithstanding — the
/// signature authorizes the name, the charset keeps it a name), and the
/// entry is cloned out of the policy lock so a long run never holds it.
fn resolve_class(
    policy: &Mutex<Policy>,
    authorizer: &Arc<dyn RunAuthorizer>,
    name: &str,
) -> Result<wabbit_policy::authorization::AuthorizationEntry> {
    use wabbit_policy::authorization::AuthorizationConfig;

    let own = authorizer.own_cgroup();
    let path = runs::class_cgroup_path(&own, name)?;
    let policy = policy
        .lock()
        .map_err(|_| anyhow::anyhow!("the policy lock is poisoned"))?;
    let config = policy.authorization.as_ref();
    let entry = config
        .and_then(|config: &AuthorizationConfig| {
            config
                .entries
                .iter()
                .find(|entry| entry.cgroup == Path::new(&path))
        })
        .cloned();
    entry.ok_or_else(|| {
        anyhow::anyhow!(
            "the active policy defines no class {name:?}: classes compile to \
             <wabbit-cgroup>/{}/<name> entries, and no entry sits at {path:?}",
            wabbit_common::cgroup_types::CLASS_SEGMENT
        )
    })
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
            // The class field is optional and last: its absence is the
            // older blob shape (and decodes as "no class"), so a fresh
            // client can still talk to a policy that defines none.
            let class = if fields.rest().is_empty() {
                None
            } else {
                Some(fields.string()?)
            };
            // The name is validated here, before the id burns: a
            // command that fails to parse never reaches execution, and
            // a class name is a path component the runtime will build a
            // cgroupfs path from — the signature authorizes the name,
            // the charset keeps it one.
            if let Some(name) = &class
                && !wabbit_common::cgroup_types::valid_class_name(name)
            {
                bail!(
                    "the run's class name {name:?} is not valid: 1-{} bytes of \
                     [a-z0-9-], no leading or trailing '-'",
                    wabbit_common::cgroup_types::CLASS_NAME_MAX_BYTES
                );
            }
            fields.finish()?;
            RequestOwned::Run(RunTaskOwned {
                program,
                args,
                class,
                command_id: header.command_id,
            })
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
    use std::{os::unix::fs::MetadataExt, sync::Mutex as StdMutex};

    use ed25519_dalek::{Signer, SigningKey};
    use wabbit_common::ipc_command::CommandHeader;
    use wabbit_policy::authorization::AuthorizationEntry;

    use super::*;

    /// The test authorizer: records what the server asked for, and
    /// fakes the filesystem half well enough for a real spawned
    /// process to be migrated (`cgroup.procs` is a plain file under a
    /// temp dir, so the write succeeds without a real cgroupfs).
    struct FakeAuthorizer {
        own: String,
        directory: PathBuf,
        preparations: StdMutex<Vec<(Option<u64>, u64)>>,
        releases: StdMutex<Vec<PathBuf>>,
    }

    impl FakeAuthorizer {
        fn new() -> Arc<Self> {
            let directory = std::env::temp_dir().join(format!(
                "wabbit-ipc-fake-{}-{}",
                std::process::id(),
                line!()
            ));
            std::fs::create_dir_all(&directory).unwrap();
            Arc::new(Self {
                own: "/sys/fs/cgroup/wabbit".into(),
                directory,
                preparations: StdMutex::new(Vec::new()),
                releases: StdMutex::new(Vec::new()),
            })
        }
    }

    impl Drop for FakeAuthorizer {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    impl RunAuthorizer for FakeAuthorizer {
        fn own_cgroup(&self) -> String {
            self.own.clone()
        }

        fn prepare_run(
            &self,
            class: Option<&AuthorizationEntry>,
            command_id: u64,
        ) -> Result<runs::PreparedRun> {
            // The class's cgroup path is absolute (cgroupfs paths always
            // are); joining one onto the temp directory would *replace*
            // it (`Path::join` with an absolute path wins), so the
            // leading `/` comes off and the fake's tree mirrors the real
            // shape underneath its own root.
            let parent = self.directory.join(match class {
                Some(entry) => entry
                    .cgroup
                    .display()
                    .to_string()
                    .trim_start_matches('/')
                    .to_string(),
                None => "own".to_string(),
            });
            std::fs::create_dir_all(&parent).unwrap();
            let cgroup = parent.join(format!("run-{command_id}"));
            std::fs::create_dir(&cgroup).unwrap();
            // A real cgroupfs exposes cgroup.procs; the migration write
            // needs somewhere to land.
            std::fs::write(cgroup.join("cgroup.procs"), "").unwrap();
            self.preparations
                .lock()
                .unwrap()
                .push((class.map(|entry| entry.action_mask), command_id));
            Ok(runs::PreparedRun {
                cgroup: cgroup.clone(),
                cgroup_id: std::fs::metadata(&cgroup).unwrap().ino(),
                rule_prefix_hashes: Vec::new(),
            })
        }

        fn release_run(&self, run: &runs::PreparedRun) {
            let _ = std::fs::remove_dir_all(&run.cgroup);
            self.releases.lock().unwrap().push(run.cgroup.clone());
        }
    }

    /// A policy whose authorization section carries the compiled shell
    /// class at the convention path the fake's own cgroup implies.
    fn classed_policy() -> Policy {
        use wabbit_common::authorization as auth;
        let entry = AuthorizationEntry {
            cgroup: "/sys/fs/cgroup/wabbit/class/shell".into(),
            action_mask: auth::ACTION_EXEC | auth::ACTION_CREDENTIALS,
            flags: auth::FLAG_PROTECT | auth::FLAG_PATH_RULES_DEFAULT_DENY,
            path_rules: vec![wabbit_policy::authorization::PathRule {
                prefix: "/usr".into(),
                verdict: wabbit_policy::authorization::PathRuleVerdict::allow_all(),
            }],
        };
        Policy {
            rootfs: None,
            authorization: Some(wabbit_policy::authorization::AuthorizationConfig {
                entries: vec![entry],
            }),
            network: None,
        }
    }

    fn test_state(keys: &[VerifyingKey], last_command_id: u64) -> Arc<IpcState> {
        test_state_with(
            keys,
            last_command_id,
            Policy::default(),
            FakeAuthorizer::new(),
        )
    }

    fn test_state_with(
        keys: &[VerifyingKey],
        last_command_id: u64,
        policy: Policy,
        authorizer: Arc<dyn RunAuthorizer>,
    ) -> Arc<IpcState> {
        Arc::new(IpcState {
            active_policy: Mutex::new(policy),
            boot_id: read_boot_id().expect("the test host has a boot id"),
            last_command_id: AtomicU64::new(last_command_id),
            public_keys: keys.to_vec(),
            authorizer,
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
        run_blob_in_class(program, args, None)
    }

    fn run_blob_in_class(program: &str, args: &[&str], class: Option<&str>) -> Vec<u8> {
        let mut blob = vec![KIND_RUN];
        put_string(&mut blob, program).unwrap();
        put_u32(&mut blob, args.len()).unwrap();
        for arg in args {
            put_string(&mut blob, arg).unwrap();
        }
        // The optional trailing class field, exactly as the client
        // encodes it when a run names one.
        if let Some(class) = class {
            put_string(&mut blob, class).unwrap();
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
                // The older blob shape carries no class field.
                assert_eq!(task.class, None);
                assert_eq!(task.command_id, 1);
            }
            RequestOwned::Reconfigure(_) => panic!("expected a run command"),
        }
        assert_eq!(state.last_command_id.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_classed_run_decodes_with_its_class() {
        let signing_key = SigningKey::from_bytes(&[1; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        let request = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            7,
            &run_blob_in_class("bash", &[], Some("ultra-privileged")),
        );
        match decode_signed_command(&request, &state).unwrap() {
            RequestOwned::Run(task) => {
                assert_eq!(task.class.as_deref(), Some("ultra-privileged"));
                assert_eq!(task.command_id, 7);
            }
            RequestOwned::Reconfigure(_) => panic!("expected a run command"),
        }
    }

    /// The class name off the wire is validated at decode, before the
    /// id burns — the signature authorizes the name; the charset keeps
    /// it a name. A traversal attempt never reaches a path.
    #[test]
    fn hostile_class_names_never_reach_a_path() {
        let signing_key = SigningKey::from_bytes(&[1; 32]);
        let state = test_state(&[signing_key.verifying_key()], 0);
        for hostile in ["../escape", "sh/ell", "UPPER", "has space"] {
            let request = signed_request(
                &signing_key,
                KIND_RUN,
                test_boot_id(),
                1,
                &run_blob_in_class("bash", &[], Some(hostile)),
            );
            let error = decode_signed_command(&request, &state)
                .unwrap_err()
                .to_string();
            assert!(error.contains("class name"), "{error}");
            // The id did not burn: the signer can fix the name and
            // resend the same id.
            assert_eq!(state.last_command_id.load(Ordering::SeqCst), 0);
        }
        // And the fix lands: the same id goes through once the name is
        // a name.
        let request = signed_request(
            &signing_key,
            KIND_RUN,
            test_boot_id(),
            1,
            &run_blob_in_class("bash", &[], Some("shell")),
        );
        assert!(decode_signed_command(&request, &state).is_ok());
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
    /// commands from the real client — the classed and classless run
    /// flows, and the replay rejection. Multi-threaded, because the
    /// client is deliberately synchronous (std sockets, no runtime) and
    /// must not starve the server task.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_real_server_takes_commands_from_the_real_client() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let authorizer = FakeAuthorizer::new();
        let authorizer_for_server: Arc<dyn RunAuthorizer> = Arc::clone(&authorizer) as _;
        let state = test_state_with(
            &[signing_key.verifying_key()],
            0,
            classed_policy(),
            authorizer_for_server,
        );

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

        // A classed run: the class resolves to the compiled entry (the
        // fake's own cgroup makes the convention path match), the run
        // executes under exactly that authorization, and both the
        // classed and the classless flows release their cgroups.
        let outcome = client
            .run_in_class("sh", ["-c", "echo classed"], Some("shell"))
            .unwrap();
        match outcome {
            wabbit_ipc::CommandOutcome::Completed(output) => {
                assert_eq!(output.status, Some(0));
                assert_eq!(output.stdout, b"classed\n");
            }
            wabbit_ipc::CommandOutcome::Reconfigured => panic!("expected a run"),
        }

        // A class the policy does not define: refused by name.
        let outcome = client.run_in_class("sh", ["-c", "echo nope"], Some("no-such-class"));
        let error = outcome.unwrap_err().to_string();
        assert!(error.contains("no class"), "{error}");

        // Both accepted runs prepared cgroups under their class's (or
        // the bare) parent, and both were released.
        {
            let preparations = authorizer.preparations.lock().unwrap();
            // (class's action mask, command id): the classless run…
            assert_eq!(preparations[0], (None, 1));
            // …and the classed one, carrying the shell class's bits.
            use wabbit_common::authorization as auth;
            assert_eq!(
                preparations[1],
                (Some(auth::ACTION_EXEC | auth::ACTION_CREDENTIALS), 2)
            );
        }
        {
            let releases = authorizer.releases.lock().unwrap();
            assert_eq!(releases.len(), 2, "every completed run releases its cgroup");
        }

        // The exact same request bytes, sent again: the replay gate.
        let command = wabbit_ipc::encode_run("sh", &["-c".into(), "echo replayed".into()]).unwrap();
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

    /// The class resolution, against the active policy: the convention
    /// path, the signed-entry lookup, and the refusal that names the
    /// missing class.
    #[test]
    fn class_resolution_follows_the_convention_path() {
        let authorizer = FakeAuthorizer::new();
        let state = test_state_with(
            &[SigningKey::from_bytes(&[10; 32]).verifying_key()],
            0,
            classed_policy(),
            Arc::clone(&authorizer) as Arc<dyn RunAuthorizer>,
        );

        let entry = resolve_class(&state.active_policy, &state.authorizer, "shell").unwrap();
        assert_eq!(entry.cgroup, Path::new("/sys/fs/cgroup/wabbit/class/shell"));
        use wabbit_common::authorization as auth;
        assert_eq!(
            entry.action_mask,
            auth::ACTION_EXEC | auth::ACTION_CREDENTIALS
        );
        assert_eq!(
            entry.flags,
            auth::FLAG_PROTECT | auth::FLAG_PATH_RULES_DEFAULT_DENY
        );

        // The name is a path component: the resolution never builds a
        // path from something that could reinterpret.
        let error = resolve_class(&state.active_policy, &state.authorizer, "../escape")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid"), "{error}");

        let error = resolve_class(&state.active_policy, &state.authorizer, "no-such-class")
            .unwrap_err()
            .to_string();
        assert!(error.contains("no class"), "{error}");
    }
}
