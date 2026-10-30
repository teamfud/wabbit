//! The signing IPC client: how a human (or a script) commands a running
//! `wabbit`.
//!
//! Every command the server will act on is **signed** (Ed25519, the
//! deployment's policy-signing key — the one `wabbit` verifies against
//! is compiled into it) and **anti-replayed**: it names the boot it was
//! minted for and carries a per-boot, strictly-increasing command id
//! that the server burns on acceptance. A command that succeeded once
//! cannot run again — not in this boot (the id is spent), and not in a
//! later one (the boot id no longer matches). The wire layout lives in
//! [`wabbit_common::ipc_command`], shared with the server.
//!
//! The client's half of the discipline is the **counter file**: one
//! small file holding the last id it sent, read and incremented per
//! command. Crash between sending and persisting re-presents an id the
//! server rejects, and the next id succeeds — the server is the
//! authority, the file is just how the signer picks fresh ids.
//!
//! The command itself travels as the base64 of a *command blob* — the
//! payload kind byte plus the command's fields (`run`: program and
//! arguments; `policy`: a signed policy file). This crate encodes the
//! blob ([`encode_run`], [`encode_policy`]); the CLI's `send` verb takes
//! the base64 blob and does the rest: counter, envelope, signature,
//! socket.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signer, SigningKey};
use wabbit_common::ipc_command::{
    self, BOOT_ID_LEN, CommandHeader, KIND_RECONFIGURE, KIND_RUN, SIGNATURE_LEN,
};

/// The environment variable naming `wabbit`'s IPC socket — the same one
/// the server reads (mirrors the server's private helper; the name is
/// derived from the brand prefix both sides compile in).
pub fn socket_var() -> String {
    format!("{}_IPC_SOCKET", wabbit_common::brand::ENV_PREFIX)
}

/// The default counter file: `.<name>-ipc-counter` in the signer's home.
pub fn default_counter_path() -> PathBuf {
    let mut path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    path.push(format!(
        ".{}-ipc-counter",
        wabbit_common::brand::NAME.to_lowercase()
    ));
    path
}

/// The result of a command, as the server reports it.
#[derive(Debug, PartialEq, Eq)]
pub enum CommandOutcome {
    /// A `run` completed: captured output and the process's exit code.
    Completed(TaskOutput),
    /// A `policy` was applied.
    Reconfigured,
}

/// A completed task's captured output.
#[derive(Debug, PartialEq, Eq)]
pub struct TaskOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// The signing client for one `wabbit` deployment.
///
/// One client per signing key: the counter file belongs to the key, and
/// every command the key ever sends to this server must go through it —
/// interleaving two counters against one server strands commands
/// (strictly-increasing is checked globally, not per client).
pub struct CommandClient {
    socket_path: PathBuf,
    signing_key: SigningKey,
    counter_path: PathBuf,
    boot_id: [u8; BOOT_ID_LEN],
}

impl CommandClient {
    /// A client that signs with the 32-byte `seed` (the file
    /// `wabbit-policy gen-key` writes), commands the wabbit listening on
    /// `socket_path`, and persists its counter in `counter_path`.
    ///
    /// The boot id is read from `/proc/sys/kernel/random/boot_id` — the
    /// machine's current boot, which is what the socket names; override
    /// with [`Self::with_boot_id`] when tunneling.
    pub fn connect(socket_path: PathBuf, seed: &[u8], counter_path: PathBuf) -> Result<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("the signing key must be exactly 32 bytes"))?;
        let boot_id = read_boot_id()?;
        Ok(Self::with_boot_id(
            socket_path,
            &seed,
            counter_path,
            boot_id,
        ))
    }

    /// [`Self::connect`] with an explicit boot id — the one
    /// `/proc/sys/kernel/random/boot_id` shows *on the machine wabbit
    /// runs on*, when the client itself runs elsewhere.
    pub fn with_boot_id(
        socket_path: PathBuf,
        seed: &[u8],
        counter_path: PathBuf,
        boot_id: [u8; BOOT_ID_LEN],
    ) -> Self {
        let seed: [u8; 32] = seed
            .try_into()
            .expect("the constructor documented exactly 32 bytes");
        Self {
            socket_path,
            signing_key: SigningKey::from_bytes(&seed),
            counter_path,
            boot_id,
        }
    }

    /// Run a program in the protected namespace, capturing its output.
    pub fn run<I, S>(&self, program: &str, args: I) -> Result<CommandOutcome>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.run_in_class(program, args, None)
    }

    /// [`Self::run`], naming the **class** the run executes under: the
    /// authorization profile the target's policy defines for that
    /// class. The server resolves the name against the *active* policy
    /// (a reconfigure rotates classes without a reboot), gives the run
    /// its own ephemeral cgroup, and applies exactly that class's
    /// rules to it — least privilege by construction: a classless run
    /// gets deny-by-default, and a classed run gets its class and
    /// nothing more.
    pub fn run_in_class<I, S>(
        &self,
        program: &str,
        args: I,
        class: Option<&str>,
    ) -> Result<CommandOutcome>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let command = encode_run_in_class(program, &args, class)?;
        self.send_encoded(&command)
    }

    /// Apply a complete signed policy file (the bytes
    /// `wabbit-policy build` writes).
    pub fn reconfigure(&self, policy: &[u8]) -> Result<CommandOutcome> {
        self.send_encoded(&encode_policy(policy)?)
    }

    /// Send a base64-encoded command blob (see [`encode_run`] /
    /// [`encode_policy`]) — the CLI's `send` verb.
    pub fn send_base64(&self, encoded: &str) -> Result<CommandOutcome> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let command = STANDARD
            .decode(encoded.trim())
            .context("the command is not valid base64")?;
        self.send_encoded(&command)
    }

    /// Send a command blob, count it, sign it, and deliver it. The blob
    /// is the payload kind byte plus the command's fields.
    fn send_encoded(&self, command: &[u8]) -> Result<CommandOutcome> {
        let request = self.request_bytes(command)?;
        match self.send_request(&request)? {
            ServerResponse::Completed(output) => Ok(CommandOutcome::Completed(output)),
            ServerResponse::Reconfigured => Ok(CommandOutcome::Reconfigured),
        }
    }

    /// Build the complete signed request for `command` — counter,
    /// envelope, signature — without sending it. Increments the counter
    /// file, exactly like a send: a built request is a spent id.
    pub fn request_bytes(&self, command: &[u8]) -> Result<Vec<u8>> {
        let Some((&kind, payload)) = command.split_first() else {
            bail!("the command blob is empty");
        };
        let header = CommandHeader {
            kind,
            boot_id: self.boot_id,
            command_id: next_command_id(&self.counter_path)?,
        };
        let mut signed = vec![0u8; CommandHeader::signed_len(payload.len())];
        header
            .encode(payload, &mut signed)
            .map_err(|error| anyhow::anyhow!("encoding the command envelope: {error:?}"))?;
        let signature = self.signing_key.sign(&signed);

        let mut request = Vec::with_capacity(1 + SIGNATURE_LEN + signed.len());
        request.push(ipc_command::SIGNED_REQUEST);
        request.extend_from_slice(&signature.to_bytes());
        request.extend_from_slice(&signed);
        Ok(request)
    }

    /// Deliver a complete signed request (as built by
    /// [`Self::request_bytes`]) and read the verdict. Sending the same
    /// request twice is exactly what the anti-replay exists for: the
    /// second delivery is rejected by the server.
    pub fn send_request(&self, request: &[u8]) -> Result<ServerResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "connecting to the IPC socket {}",
                self.socket_path.display()
            )
        })?;
        stream.write_all(request)?;
        // Half-close: the server reads to EOF, then answers.
        use std::net::Shutdown;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        decode_response(&response)
    }
}

/// The server's answer to one command. A rejected command is not a
/// variant: the decode turns the server's failure message into an
/// `Err`, message first.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerResponse {
    Completed(TaskOutput),
    Reconfigured,
}

/// Encode a `run` command blob: program and its arguments.
///
/// Same as [`encode_run_in_class`] with no class — the least-privilege
/// floor: the run gets its own ephemeral cgroup with no authorization
/// at all.
pub fn encode_run(program: &str, args: &[String]) -> Result<Vec<u8>> {
    encode_run_in_class(program, args, None)
}

/// Encode a `run` command blob, optionally naming the **class** the
/// run executes under. The class must be defined in the target's
/// policy (`wabbit-policy build` compiles `[[class]]` blocks into the
/// cgroup rules a run resolves); the name travels inside the
/// signature, so the class a command runs with is exactly the class
/// its signer chose.
pub fn encode_run_in_class(program: &str, args: &[String], class: Option<&str>) -> Result<Vec<u8>> {
    let mut output = vec![KIND_RUN];
    put_string(&mut output, program)?;
    put_u32(&mut output, args.len())?;
    for arg in args {
        put_string(&mut output, arg)?;
    }
    // The optional trailing class field: absent for the older blob
    // shape, present — and validated before it is ever signed — when
    // the run names a class.
    if let Some(class) = class {
        if !wabbit_common::cgroup_types::valid_class_name(class) {
            bail!(
                "the class name {class:?} is not valid: 1-{} bytes of [a-z0-9-], \
                 no leading or trailing '-'",
                wabbit_common::cgroup_types::CLASS_NAME_MAX_BYTES
            );
        }
        put_string(&mut output, class)?;
    }
    Ok(output)
}

/// Encode a `policy` command blob: a complete signed policy file.
pub fn encode_policy(policy: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![KIND_RECONFIGURE];
    put_bytes(&mut output, policy)?;
    Ok(output)
}

/// This machine's boot id, as `/proc/sys/kernel/random/boot_id` spells
/// it: the canonical 36-byte ASCII UUID, no trailing newline.
pub fn read_boot_id() -> Result<[u8; BOOT_ID_LEN]> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("reading /proc/sys/kernel/random/boot_id")?;
    let mut boot_id = [0u8; BOOT_ID_LEN];
    let bytes = text.trim().as_bytes();
    if bytes.len() != BOOT_ID_LEN || !ipc_command::is_canonical_boot_id(bytes) {
        bail!("the boot id {text:?} is not a canonical UUID");
    }
    boot_id.copy_from_slice(bytes);
    Ok(boot_id)
}

/// The next command id from the counter file: the stored value plus one,
/// persisted before returning. A missing file starts at 0 (the first id
/// is 1); a corrupt file is treated as 0 — the server rejects ids it has
/// already seen, so a lost or damaged counter fails safe, never unsafe.
fn next_command_id(path: &Path) -> Result<u64> {
    let current = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let next = current
        .checked_add(1)
        .context("the command counter wrapped; this deployment has lived long enough")?;
    let staged = path.with_extension("next");
    std::fs::write(&staged, format!("{next}\n"))
        .with_context(|| format!("staging the command counter {}", staged.display()))?;
    std::fs::rename(&staged, path)
        .with_context(|| format!("updating the command counter {}", path.display()))?;
    Ok(next)
}

// The response half of the wire, mirroring the server's encoder; the
// two are pinned together by the end-to-end tests in `wabbit`, which
// run this client against the real server.
const COMPLETED_RESPONSE: u8 = 0b01;
const FAILED_RESPONSE: u8 = 0b10;
const RECONFIGURED_RESPONSE: u8 = 0b11;

/// One `u32` little-endian length-prefixed field, the framing the IPC
/// protocol has always used.
struct Fields<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Fields<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8]> {
        let end = usize::checked_add(self.position, length).context("response length overflow")?;
        let slice = self
            .bytes
            .get(self.position..end)
            .context("truncated IPC response")?;
        self.position = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(*self.take(1)?.first().context("empty IPC response")?)
    }

    fn field(&mut self) -> Result<Vec<u8>> {
        let bytes = self.take(4)?;
        let length = u32::from_le_bytes(bytes.try_into().expect("4 bytes is a u32")) as usize;
        Ok(self.take(length)?.to_vec())
    }

    fn finish(&self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            bail!("trailing bytes in IPC response")
        }
    }
}

fn decode_response(bytes: &[u8]) -> Result<ServerResponse> {
    let mut fields = Fields { bytes, position: 0 };
    match fields.byte()? {
        COMPLETED_RESPONSE => {
            let status = match fields.byte()? {
                0 => None,
                1 => {
                    let bytes: [u8; 4] = fields.take(4)?.try_into().expect("4 bytes is an i32");
                    Some(i32::from_le_bytes(bytes))
                }
                _ => bail!("invalid process status marker"),
            };
            let stdout = fields.field()?;
            let stderr = fields.field()?;
            fields.finish()?;
            Ok(ServerResponse::Completed(TaskOutput {
                status,
                stdout,
                stderr,
            }))
        }
        FAILED_RESPONSE => {
            let message =
                String::from_utf8(fields.field()?).context("the failure message is not UTF-8")?;
            fields.finish()?;
            bail!("{message}")
        }
        RECONFIGURED_RESPONSE => {
            fields.finish()?;
            Ok(ServerResponse::Reconfigured)
        }
        _ => bail!("unknown IPC response"),
    }
}

fn put_u32(output: &mut Vec<u8>, value: usize) -> Result<()> {
    output.extend_from_slice(
        &u32::try_from(value)
            .context("IPC field count overflows u32")?
            .to_le_bytes(),
    );
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    put_u32(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    put_bytes(output, value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_blobs_have_the_shape_the_server_decodes() {
        let args = vec!["-c".to_string(), "echo hi".to_string()];
        let blob = encode_run("sh", &args).unwrap();
        assert_eq!(blob[0], KIND_RUN);
        // program string, then the argument count, then each argument —
        // every field u32-length-prefixed, little-endian.
        assert_eq!(&blob[1..5], &2u32.to_le_bytes());
        assert_eq!(&blob[5..7], b"sh");
        assert_eq!(&blob[7..11], &2u32.to_le_bytes());
    }

    #[test]
    fn policy_blobs_wrap_the_file_bytes() {
        let blob = encode_policy(b"policy-bytes").unwrap();
        assert_eq!(blob[0], KIND_RECONFIGURE);
        assert_eq!(&blob[1..5], &12u32.to_le_bytes());
        assert_eq!(&blob[5..], b"policy-bytes");
    }

    #[test]
    fn classed_blobs_carry_the_class_last() {
        let args = vec!["-c".to_string(), "uptime".to_string()];
        let blob = encode_run_in_class("bash", &args, Some("ultra-privileged")).unwrap();
        // program, argc, args, then the class as the trailing string —
        // the shape the server decodes (and rejects hostile names in).
        let expected = {
            let mut blob = vec![KIND_RUN];
            put_string(&mut blob, "bash").unwrap();
            put_u32(&mut blob, 2).unwrap();
            put_string(&mut blob, "-c").unwrap();
            put_string(&mut blob, "uptime").unwrap();
            put_string(&mut blob, "ultra-privileged").unwrap();
            blob
        };
        assert_eq!(blob, expected);

        // And a name that could reinterpret as a path never gets
        // signed in the first place.
        assert!(encode_run_in_class("bash", &args, Some("../escape")).is_err());
        assert!(encode_run_in_class("bash", &args, Some("sh/ell")).is_err());
        assert!(encode_run_in_class("bash", &args, Some("")).is_err());
    }

    #[test]
    fn an_empty_command_blob_is_rejected() {
        let client = CommandClient::with_boot_id(
            PathBuf::from("/nonexistent/socket"),
            &[3; 32],
            std::env::temp_dir().join("never-written"),
            read_boot_id().unwrap(),
        );
        assert!(client.request_bytes(b"").is_err());
    }

    #[test]
    fn responses_round_trip() {
        let mut response = vec![COMPLETED_RESPONSE, 1];
        response.extend_from_slice(&0i32.to_le_bytes());
        put_bytes(&mut response, b"out").unwrap();
        put_bytes(&mut response, b"err").unwrap();
        assert_eq!(
            decode_response(&response).unwrap(),
            ServerResponse::Completed(TaskOutput {
                status: Some(0),
                stdout: b"out".to_vec(),
                stderr: b"err".to_vec(),
            })
        );
    }

    #[test]
    fn failure_responses_bail_with_the_message() {
        let mut response = vec![FAILED_RESPONSE];
        put_string(&mut response, "nope").unwrap();
        let error = decode_response(&response).unwrap_err().to_string();
        assert!(error.contains("nope"), "{error}");
    }

    #[test]
    fn truncated_responses_are_rejected() {
        assert!(decode_response(&[COMPLETED_RESPONSE]).is_err());
        assert!(decode_response(&[]).is_err());
        assert!(decode_response(&[0xff]).is_err());
    }

    #[test]
    fn the_counter_increments_and_survives_a_corrupt_file() {
        let directory = std::env::temp_dir().join(format!(
            "wabbit-ipc-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let counter = directory.join("counter");

        let first = next_command_id(&counter).unwrap();
        let second = next_command_id(&counter).unwrap();
        assert_eq!((first, second), (1, 2));

        // A damaged counter fails safe: the signer restarts from the
        // bottom, and the server (strictly increasing) is the authority.
        std::fs::write(&counter, "not a number").unwrap();
        assert_eq!(next_command_id(&counter).unwrap(), 1);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn request_bytes_sign_the_envelope_the_server_verifies() {
        let client = CommandClient::with_boot_id(
            PathBuf::from("/nonexistent"),
            &[5; 32],
            std::env::temp_dir().join(format!("wabbit-ipc-sign-{}", std::process::id())),
            read_boot_id().unwrap(),
        );
        let command = encode_run("true", &[]).unwrap();
        let request = client.request_bytes(&command).unwrap();
        std::fs::remove_file(
            std::env::temp_dir().join(format!("wabbit-ipc-sign-{}", std::process::id())),
        )
        .ok();

        assert_eq!(request[0], ipc_command::SIGNED_REQUEST);
        let signature: [u8; SIGNATURE_LEN] =
            request[1..1 + SIGNATURE_LEN].try_into().expect("64 bytes");
        let signed = &request[1 + SIGNATURE_LEN..];
        let header = ipc_command::decode_header(signed).unwrap();
        assert_eq!(header.kind, KIND_RUN);
        assert_eq!(header.boot_id, read_boot_id().unwrap());
        assert_eq!(header.command_id, 1);
        // The signature verifies against the client's own public half —
        // the server does the same against its compiled-in keys.
        use ed25519_dalek::{Signature, Verifier};
        let signature = Signature::from_bytes(&signature);
        client
            .signing_key
            .verifying_key()
            .verify(signed, &signature)
            .expect("the signature covers the whole envelope");
    }
}
