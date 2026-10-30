//! `wabbit-ipc` — send a signed command to a running wabbit.
//!
//! One command per invocation; the id discipline is the client's half of
//! the anti-replay: each invocation spends the next id from the counter
//! file (see `wabbit_ipc`'s docs), signs the command with the
//! deployment's signing key — the same key that signs policy files —
//! and delivers it to the IPC socket.
//!
//! ```text
//! # run a program in the protected namespace:
//! wabbit-ipc --key policy.key run sh -c 'uptime'
//!
//! # apply a signed policy:
//! wabbit-ipc --key policy.key policy policy.wspf
//!
//! # the same, but the command comes as base64:
//! wabbit-ipc --key policy.key send "$(wabbit-ipc encode-run sh -c uptime)"
//! ```
//!
//! The socket defaults to the `WABBIT_IPC_SOCKET` environment variable;
//! the counter defaults to `~/.wabbit-ipc-counter`; the boot id to this
//! machine's current boot. Override any of them when tunneling or
//! scripting.

use std::{io::Write, path::PathBuf};

use anyhow::{Context, Result, bail};
use wabbit_ipc::{CommandClient, CommandOutcome};

const USAGE: &str = "\
usage: wabbit-ipc [options] VERB [arguments]

options:
  --socket PATH     wabbit's IPC socket (default: $WABBIT_IPC_SOCKET)
  --key PATH        the 32-byte Ed25519 signing seed (wabbit-policy gen-key
                    writes it); required for run, policy, and send
  --counter PATH    the command counter file (default: ~/.wabbit-ipc-counter)
  --boot-id ID      the target boot's UUID (default: this machine's current
                    boot, from /proc/sys/kernel/random/boot_id)
  --class NAME      the class the run executes under (run and encode-run
                    only): the authorization profile this name selects from
                    the target's policy. A classed run gets its own
                    ephemeral cgroup with exactly the class's rules; without
                    it the run is deny-by-default
  -h | --help       this text

verbs:
  run PROGRAM [ARGS...]  run a program in the protected namespace
  policy FILE            apply a complete signed policy file
  send BASE64            send a base64-encoded command blob
  encode-run PROGRAM [ARGS...]
                         print the base64 command blob for a run — no key,
                         no counter; feed it to send now or elsewhere

every command is signed (Ed25519) and travels as base64 in the blob
verbs above — the blob is the reviewable, relayable artifact: mint it
with encode-run, inspect or carry it anywhere, deliver it with send.

  wabbit-ipc --key policy.key --class ultra-privileged encode-run bash
  wabbit-ipc --key policy.key send \"$(wabbit-ipc --class ultra-privileged encode-run bash)\"
";

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("wabbit-ipc: {error:#}");
            2
        }
    };
    std::process::exit(code);
}

/// The parsed command line: the options, the verb, and whatever the
/// verb takes. Options come before the verb; anything after it is the
/// verb's own argument list.
struct CommandLine {
    socket: Option<PathBuf>,
    key: Option<PathBuf>,
    counter: Option<PathBuf>,
    boot_id: Option<String>,
    class: Option<String>,
    verb: String,
    arguments: Vec<String>,
}

fn parse_arguments() -> Result<CommandLine> {
    let mut command = CommandLine {
        socket: None,
        key: None,
        counter: None,
        boot_id: None,
        class: None,
        verb: String::new(),
        arguments: Vec::new(),
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => command.socket = Some(value(&mut arguments, "--socket")?.into()),
            "--key" => command.key = Some(value(&mut arguments, "--key")?.into()),
            "--counter" => command.counter = Some(value(&mut arguments, "--counter")?.into()),
            "--boot-id" => {
                let boot_id = value(&mut arguments, "--boot-id")?;
                if !wabbit_common::ipc_command::is_canonical_boot_id(boot_id.trim().as_bytes()) {
                    bail!(
                        "--boot-id must be a canonical UUID, as /proc/sys/kernel/random/boot_id \
                         spells it"
                    );
                }
                command.boot_id = Some(boot_id.trim().to_string());
            }
            "--class" => {
                let class = value(&mut arguments, "--class")?;
                if !wabbit_common::cgroup_types::valid_class_name(class.trim()) {
                    bail!(
                        "--class must be 1-{} bytes of [a-z0-9-], no leading or trailing '-'",
                        wabbit_common::cgroup_types::CLASS_NAME_MAX_BYTES
                    );
                }
                command.class = Some(class.trim().to_string());
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            verb => {
                command.verb = verb.to_string();
                command.arguments = arguments.collect();
                return Ok(command);
            }
        }
    }
    bail!("missing verb: run, policy, send, or encode-run")
}

fn value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    arguments
        .next()
        .with_context(|| format!("{flag} needs a value"))
}

fn run() -> Result<i32> {
    let command = parse_arguments()?;
    match command.verb.as_str() {
        // The blob producer: encodes only — no key, no socket, nothing
        // spent. Print the base64 on one line for shell capture.
        "encode-run" => {
            let Some(program) = command.arguments.first() else {
                bail!("encode-run needs a program");
            };
            let blob = wabbit_ipc::encode_run_in_class(
                program,
                &command.arguments[1..],
                command.class.as_deref(),
            )?;
            println!("{}", base64(blob.as_slice()));
            Ok(0)
        }
        "run" => {
            let Some(program) = command.arguments.first() else {
                bail!("run needs a program");
            };
            let blob = wabbit_ipc::encode_run_in_class(
                program,
                &command.arguments[1..],
                command.class.as_deref(),
            )?;
            deliver(&command, &blob)
        }
        "policy" => {
            reject_class(&command, "policy")?;
            let Some(path) = command.arguments.first() else {
                bail!("policy needs a signed policy file");
            };
            let policy =
                std::fs::read(path).with_context(|| format!("reading the policy {}", path))?;
            let blob = wabbit_ipc::encode_policy(&policy)?;
            deliver(&command, &blob)
        }
        "send" => {
            reject_class(&command, "send")?;
            let Some(encoded) = command.arguments.first() else {
                bail!("send needs a base64-encoded command");
            };
            deliver_encoded(&command, encoded)
        }
        other => bail!("unknown verb {other:?}: run, policy, send, or encode-run"),
    }
}

/// `--class` selects the authorization profile of a *run*; on any other
/// verb it is a typo, not a silent no-op.
fn reject_class(command: &CommandLine, verb: &str) -> Result<()> {
    if let Some(class) = &command.class {
        bail!("--class {class:?} does nothing with {verb:?}: it selects a run's class");
    }
    Ok(())
}

/// Send a command blob (kind byte plus fields) and report the outcome
/// the way a human wants it: a run's output goes to our own, its exit
/// code becomes ours; anything else prints the verdict.
fn deliver(command: &CommandLine, blob: &[u8]) -> Result<i32> {
    deliver_encoded(command, &base64(blob))
}

/// [`deliver`], but the command is already base64.
fn deliver_encoded(command: &CommandLine, encoded: &str) -> Result<i32> {
    let client = client(command)?;
    match client.send_base64(encoded)? {
        CommandOutcome::Completed(output) => {
            std::io::stdout().write_all(&output.stdout)?;
            std::io::stderr().write_all(&output.stderr)?;
            Ok(output.status.unwrap_or(1))
        }
        CommandOutcome::Reconfigured => {
            println!("policy applied");
            Ok(0)
        }
    }
}

/// Build the client from the resolved options: the socket (flag, or the
/// environment variable the server also answers to), the key (always
/// required here — a command is only worth sending signed), the counter
/// file, and the boot id (flag, or this machine's).
fn client(command: &CommandLine) -> Result<CommandClient> {
    let socket = command
        .socket
        .clone()
        .or_else(|| std::env::var_os(wabbit_ipc::socket_var()).map(PathBuf::from))
        .context("no IPC socket: pass --socket or set WABBIT_IPC_SOCKET")?;
    let key_path = command
        .key
        .clone()
        .context("--key is required (the 32-byte signing seed)")?;
    let key = read_seed(&key_path)?;
    let counter = command
        .counter
        .clone()
        .unwrap_or_else(wabbit_ipc::default_counter_path);
    Ok(match &command.boot_id {
        // The explicit boot id is for tunneling: the machine the socket
        // names, not the one this CLI runs on.
        Some(boot_id) => {
            let mut bytes = [0u8; 36];
            bytes.copy_from_slice(boot_id.trim().as_bytes());
            CommandClient::with_boot_id(socket, &key, counter, bytes)
        }
        None => CommandClient::connect(socket, &key, counter)?,
    })
}

/// Read the signing seed (the file `wabbit-policy gen-key` writes:
/// exactly 32 bytes, mode 0600). The read buffer zeroes itself when it
/// goes out of scope — the seed outlives the call only inside the key.
fn read_seed(path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let seed = zeroize::Zeroizing::new(
        std::fs::read(path)
            .with_context(|| format!("reading the signing key {}", path.display()))?,
    );
    if seed.len() != 32 {
        bail!("the signing key must be exactly 32 bytes (wabbit-policy gen-key writes that)");
    }
    Ok(seed)
}

fn base64(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
}
