//! `wabbit-ipc` — mint and deliver signed commands to a running wabbit.
//!
//! Two halves, one per machine (see `wabbit_ipc`'s docs): **minting**
//! needs the signing key and happens wherever the key lives — off box,
//! by design — and **delivery** needs nothing but the socket, because
//! wabbit itself decodes and validates the command. A client that only
//! delivers holds no secret and makes no decision; it needs no trust.
//!
//! ```text
//! # mint off box (needs the key; --boot-id names the TARGET's boot):
//! wabbit-ipc --key policy.key --boot-id "$(ssh box cat /proc/sys/kernel/random/boot_id)" \
//!           --class ultra-privileged encode-run bash
//!
//! # deliver on box (no key, no counter — a dumb pipe):
//! wabbit-ipc --socket /run/wabbit/wabbit.sock '<base64>'
//!
//! # mint and deliver in one step (the machine with the key):
//! wabbit-ipc --key policy.key --socket /run/wabbit/wabbit.sock run sh -c 'uptime'
//! ```
//!
//! (The names above are the stock ones; a branded build's help text —
//! `--help` — spells this binary's own installed name, the product's,
//! and the policy CLI's the deployment set.)

use std::{io::Write, path::PathBuf};

use anyhow::{Context, Result, bail};
use wabbit_common::brand;
use wabbit_ipc::{CommandClient, CommandOutcome};

/// The whole help text, every name in it following the brand: the client
/// names itself by its installed name, the server by the product name,
/// the environment variable by the prefix, and the key tool by the
/// policy CLI's name.
fn usage() -> String {
    let name = brand::NAME;
    let client = brand::CLIENT_NAME;
    let prefix = brand::ENV_PREFIX;
    let policy = brand::POLICY_NAME;
    let counter = wabbit_ipc::default_counter_path().display().to_string();
    format!(
        "\
usage: {client} [options] VERB [arguments]

options:
  --socket PATH     {name}'s IPC socket (default: ${prefix}_IPC_SOCKET);
                    needed by run, policy, stop, send, and the bare form
  --key PATH        the 32-byte Ed25519 signing seed ({policy}
                    gen-key writes it); required for run, policy, stop,
                    encode-run, encode-policy, and encode-stop — the
                    minting verbs.
                    The key never needs to reach the target: mint where
                    it lives, deliver the base64 anywhere
  --counter PATH    the command counter file (default: {counter});
                    the id source when minting, kept by the signer
  --command-id N    mint with this id instead of the counter file — for
                    scripted runs that pick their own (the server still
                    enforces strictly-increasing acceptance)
  --boot-id ID      the TARGET boot's UUID (default: this machine's
                    current boot, from /proc/sys/kernel/random/boot_id).
                    Required in practice when minting off box: a command
                    minted for the wrong boot is rejected by the server
  --class NAME      the class the run executes under (run and
                    encode-run only): the authorization profile this
                    name selects from the target's policy. A classed run
                    gets its own ephemeral cgroup with exactly the
                    class's rules; without it the run is deny-by-default
  -h | --help       this text

verbs:
  run PROGRAM [ARGS...]      mint a run here and deliver it (needs
                             --key and --socket)
  policy FILE                mint a policy application here and deliver
                             it (needs --key and --socket)
  stop                       mint a graceful stop here and deliver it
                             (needs --key and --socket): the
                             authenticated way to ask {name} to end
                             its enforcement and exit — what Ctrl-C
                             was before the self-guard stopped
                             accepting signals from outside processes
  encode-run PROGRAM [ARGS...]
                             mint a run and print it as base64 — no
                             socket touched, nothing delivered; carry
                             the output anywhere
  encode-policy FILE         mint a policy application and print it as
                             base64
  encode-stop                mint a stop and print it as base64
  send BASE64                deliver a minted command verbatim — no key,
                             no counter, no validation: {name} decodes
                             and validates the command itself
  BASE64                     the bare form of send: just the payload

every command is signed (Ed25519) and travels as base64 text of the
complete signed request — one printable, pasteable artifact. Mint it
with the encode-* verbs wherever the key lives (off box), deliver it
with send (or bare) wherever the socket lives:

  {client} --key policy.key --class ultra-privileged encode-run bash
  {client} --socket /run/{name}/{name}.sock \\
    \"$( {client} --key policy.key --class ultra-privileged encode-run bash )\"

minted commands carry strictly-increasing ids — deliver them in mint
order, or the server rejects the ones that arrive below its last
accepted id.
"
    )
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}: {error:#}", brand::CLIENT_NAME);
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
    command_id: Option<u64>,
    boot_id: Option<String>,
    class: Option<String>,
    verb: String,
    arguments: Vec<String>,
}

/// The known verbs — anything else in verb position is the bare form:
/// a base64 command to deliver verbatim.
const VERBS: &[&str] = &[
    "run",
    "policy",
    "stop",
    "encode-run",
    "encode-policy",
    "encode-stop",
    "send",
];

fn parse_arguments() -> Result<CommandLine> {
    let mut command = CommandLine {
        socket: None,
        key: None,
        counter: None,
        command_id: None,
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
            "--command-id" => {
                let raw = value(&mut arguments, "--command-id")?;
                command.command_id = Some(
                    raw.trim()
                        .parse()
                        .with_context(|| format!("--command-id {raw:?} is not a number"))?,
                );
            }
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
                print!("{}", usage());
                std::process::exit(0);
            }
            first => {
                if VERBS.contains(&first) {
                    command.verb = first.to_string();
                    command.arguments = arguments.collect();
                } else {
                    // The bare form: the payload is the whole rest of
                    // the line, delivered verbatim.
                    command.verb = "send".to_string();
                    command.arguments = Some(first.to_string())
                        .into_iter()
                        .chain(arguments)
                        .collect();
                }
                return Ok(command);
            }
        }
    }
    bail!("missing verb: run, policy, stop, encode-run, encode-policy, encode-stop, or send")
}

fn value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    arguments
        .next()
        .with_context(|| format!("{flag} needs a value"))
}

fn run() -> Result<i32> {
    let command = parse_arguments()?;
    match command.verb.as_str() {
        // The minting-and-printing verbs: no socket, nothing delivered.
        // The base64 goes to stdout for capture, carrying, and delivery
        // anywhere — including by hand, into `send` on the target.
        "encode-run" => {
            let Some(program) = command.arguments.first() else {
                bail!("encode-run needs a program");
            };
            let client = minting_client(&command)?;
            let minted = client.mint_run_in_class(
                program,
                &command.arguments[1..],
                command.class.as_deref(),
            )?;
            println!("{minted}");
            Ok(0)
        }
        "encode-policy" => {
            reject_class(&command, "encode-policy")?;
            let Some(path) = command.arguments.first() else {
                bail!("encode-policy needs a signed policy file");
            };
            let policy =
                std::fs::read(path).with_context(|| format!("reading the policy {}", path))?;
            let client = minting_client(&command)?;
            let minted = client.mint_policy(&policy)?;
            println!("{minted}");
            Ok(0)
        }
        // The mint-and-deliver verbs: one step, on the machine that
        // holds the key and can reach the socket.
        "run" => {
            let Some(program) = command.arguments.first() else {
                bail!("run needs a program");
            };
            let client = minting_client(&command)?;
            let outcome =
                client.run_in_class(program, &command.arguments[1..], command.class.as_deref())?;
            report(outcome)
        }
        "policy" => {
            reject_class(&command, "policy")?;
            let Some(path) = command.arguments.first() else {
                bail!("policy needs a signed policy file");
            };
            let policy =
                std::fs::read(path).with_context(|| format!("reading the policy {}", path))?;
            let client = minting_client(&command)?;
            report(client.reconfigure(&policy)?)
        }
        // The authenticated stop: mint and deliver in one step, on the
        // machine that holds the key. `stop` takes no arguments — the
        // signature, the boot id, and the burned counter are the whole
        // command.
        "stop" => {
            reject_class(&command, "stop")?;
            reject_arguments(&command, "stop")?;
            let client = minting_client(&command)?;
            report(client.stop()?)
        }
        "encode-stop" => {
            reject_class(&command, "encode-stop")?;
            reject_arguments(&command, "encode-stop")?;
            let client = minting_client(&command)?;
            let minted = client.mint_stop()?;
            println!("{minted}");
            Ok(0)
        }
        // The delivery-only verb (and the bare form): no key, no
        // counter, no validation — wabbit does all of it. This is the
        // one that runs on the target.
        "send" => {
            reject_class(&command, "send")?;
            let Some(encoded) = command.arguments.first() else {
                bail!("send needs a base64-encoded command");
            };
            let socket = delivery_socket(&command)?;
            let outcome = wabbit_ipc::deliver(&socket, encoded)?;
            report(outcome)
        }
        other => bail!(
            "unknown verb {other:?}: run, policy, stop, encode-run, encode-policy, \
             encode-stop, or send"
        ),
    }
}

/// `stop` (and its encode form) carry no arguments — anything trailing
/// is a typo, not a silent no-op.
fn reject_arguments(command: &CommandLine, verb: &str) -> Result<()> {
    if !command.arguments.is_empty() {
        bail!("{verb} carries no arguments: the stop request is the whole command");
    }
    Ok(())
}

/// Report a command's outcome the way a human wants it: a run's output
/// goes to our own, its exit code becomes ours; anything else prints
/// the verdict.
fn report(outcome: CommandOutcome) -> Result<i32> {
    match outcome {
        CommandOutcome::Completed(output) => {
            std::io::stdout().write_all(&output.stdout)?;
            std::io::stderr().write_all(&output.stderr)?;
            Ok(output.status.unwrap_or(1))
        }
        CommandOutcome::Reconfigured => {
            println!("policy applied");
            Ok(0)
        }
        CommandOutcome::Stopped => {
            println!("stopping: the graceful exit is taken");
            Ok(0)
        }
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

/// The minting client from the resolved options: the key (always
/// required — a command is only worth minting signed), the boot id
/// (flag, or this machine's), and the command id (flag, or the counter
/// file).
fn minting_client(command: &CommandLine) -> Result<CommandClient> {
    let key_path = command
        .key
        .clone()
        .context("--key is required for minting (the 32-byte signing seed)")?;
    let key = read_seed(&key_path)?;
    let counter = command
        .counter
        .clone()
        .unwrap_or_else(wabbit_ipc::default_counter_path);
    let client = match &command.boot_id {
        // The explicit boot id names the machine the command is FOR —
        // required in practice when minting off box.
        Some(boot_id) => {
            let mut bytes = [0u8; 36];
            bytes.copy_from_slice(boot_id.trim().as_bytes());
            CommandClient::with_boot_id(
                // The socket is unused for the encode-* verbs, but the
                // client wants one; any path will do.
                command
                    .socket
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/nonexistent/socket")),
                &key,
                counter,
                bytes,
            )
        }
        None => {
            let socket = command
                .socket
                .clone()
                .unwrap_or_else(|| PathBuf::from("/nonexistent/socket"));
            CommandClient::connect(socket, &key, counter)?
        }
    };
    Ok(match command.command_id {
        Some(id) => client.command_id(id),
        None => client,
    })
}

/// The delivery socket from the resolved options — the only thing
/// delivery needs.
fn delivery_socket(command: &CommandLine) -> Result<PathBuf> {
    command
        .socket
        .clone()
        .or_else(|| std::env::var_os(wabbit_ipc::socket_var()).map(PathBuf::from))
        .context(format!(
            "no IPC socket: pass --socket or set {}_IPC_SOCKET",
            brand::ENV_PREFIX
        ))
}

/// Read the signing seed (the file the policy CLI's `gen-key` writes:
/// exactly 32 bytes, mode 0600 — the CLI's name follows the brand). The
/// read buffer zeroes itself when it goes out of scope — the seed
/// outlives the call only inside the key.
fn read_seed(path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let seed = zeroize::Zeroizing::new(
        std::fs::read(path)
            .with_context(|| format!("reading the signing key {}", path.display()))?,
    );
    if seed.len() != 32 {
        bail!(
            "the signing key must be exactly 32 bytes ({} gen-key writes that)",
            brand::POLICY_NAME
        );
    }
    Ok(seed)
}
