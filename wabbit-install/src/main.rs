//! wabbit-install — install wabbit into the boot chain via the host's
//! initramfs tooling.
//!
//! The recipe this automates is documented in AGENTS.md ("Initrd
//! integration") and docs/wabbit-initrd.md:
//!
//! 1. `/wabbit-initrd` — one statically linked musl binary — placed at the
//!    initramfs root. It embeds the bnuuy eBPF object and the wabbit
//!    binary (materialized at runtime via memfd), so nothing else ships.
//! 2. The init launches it AFTER `/proc`, `/sys`, and `/dev` are mounted
//!    and BEFORE any root mounting: detached (`setsid`), output to the
//!    console (which never blocks when the world freezes), `RUST_LOG=info`.
//! 3. The init cooperates where it cannot be frozen: PID 1 ignores
//!    SIGSTOP, so the flow waits for bnuuy's first bpffs pin
//!    (`/sys/fs/bpf/boot/bpf`) before doing sensitive work, and waits for
//!    wabbit-initrd to exit before switch_root — the handoff choreography
//!    (and the second freeze) belongs to wabbit-initrd.
//! 4. `lsm=bpf` on the kernel command line unless the BPF LSM is already
//!    active — no bnuuy hook can attach without it. (RHEL-family kernels
//!    ship `bpf` in the list; Ubuntu and Debian do not.)
//!
//! Both extension-point slots are the flavors' own: `init-premount` /
//! `init-bottom` for initramfs-tools, `pre-mount` / `pre-pivot` via a
//! 90wabbit dracut module. The launch slots run synchronously in the init
//! flow (a busybox `/init` runs init-premount scripts from PID 1; a
//! systemd initrd runs them as dracut-pre-mount.service children) —
//! either way the world may freeze mid-wait and resume, and either way
//! nothing proceeds until the pin exists.
//!
//! The default pre-switch wait holds the boot at the initrd until
//! wabbit-initrd exits — and its exit is the handoff's completion
//! (wabbit announced readiness, the pre-shutdown self-test passed, the
//! go-ahead was exchanged), so the wait releases the boot exactly at the
//! crossing; `--no-switch-wait` omits that hook. Takes effect on the
//! next boot; the initramfs and any kernel command line change activate
//! together.
//!
//! The wabbit-initrd artifact is compiled into this binary by its build
//! script — the same arrangement wabbit-initrd uses to embed wabbit — so
//! the installer carries its artifact and needs no checkout on the target
//! system; `--artifact` overrides the bundle for custom builds.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Compile-time branding, mirrored from `wabbit-common`'s `brand` module.
/// This crate is deliberately dependency-free, so the few constants it
/// needs are duplicated here; the defaults reproduce the stock names, and
/// a white-label build sets the same environment variables.
mod brand {
    /// The product name: paths, the in-image binary, and message wording.
    pub const NAME: &str = match option_env!("WABBIT_BRAND_NAME") {
        Some(name) => name,
        None => "wabbit",
    };

    /// The environment-variable prefix wabbit reads its configuration
    /// path from (`<prefix>_FILESYSTEM_CONFIGURATION_FILE`).
    pub const ENV_PREFIX: &str = match option_env!("WABBIT_BRAND_ENV_PREFIX") {
        Some(prefix) => prefix,
        None => "WABBIT",
    };

    /// The name of the boot sign: `<name>.bin`.
    pub const SIGN_NAME: &str = match option_env!("WABBIT_BRAND_SIGN_NAME") {
        Some(name) => name,
        None => "bnuuy",
    };

    /// The IPC client's *installed* file name — the deployment
    /// generator's `--name-ipc`, so the box's client and the deployment
    /// directory's copy answer to the same name.
    pub const CLIENT_NAME: &str = match option_env!("WABBIT_INSTALL_CLIENT_NAME") {
        Some(name) => name,
        None => "wabbit-ipc",
    };

    /// Whether `value` is safe as one path/shell component (the same
    /// compile-time validation `wabbit-common` applies).
    const fn is_safe_component(value: &str) -> bool {
        let bytes = value.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.') {
                return false;
            }
            i += 1;
        }
        true
    }

    const _: () = {
        assert!(!NAME.is_empty(), "WABBIT_BRAND_NAME must not be empty");
        assert!(
            is_safe_component(NAME),
            "WABBIT_BRAND_NAME must be one path- and shell-safe component"
        );
        assert!(
            !ENV_PREFIX.is_empty(),
            "WABBIT_BRAND_ENV_PREFIX must not be empty"
        );
        assert!(
            is_safe_component(ENV_PREFIX),
            "WABBIT_BRAND_ENV_PREFIX must be one shell-safe component"
        );
        assert!(
            !SIGN_NAME.is_empty(),
            "WABBIT_BRAND_SIGN_NAME must not be empty"
        );
        assert!(
            is_safe_component(SIGN_NAME),
            "WABBIT_BRAND_SIGN_NAME must be one path- and shell-safe component"
        );
        assert!(
            !CLIENT_NAME.is_empty(),
            "WABBIT_INSTALL_CLIENT_NAME must not be empty"
        );
        assert!(
            is_safe_component(CLIENT_NAME),
            "WABBIT_INSTALL_CLIENT_NAME must be one path- and shell-safe component"
        );
    };
}

/// The stable system path for the artifact; both flavors reference it so
/// initramfs rebuilds do not need the repository.
fn system_binary() -> String {
    let name = brand::NAME;
    format!("/usr/lib/{name}/{name}-initrd")
}

/// The stable system path for the signed policy file: `<prefix>_FILESYSTEM_
/// CONFIGURATION_FILE` names it, the launch hook exports it, and the build
/// hooks copy it into the image so wabbit can read it from the initrd —
/// before `switch_root`, the real root lives under `/sysroot` (dracut) or
/// `/root` (initramfs-tools), so the policy must ride in the image.
fn system_policy() -> String {
    let name = brand::NAME;
    format!("/etc/{name}/policy.wspf")
}

/// The environment line the launch hook exports so wabbit finds the
/// policy: `<prefix>_FILESYSTEM_CONFIGURATION_FILE=<system_policy>`.
fn policy_env_line() -> String {
    format!(
        "{}={}",
        format!("{}_FILESYSTEM_CONFIGURATION_FILE", brand::ENV_PREFIX),
        system_policy()
    )
}

/// The environment line the launch hook exports so wabbit serves IPC
/// commands on a socket: `<prefix>_IPC_SOCKET=<path>`. Without it
/// wabbit never listens — the socket is opt-in, and this flag is the
/// supported way to opt in on a deployed box (the hook is the one
/// place wabbit's environment comes from).
fn ipc_env_line(socket: &str) -> String {
    format!("{}_IPC_SOCKET={}", brand::ENV_PREFIX, socket)
}

/// The wabbit-initrd artifact, compiled into this installer by its build
/// script (static musl, complete with its embedded bnuuy object and
/// wabbit blob) — the installer carries its artifact and needs no
/// checkout.
const BUNDLED_WABBIT_INITRD: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/wabbit-initrd-blob"));

/// The `wabbit-ipc` client, compiled into this installer by its build
/// script (static musl) — the box gets a working signed-command client
/// in its PATH with no second upload. The socket itself stays opt-in
/// (`WABBIT_IPC_SOCKET`).
const BUNDLED_WABBIT_IPC: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wabbit-ipc-blob"));

/// Where the artifact to install comes from.
enum Artifact {
    /// The binary embedded at build time.
    Bundled,
    /// An explicit `--artifact` override.
    Path(PathBuf),
}

// ------------------------------------------------------------------ the hooks

/// The protector's in-image path: the initramfs root.
fn image_binary() -> String {
    format!("/{}-initrd", brand::NAME)
}

/// Where the IPC client lands: the root filesystem's local bin folder —
/// site-local software's standard home, in every target distro's PATH.
/// The file name is the brand's `<name>-ipc`, or the deployment
/// generator's `--name-ipc` when it renamed the deployment copy (see
/// [`brand::client_name`]) — the box's client and the deployment
/// directory's copy answer to the same name.
fn client_binary() -> String {
    format!("/usr/local/bin/{}", brand::CLIENT_NAME)
}

/// The launch hook's pidfiles: `/run`, with `/dev` as the pre-`/run`
/// fallback.
fn pidfiles() -> (String, String) {
    let name = brand::NAME;
    (
        format!("/run/{name}-initrd.pid"),
        format!("/dev/.{name}-initrd.pid"),
    )
}

/// The initramfs-tools prereqs protocol: mkinitramfs invokes every script
/// under `scripts/` with the argument `prereqs` at *build* time to collect
/// ordering (fed to `tsort`), and only runs the body at boot. Without the
/// guard, the boot-time body runs during the initramfs rebuild — launching
/// the protector from the staging host (where the image binary does not
/// exist) and then waiting forever for a boot-time pin that never comes,
/// hanging the rebuild inside `tsort`. dracut never passes `prereqs`, so
/// the same guarded script serves both flavors.
const PREREQS_PREAMBLE: &str = r#"PREREQ=""
prereqs() {
    echo "$PREREQ"
}
case "$1" in
prereqs)
    prereqs
    exit 0
    ;;
esac
"#;

/// The launch hook: the documented `/init` recipe, run from the flavor's
/// launch slot. POSIX sh — initramfs hooks run under busybox too.
///
/// `setsid` keeps terminal and job-control signals away from the protector
/// and everything it spawns, but no initrd guarantees it exists (noble's
/// carries none), so the hook degrades to a plain background launch when
/// it is missing rather than failing the boot step. The pin wait is
/// fail-open for the same reason: a protector that dies before arming
/// must never hang the boot — an unprotected boot beats a frozen one.
///
/// When a policy is installed (`--policy`), the hook also exports
/// `<prefix>_FILESYSTEM_CONFIGURATION_FILE`: wabbit reads it from its
/// inherited environment and verifies the file's Ed25519 signature against
/// the key compiled into the wabbit binary. No policy installed → no env
/// var → wabbit boots on `Policy::default()` (deny-by-default maps).
fn launch_hook(policy_installed: bool, ipc_socket: Option<&str>) -> String {
    let name = brand::NAME;
    let binary = image_binary();
    let (pidfile_run, pidfile_dev) = pidfiles();
    // The env assignment prefixes the launch line (`VAR=x cmd`), so it must
    // carry its own trailing space when present and nothing when not.
    let policy_env = if policy_installed {
        format!("{} ", policy_env_line())
    } else {
        String::new()
    };
    let ipc_env = match ipc_socket {
        Some(socket) => format!("{} ", ipc_env_line(socket)),
        None => String::new(),
    };
    format!(
        r#"#!/bin/sh
# {name}: launch the initrd protector. This slot runs after /proc, /sys,
# and /dev are mounted, before any root mounting. The console never
# blocks when the world freezes (a pipe-backed stderr would). RUST_LOG
# matters: env_logger defaults to error-only.
{PREREQS_PREAMBLE}
if command -v setsid >/dev/null 2>&1; then
    {policy_env}{ipc_env}RUST_LOG=info setsid {binary} </dev/null >/dev/console 2>&1 &
else
    {policy_env}{ipc_env}RUST_LOG=info {binary} </dev/null >/dev/console 2>&1 &
fi
protector_pid=$!
pidfile={pidfile_run}
if ! echo "$protector_pid" >"$pidfile" 2>/dev/null; then
    pidfile={pidfile_dev}
    echo "$protector_pid" >"$pidfile"
fi

# Cooperation: the kernel discards SIGSTOP for PID 1, so a busybox /init
# (or systemd) cannot be frozen. This hook runs synchronously from the
# init flow, so waiting here means nothing proceeds until the
# protector's first pin exists. The freeze may stop this very wait; the
# protector resumes it when the world thaws. Fail-open: a protector that
# died before arming releases the boot to continue unprotected —
# waiting for a pin from a dead process would hang the boot forever.
while [ ! -e /sys/fs/bpf/boot/bpf ]; do
    if ! kill -0 "$protector_pid" 2>/dev/null; then
        echo "{name}: the protector exited before arming; continuing unprotected" >/dev/console
        break
    fi
    sleep 0.1
done
"#
    )
}

/// The pre-switch wait: after the real root is mounted and settled, the
/// rest belongs to the protector. Do not race it to switch_root — its exit
/// is the handoff's completion, and only then is the boot free to cross.
fn switch_wait_hook() -> String {
    let name = brand::NAME;
    let (pidfile_run, pidfile_dev) = pidfiles();
    format!(
        r#"#!/bin/sh
# {name}: hold until {name}-initrd exits. It owns the handoff
# choreography — wabbit's readiness announcement, the pre-shutdown
# self-test, the go-ahead — and the boot must not race it to
# switch_root. The wait ends at its exit, which is exactly the
# handoff's completion; {name} itself survives the crossing
# (argv[0][0] == '@' spares it the switch-root kill).
{PREREQS_PREAMBLE}
for pidfile in {pidfile_run} {pidfile_dev}; do
    if [ -f "$pidfile" ]; then
        protector_pid=$(cat "$pidfile")
        while kill -0 "$protector_pid" 2>/dev/null; do sleep 0.5; done
    fi
done
"#
    )
}

/// The initramfs-tools build hook: carries the binary into the image at
/// mkinitramfs time, with `$DESTDIR` as the staging tree. `setsid` comes
/// along when the host has it (the launch hook degrades to a plain
/// background launch when the image lacks it — best effort, never a
/// failure). The policy rides along when one is installed: wabbit reads
/// it from the initrd, before `switch_root` exposes the real root.
fn initramfs_tools_build_hook() -> String {
    let name = brand::NAME;
    let system = system_binary();
    let binary = image_binary();
    let policy = system_policy();
    format!(
        r#"#!/bin/sh
# {name}: carry {name}-initrd into the image. This is an initramfs-tools
# build hook: $DESTDIR is the staging tree.
set -e
if [ -z "${{DESTDIR:-}}" ]; then
    echo "{name} hook: DESTDIR is not set — run me via mkinitramfs" >&2
    exit 1
fi
mkdir -p "$DESTDIR"
if command -v copy_exec >/dev/null 2>&1; then
    copy_exec {system} {binary}
    if command -v setsid >/dev/null 2>&1; then
        copy_exec "$(command -v setsid)"
    else
        echo "{name} hook: no setsid on this host; the launch hook will run without it" >&2
    fi
else
    cp {system} "$DESTDIR{binary}"
    chmod 0755 "$DESTDIR{binary}"
fi
if [ -f {policy} ]; then
    mkdir -p "$DESTDIR$(dirname {policy})"
    cp {policy} "$DESTDIR{policy}"
fi
"#
    )
}

/// The dracut module: installs the binary and the hook scripts into the
/// image when the image is generated. `$initdir` is the image staging
/// tree, `$moddir` the module's directory, `$hookdir` the in-image hook
/// root. Hook scripts are sourced into the init shell by busybox-style
/// inits and run as dracut-pre-mount / dracut-pre-pivot services in
/// systemd initrds — the same slots, either way.
fn dracut_module_setup() -> String {
    let name = brand::NAME;
    let system = system_binary();
    let binary = image_binary();
    let policy = system_policy();
    format!(
        r#"#!/bin/sh
# dracut module: {name}-initrd.
check() {{ return 0; }}
depends() {{ return 0; }}

install() {{
    # The binary at a stable system path; inside the image it is
    # {binary}, at the initramfs root.
    inst_binary {system} {binary}

    # setsid for the launch hook's session isolation — best effort; the
    # hook degrades to a plain background launch without it.
    if command -v setsid >/dev/null 2>&1; then
        inst_binary setsid
    else
        echo "{name}: no setsid on this host; the launch hook will run without it" >&2
    fi

    # The policy, when one is installed: wabbit reads it from the initrd,
    # before switch_root exposes the real root.
    if [ -f {policy} ]; then
        inst_simple {policy} {policy}
    fi

    # The hooks, through dracut's own helper. A module's install() must
    # never invoke `install(1)` by bare name: bash resolves it to the
    # install() function this file defines, recursing until its C stack
    # dies — the dracut SIGSEGV the first rocky deploy runs hit, which
    # looked exactly like a distro bug. inst_hook validates the hook type
    # against dracut's $hookdirs and the script's existence, and installs
    # into /lib/dracut/hooks/<type>/<prio>-<script>; the hooks run in
    # lexical order within each type.
    inst_hook pre-mount 01 "$moddir/launch.sh"
    if [ -e "$moddir/switch-wait.sh" ]; then
        inst_hook pre-pivot 99 "$moddir/switch-wait.sh"
    fi
}}
"#
    )
}

/// The dracut module's own directory, `90<name>`.
fn dracut_module_dir() -> String {
    format!("/usr/lib/dracut/modules.d/90{}", brand::NAME)
}

/// The grub drop-in: a LATER numbered file wins over a cloud image's
/// `50-cloudimg-settings.cfg` without having to know what it says.
fn grub_lsm_drop_in() -> String {
    format!(
        r#"# {name}: enroll the BPF LSM — the boot protections cannot attach without it.
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=bpf"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX lsm=bpf"
"#,
        name = brand::NAME
    )
}

// -------------------------------------------------------------------- helpers

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Dracut,
    InitramfsTools,
}

impl Flavor {
    fn as_str(self) -> &'static str {
        match self {
            Flavor::Dracut => "dracut",
            Flavor::InitramfsTools => "initramfs-tools",
        }
    }
}

impl std::fmt::Display for Flavor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

struct Options {
    artifact: Option<String>,
    /// A `wabbit-ipc` client binary to install instead of the one
    /// bundled at build time.
    client: Option<String>,
    /// A signed policy file to install at [`system_policy`] and export to
    /// wabbit through the launch hook. `None` → wabbit boots on
    /// `Policy::default()`.
    policy: Option<String>,
    /// Have the launch hook export `<prefix>_IPC_SOCKET=<path>` so
    /// wabbit serves signed IPC commands on a socket. `None` → wabbit
    /// never listens (the socket is opt-in, and the hook is the one
    /// place wabbit's environment comes from).
    ipc_socket: Option<String>,
    flavor: Option<Flavor>,
    switch_wait: bool,
    do_lsm: bool,
    remove: bool,
    dry_run: bool,
}

fn die(message: &str) -> ! {
    eprintln!("{}-install: {message}", brand::NAME);
    std::process::exit(1);
}

fn usage(code: i32) -> ! {
    let name = brand::NAME;
    let client = brand::CLIENT_NAME;
    print!(
        "\
usage: {name}-install [options]
  --artifact PATH   install this {name}-initrd binary instead of the one
                    bundled at build time
  --client PATH     install this {client} client at /usr/local/bin instead
                    of the one bundled at build time
  --policy PATH     install this signed policy file at /etc/{name}/policy.wspf,
                    copy it into the initramfs, and export
                    <prefix>_FILESYSTEM_CONFIGURATION_FILE to {name}
                    through the launch hook
  --ipc-socket PATH have {name} serve signed IPC commands on this Unix
                    socket (the launch hook exports
                    <prefix>_IPC_SOCKET=PATH; without it {name} never
                    listens). The client lands in /usr/local/bin either
                    way — {client} run/policy/send need the socket.
  --flavor NAME     dracut | initramfs-tools (default: autodetect)
  --no-switch-wait  do not install the pre-switch_root wait hook
  --no-lsm          do not add lsm=bpf to the kernel command line
  --remove          uninstall everything this tool installs
  --dry-run         print what would be done, change nothing
  -h | --help       this text
"
    );
    std::process::exit(code)
}

fn parse_args() -> Options {
    let mut options = Options {
        artifact: None,
        client: None,
        policy: None,
        ipc_socket: None,
        flavor: None,
        switch_wait: true,
        do_lsm: true,
        remove: false,
        dry_run: false,
    };
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--artifact" => {
                options.artifact = Some(
                    arguments
                        .next()
                        .unwrap_or_else(|| die("--artifact needs a path")),
                )
            }
            "--client" => {
                options.client = Some(
                    arguments
                        .next()
                        .unwrap_or_else(|| die("--client needs a path")),
                )
            }
            "--policy" => {
                options.policy = Some(
                    arguments
                        .next()
                        .unwrap_or_else(|| die("--policy needs a path")),
                )
            }
            "--ipc-socket" => {
                let socket = arguments
                    .next()
                    .unwrap_or_else(|| die("--ipc-socket needs a path"));
                if !socket.starts_with('/') {
                    die(
                        "--ipc-socket needs an absolute path ({name} runs before / is relative to anything)",
                    );
                }
                options.ipc_socket = Some(socket);
            }
            "--flavor" => {
                let flavor = arguments
                    .next()
                    .unwrap_or_else(|| die("--flavor needs a name"));
                options.flavor = Some(match flavor.as_str() {
                    "dracut" => Flavor::Dracut,
                    "initramfs-tools" => Flavor::InitramfsTools,
                    other => die(&format!(
                        "unknown flavor '{other}' (dracut | initramfs-tools)"
                    )),
                });
            }
            "--no-switch-wait" => options.switch_wait = false,
            "--no-lsm" => options.do_lsm = false,
            "--remove" => options.remove = true,
            "--dry-run" => options.dry_run = true,
            "-h" | "--help" => usage(0),
            other => {
                eprintln!("unknown option: {other}");
                usage(1);
            }
        }
    }
    options
}

/// The effective uid, from /proc/self/status — no libc dependency for one
/// number.
fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // real, effective, saved, fs
            return rest.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

/// `command -v`, without forking.
fn in_path(program: &str) -> bool {
    let path = env::var_os("PATH").unwrap_or_default();
    env::split_paths(&path).any(|directory| directory.join(program).is_file())
}

/// Write a file with an explicit mode (initramfs hooks must be
/// executable; the grub drop-in must not be).
fn write_file(dry_run: bool, mode: u32, path: &str, contents: &str) {
    println!("+ install -m {mode:o} (generated) {path}");
    if dry_run {
        return;
    }
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(error) = fs::write(path, contents) {
        die(&format!("writing {path}: {error}"));
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            die(&format!("setting the mode of {path}: {error}"));
        }
    }
}

fn remove_file(dry_run: bool, path: &str) {
    if !Path::new(path).exists() {
        return;
    }
    println!("+ rm -f {path}");
    if !dry_run && let Err(error) = fs::remove_file(path) {
        die(&format!("removing {path}: {error}"));
    }
}

fn remove_dir_if_empty(dry_run: bool, path: &str) {
    println!("+ rmdir (if empty) {path}");
    if dry_run {
        return;
    }
    if let Ok(mut entries) = fs::read_dir(path)
        && entries.next().is_none()
    {
        let _ = fs::remove_dir(path);
    }
}

fn run(dry_run: bool, program: &str, arguments: &[&str]) {
    print!("+ {program}");
    for argument in arguments {
        print!(" {argument}");
    }
    println!();
    if dry_run {
        return;
    }
    match Command::new(program).args(arguments).status() {
        Ok(status) if status.success() => {}
        Ok(status) => die(&format!("{program} failed: {status}")),
        Err(error) => die(&format!("running {program}: {error}")),
    }
}

/// Run a command and return its stdout, for the image verification.
fn capture(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

/// Resolve the artifact to install: the bundle embedded at build time,
/// or the explicit `--artifact` override (which must be a real,
/// executable file — the bundle already went through the build).
fn find_artifact(options: &Options) -> Artifact {
    let Some(artifact) = &options.artifact else {
        return Artifact::Bundled;
    };
    let path = Path::new(artifact);
    if !path.is_file() {
        die(&format!("artifact '{artifact}' does not exist"));
    }
    if let Err(error) = path.metadata().and_then(|metadata| {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            Err(std::io::Error::other("not executable"))
        } else {
            Ok(())
        }
    }) {
        die(&format!("artifact '{artifact}' is {error}"));
    }
    Artifact::Path(path.to_path_buf())
}

// ------------------------------------------------------------------ the flows

fn remove(options: &Options, flavor: Flavor) -> ! {
    let name = brand::NAME;
    if flavor == Flavor::InitramfsTools {
        remove_file(
            options.dry_run,
            &format!("/etc/initramfs-tools/hooks/{name}"),
        );
        remove_file(
            options.dry_run,
            &format!("/etc/initramfs-tools/scripts/init-premount/{name}"),
        );
        remove_file(
            options.dry_run,
            &format!("/etc/initramfs-tools/scripts/init-bottom/{name}"),
        );
        run(options.dry_run, "update-initramfs", &["-u", "-k", "all"]);
    } else {
        let module = dracut_module_dir();
        remove_file(options.dry_run, &format!("{module}/module-setup.sh"));
        remove_file(options.dry_run, &format!("{module}/launch.sh"));
        remove_file(options.dry_run, &format!("{module}/switch-wait.sh"));
        remove_dir_if_empty(options.dry_run, &module);
        run(options.dry_run, "dracut", &["--force"]);
    }
    remove_file(options.dry_run, &system_binary());
    remove_dir_if_empty(options.dry_run, &format!("/usr/lib/{name}"));
    remove_file(options.dry_run, &client_binary());
    remove_file(options.dry_run, &system_policy());
    remove_dir_if_empty(options.dry_run, &format!("/etc/{name}"));
    // The lsm=bpf addition is deliberately left in place: it is additive
    // (it only enrolls one more LSM) and other tooling may rely on it.
    println!("removed. any lsm=bpf added to the kernel command line was left alone.");
    std::process::exit(0);
}

// ------------------------------------------------------------------ the stamp

/// This installer build's timestamp, emitted by the build script (see its
/// doc comment for the convention): the mtime every file the installer
/// writes carries once [`stamp_installed_files`] has run.
const BUILD_TIME: &str = env!("WABBIT_INSTALL_BUILD_TIME");

fn build_time() -> i64 {
    BUILD_TIME
        .parse()
        .expect("the build script emits an integer timestamp")
}

/// Every file this run wrote to the root filesystem — the paths the
/// install flow just created, with the same conditions that created
/// them. The files *inside* the rebuilt initramfs are not on this list:
/// mkinitramfs and dracut own their images' contents and their mtimes;
/// neither is `/etc/default/grub`, a distro-owned file this tool only
/// amends in place.
fn installed_paths(options: &Options, flavor: Flavor) -> Vec<String> {
    let name = brand::NAME;
    let mut paths = vec![system_binary(), client_binary()];
    if options.policy.is_some() {
        paths.push(system_policy());
    }
    match flavor {
        Flavor::InitramfsTools => {
            paths.push(format!("/etc/initramfs-tools/hooks/{name}"));
            paths.push(format!("/etc/initramfs-tools/scripts/init-premount/{name}"));
            if options.switch_wait {
                paths.push(format!("/etc/initramfs-tools/scripts/init-bottom/{name}"));
            }
        }
        Flavor::Dracut => {
            let module = dracut_module_dir();
            paths.push(format!("{module}/launch.sh"));
            paths.push(format!("{module}/module-setup.sh"));
            if options.switch_wait {
                paths.push(format!("{module}/switch-wait.sh"));
            }
        }
    }
    // The grub drop-in: written only when this run took the drop-in
    // path (not grubby, not the in-place amendment, and the BPF LSM
    // was not already active).
    if options.do_lsm && !bpf_lsm_active() && !in_path("grubby") {
        paths.push(format!("/etc/default/grub.d/99-{name}-lsm.cfg"));
    }
    paths
}

/// The end-of-install pass: stamp everything this run wrote with this
/// build's time. After the fact, deliberately — one pass here instead
/// of hooks in every write path — so no future write path can forget
/// it. Failures warn and move on: the files are placed and correct; a
/// stamp the filesystem refused is a cosmetic loss, not a broken
/// install.
fn stamp_installed_files(options: &Options, flavor: Flavor) {
    if options.dry_run {
        println!("(dry-run: skipping the build-time stamp)");
        return;
    }
    let stamp = build_time();
    let mut stamped = 0usize;
    for path in installed_paths(options, flavor) {
        if !Path::new(&path).exists() {
            continue;
        }
        match stamp_one(&path, stamp) {
            Ok(()) => stamped += 1,
            Err(error) => eprintln!("{}-install: could not stamp {path}: {error}", brand::NAME),
        }
    }
    println!("+ stamped {stamped} installed file(s) with this build's time");
}

/// Set one file's access and modification times to `stamp` (seconds
/// since the epoch).
fn stamp_one(path: &str, stamp: i64) -> Result<(), rustix::io::Errno> {
    use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};
    let time = Timespec {
        tv_sec: stamp,
        tv_nsec: 0,
    };
    let times = Timestamps {
        last_access: time,
        last_modification: time,
    };
    utimensat(CWD, path, &times, AtFlags::empty())
}

fn install(options: &Options, flavor: Flavor) {
    let name = brand::NAME;
    let sign_name = brand::SIGN_NAME;
    let system = system_binary();
    let artifact = find_artifact(options);
    let artifact_name = match &artifact {
        Artifact::Bundled => format!("<bundled {name}-initrd>"),
        Artifact::Path(path) => path.display().to_string(),
    };

    println!("flavor: {}", flavor.as_str());
    println!("+ install -m 0755 {artifact_name} {system}");
    if !options.dry_run {
        if let Some(parent) = Path::new(&system).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let write = match &artifact {
            Artifact::Bundled => fs::write(&system, BUNDLED_WABBIT_INITRD),
            Artifact::Path(path) => fs::copy(path, &system).map(|_| ()),
        };
        if let Err(error) = write {
            die(&format!("installing the artifact to {system}: {error}"));
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&system, std::fs::Permissions::from_mode(0o755));
    }

    // The IPC client: on the box, in its PATH, so operators command the
    // running wabbit without a second upload. Harmless without the
    // socket — it reports "no IPC socket" and exits — so installing it
    // unconditionally is safe.
    let client = client_binary();
    let client_src = options
        .client
        .clone()
        .unwrap_or_else(|| format!("<bundled {}>", brand::CLIENT_NAME));
    println!("+ install -m 0755 {client_src} {client}");
    if !options.dry_run {
        if let Some(parent) = Path::new(&client).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let write = match &options.client {
            Some(path) => fs::copy(path, &client).map(|_| ()),
            None => fs::write(&client, BUNDLED_WABBIT_IPC),
        };
        if let Err(error) = write {
            die(&format!("installing the IPC client to {client}: {error}"));
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755));
    }

    // The policy, before the hooks that reference it and the image rebuild
    // that copies it in. Mode 0600: the policy names blue-team paths, and
    // nothing but wabbit (root) needs to read it.
    if let Some(policy) = &options.policy {
        let destination = system_policy();
        println!("+ install -m 0600 {policy} {destination}");
        if !options.dry_run {
            if let Some(parent) = Path::new(&destination).parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(error) = fs::copy(policy, &destination) {
                die(&format!(
                    "installing the policy {policy} to {destination}: {error}"
                ));
            }
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600));
        }
    }

    match flavor {
        Flavor::InitramfsTools => {
            write_file(
                options.dry_run,
                0o755,
                &format!("/etc/initramfs-tools/hooks/{name}"),
                &initramfs_tools_build_hook(),
            );
            write_file(
                options.dry_run,
                0o755,
                &format!("/etc/initramfs-tools/scripts/init-premount/{name}"),
                &launch_hook(options.policy.is_some(), options.ipc_socket.as_deref()),
            );
            if options.switch_wait {
                write_file(
                    options.dry_run,
                    0o755,
                    &format!("/etc/initramfs-tools/scripts/init-bottom/{name}"),
                    &switch_wait_hook(),
                );
            }
            run(options.dry_run, "update-initramfs", &["-u", "-k", "all"]);
        }
        Flavor::Dracut => {
            let module = dracut_module_dir();
            write_file(
                options.dry_run,
                0o755,
                &format!("{module}/launch.sh"),
                &launch_hook(options.policy.is_some(), options.ipc_socket.as_deref()),
            );
            if options.switch_wait {
                write_file(
                    options.dry_run,
                    0o755,
                    &format!("{module}/switch-wait.sh"),
                    &switch_wait_hook(),
                );
            }
            write_file(
                options.dry_run,
                0o755,
                &format!("{module}/module-setup.sh"),
                &dracut_module_setup(),
            );
            run(
                options.dry_run,
                "dracut",
                &["--force", "--add", brand::NAME],
            );
        }
    }

    if !options.dry_run {
        verify_image(flavor);
    } else {
        println!("(dry-run: skipping image verification)");
    }

    if options.do_lsm {
        enroll_bpf_lsm(options);
    }

    // The after-the-fact pass: everything this run wrote, stamped with
    // this build's time — dpkg's and rpm's convention, so the installed
    // files sit consistently with the distro-packaged files around them
    // (which all carry their package's build time, not the install
    // moment), and one build's files are byte- and time-identical no
    // matter how often it is (re)installed.
    stamp_installed_files(options, flavor);

    let image = image_binary();
    let installed_client = brand::CLIENT_NAME;
    let switch_summary = if options.switch_wait {
        format!("waits for {name}-initrd to exit (see the handoff note in --help)")
    } else {
        "NOT INSTALLED (--no-switch-wait)".to_string()
    };
    let policy_summary = if options.policy.is_some() {
        format!(
            "installed at {} and exported to {name} via <prefix>_FILESYSTEM_CONFIGURATION_FILE",
            system_policy()
        )
    } else {
        format!("NOT INSTALLED (no --policy; {name} boots on Policy::default())")
    };
    let ipc_summary = match &options.ipc_socket {
        Some(socket) => format!("{socket} — {installed_client} on /usr/local/bin talks to it"),
        None => format!("NOT LISTENING (no --ipc-socket; {name} takes no commands)"),
    };
    print!(
        "
installed via {flavor}:
  binary:        {image} in the image (installed from {artifact_name})
  client:        {client} — command the running {name} with {installed_client}
  launch:        after /proc, /sys, /dev are mounted, before root mounting;
                 holds the init flow until the protector's /sys/fs/bpf/boot/bpf pin
  before
  switch_root:   {switch_summary}
  policy:       {policy_summary}
  ipc:           {ipc_summary}

takes effect on the next boot. any {name}-initrd failure leaves the {sign_name}
sign at /run/{sign_name}.bin explaining why — the boot itself continues
unprotected rather than not at all.
"
    );
}

/// Best-effort confirmation that the rebuilt image actually carries the
/// wiring; a warning, not a failure.
fn verify_image(flavor: Flavor) {
    let name = brand::NAME;
    let carrying = |listing: String| {
        listing
            .lines()
            .filter(|line| line.contains(name))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let found = match flavor {
        Flavor::InitramfsTools => {
            let image = format!("/boot/initrd.img-{}", uname_release());
            capture("lsinitramfs", &[&image]).map(carrying)
        }
        Flavor::Dracut => capture("lsinitrd", &[]).map(carrying),
    };
    match found {
        Some(lines) if !lines.is_empty() => println!("image carries: {}", lines.join(" ")),
        _ => eprintln!(
            "warning: could not confirm {} inside the image (lsinitrd/lsinitramfs)",
            brand::NAME
        ),
    }
}

fn uname_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// `lsm=bpf` on the kernel command line unless the BPF LSM is already
/// active — no bnuuy hook can attach without it.
/// Whether the BPF LSM is already enrolled on this kernel.
fn bpf_lsm_active() -> bool {
    fs::read_to_string("/sys/kernel/security/lsm")
        .map(|active| active.split(',').any(|lsm| lsm.trim() == "bpf"))
        .unwrap_or(false)
}

fn enroll_bpf_lsm(options: &Options) {
    if bpf_lsm_active() {
        let active = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        println!("lsm: the BPF LSM is already active ({})", active.trim());
        return;
    }
    if in_path("grubby") {
        // BLS systems (RHEL family): grubby manages the boot entries.
        run(
            options.dry_run,
            "grubby",
            &["--update-kernel=ALL", "--args=lsm=bpf"],
        );
    } else if Path::new("/etc/default/grub.d").is_dir() {
        write_file(
            options.dry_run,
            0o644,
            &format!("/etc/default/grub.d/99-{}-lsm.cfg", brand::NAME),
            &grub_lsm_drop_in(),
        );
        run(options.dry_run, "update-grub", &[]);
    } else {
        prepend_lsm_to_grub_default(options);
        run(options.dry_run, "update-grub", &[]);
    }
}

/// The no-grub.d fallback: add `lsm=bpf` to GRUB_CMDLINE_LINUX_DEFAULT in
/// place — idempotently, unlike the sed it replaces.
fn prepend_lsm_to_grub_default(options: &Options) {
    let path = "/etc/default/grub";
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => die(&format!(
            "reading {path}: {error} — pass --no-lsm to skip the kernel command line step"
        )),
    };
    let mut changed = false;
    let mut updated = String::with_capacity(contents.len());
    for line in contents.lines() {
        if line.starts_with("GRUB_CMDLINE_LINUX_DEFAULT=\"") && !line.contains("lsm=bpf") {
            updated.push_str(&line.replacen(
                "GRUB_CMDLINE_LINUX_DEFAULT=\"",
                "GRUB_CMDLINE_LINUX_DEFAULT=\"lsm=bpf ",
                1,
            ));
            changed = true;
        } else {
            updated.push_str(line);
        }
        updated.push('\n');
    }
    if !changed {
        println!(
            "lsm: {path} carries no GRUB_CMDLINE_LINUX_DEFAULT to amend; edit it by hand to add lsm=bpf"
        );
        return;
    }
    println!("+ amend {path} (add lsm=bpf to GRUB_CMDLINE_LINUX_DEFAULT)");
    if !options.dry_run
        && let Err(error) = fs::write(path, updated)
    {
        die(&format!("writing {path}: {error}"));
    }
}

fn main() {
    let options = parse_args();

    if !options.dry_run && effective_uid().unwrap_or(1) != 0 {
        die("must run as root: it writes the initramfs and the boot configuration");
    }

    let flavor = match options.flavor {
        Some(flavor) => flavor,
        None => {
            let dracut = in_path("dracut");
            let initramfs_tools = in_path("update-initramfs");
            match (dracut, initramfs_tools) {
                (true, true) => {
                    die("both dracut and initramfs-tools are present; pick one with --flavor")
                }
                (true, false) => Flavor::Dracut,
                (false, true) => Flavor::InitramfsTools,
                (false, false) => die("neither dracut nor initramfs-tools found on this host"),
            }
        }
    };

    if options.remove {
        remove(&options, flavor);
    }
    install(&options, flavor);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launch_hook_is_the_documented_recipe() {
        let name = brand::NAME;
        let hook = launch_hook(false, None);
        assert!(hook.contains(&format!(
            "RUST_LOG=info setsid /{name}-initrd </dev/null >/dev/console 2>&1 &"
        )));
        assert!(hook.contains("/sys/fs/bpf/boot/bpf"));
    }

    /// `--ipc-socket` reaches wabbit the only way anything can: the
    /// launch hook's environment, prefixing the same launch line the
    /// policy env prefixes.
    #[test]
    fn the_ipc_socket_is_exported_through_the_hook() {
        let hook = launch_hook(false, Some("/run/wabbit/wabbit.sock"));
        assert!(hook.contains(&format!(
            "{}_IPC_SOCKET=/run/wabbit/wabbit.sock ",
            brand::ENV_PREFIX
        )));
        // …on the launch line itself, before RUST_LOG, so wabbit is
        // born with it.
        assert!(hook.contains(&format!(
            "{}_IPC_SOCKET=/run/wabbit/wabbit.sock RUST_LOG=info",
            brand::ENV_PREFIX
        )));
        // And without the flag, nothing socket-shaped leaks in.
        assert!(!launch_hook(false, None).contains("IPC_SOCKET"));
    }

    /// With a policy installed, the launch hook exports the env var wabbit
    /// reads its path from; without one, it must not — wabbit boots on
    /// `Policy::default()` and an env var naming a missing file would fail
    /// the boot step instead.
    #[test]
    fn the_launch_hook_exports_the_policy_only_when_installed() {
        let with_policy = launch_hook(true, None);
        assert!(
            with_policy.contains(&policy_env_line()),
            "the installed hook must export {}",
            policy_env_line()
        );
        let without_policy = launch_hook(false, None);
        assert!(
            !without_policy.contains("FILESYSTEM_CONFIGURATION_FILE"),
            "a policy-less install must not export the policy env var"
        );
    }

    /// Both flavors' build hooks carry the policy into the image: wabbit
    /// reads it from the initrd, before `switch_root` exposes the real
    /// root (`/sysroot`/`/root` mount points).
    #[test]
    fn the_build_hooks_carry_the_policy() {
        let policy = system_policy();
        assert!(
            initramfs_tools_build_hook().contains(&format!("cp {policy} ")),
            "the initramfs-tools hook must copy the policy into $DESTDIR"
        );
        assert!(
            dracut_module_setup().contains(&format!("inst_simple {policy} {policy}")),
            "the dracut module must install the policy into the image"
        );
    }

    #[test]
    fn the_switch_wait_holds_on_the_protector() {
        assert!(switch_wait_hook().contains("kill -0 \"$protector_pid\""));
    }

    /// The launch hook must degrade rather than fail: no `setsid` in the
    /// image (noble's initramfs ships none — the deploy lab caught the
    /// resulting hang) means a plain background launch, and a protector
    /// that dies before arming must release the boot, not hang it in the
    /// pin wait — an unprotected boot beats a frozen one.
    #[test]
    fn the_launch_hook_fails_open() {
        let hook = launch_hook(false, None);
        assert!(
            hook.contains("if command -v setsid >/dev/null 2>&1; then"),
            "the launch must fall back to a plain background launch"
        );
        assert!(
            hook.contains("RUST_LOG=info /") || hook.contains("RUST_LOG=info {"),
            "the fallback launch line is missing"
        );
        assert!(
            hook.contains("continuing unprotected"),
            "a dead protector must break the pin wait"
        );
    }

    /// Both flavors' build hooks carry `setsid` into the image when the
    /// host has it, so the launch hook's preferred path exists in the
    /// initrd.
    #[test]
    fn the_build_hooks_carry_setsid() {
        assert!(initramfs_tools_build_hook().contains("copy_exec \"$(command -v setsid)\""));
        assert!(dracut_module_setup().contains("inst_binary setsid"));
    }

    #[test]
    /// The dracut module installs its hooks through dracut's `inst_hook`
    /// into the standard hook types — and never invokes `install(1)` by
    /// bare name: a module's `install()` hook resolves that to itself in
    /// bash, recurses, and takes dracut down with a SIGSEGV that looks
    /// like a distro bug (measured on Rocky 9.8).
    fn the_dracut_module_uses_dracut_hook_dirs() {
        let setup = dracut_module_setup();
        assert!(setup.contains(r#"inst_hook pre-mount 01"#));
        assert!(setup.contains(r#"inst_hook pre-pivot 99"#));
        assert!(
            !setup.contains("install -m"),
            "bare `install -m` in install() recurses into itself in bash: dracut SIGSEGV"
        );
    }

    #[test]
    fn the_grub_drop_in_enrolls_the_bpf_lsm() {
        assert!(grub_lsm_drop_in().contains("lsm=bpf"));
    }

    /// The hooks carry the brand — and no other name — in every path
    /// they touch.
    #[test]
    fn the_hooks_carry_the_brand() {
        let name = brand::NAME;
        assert!(launch_hook(false, None).contains(&format!("/{name}-initrd")));
        assert!(initramfs_tools_build_hook().contains(&system_binary()));
        assert!(dracut_module_dir().contains(&format!("90{name}")));
        assert!(system_binary().contains(&format!("/usr/lib/{name}/{name}")));
        assert!(system_policy().contains(&format!("/etc/{name}/policy.wspf")));
        assert!(policy_env_line().contains("FILESYSTEM_CONFIGURATION_FILE="));
    }

    /// Both initramfs-tools hooks must answer the build-time `prereqs`
    /// invocation and exit before their boot-time body: mkinitramfs runs
    /// every `scripts/` entry with `prereqs` while collecting ordering,
    /// and without the guard the rebuild launches the protector from the
    /// staging host and then waits forever for a boot-time pin — exactly
    /// the hang the deploy lab caught (`tsort` never seeing EOF).
    #[test]
    fn the_hooks_answer_the_prereqs_invocation() {
        for (hook, body) in [
            (launch_hook(false, None), "RUST_LOG=info setsid"),
            (switch_wait_hook(), "for pidfile in"),
        ] {
            let guard = hook
                .find("case \"$1\" in\nprereqs)\n    prereqs\n    exit 0\n    ;;\nesac")
                .expect("the prereqs guard is missing");
            let body_at = hook.find(body).expect("the hook's body is missing");
            assert!(
                guard < body_at,
                "the prereqs guard must exit before the boot-time body"
            );
        }
    }

    /// The build script really did bundle an artifact: a non-empty ELF.
    #[test]
    fn the_bundle_is_a_real_artifact() {
        assert!(
            BUNDLED_WABBIT_INITRD.len() > 1_000_000,
            "the bundled artifact is suspiciously small ({} bytes)",
            BUNDLED_WABBIT_INITRD.len()
        );
        assert_eq!(
            &BUNDLED_WABBIT_INITRD[..4],
            b"\x7fELF",
            "the bundled artifact is not an ELF binary"
        );
    }

    /// The build script really did bundle the client: a smaller, but
    /// real, ELF — the one the installer writes to the box's
    /// `/usr/local/bin`.
    #[test]
    fn the_client_bundle_is_a_real_artifact() {
        assert!(
            BUNDLED_WABBIT_IPC.len() > 100_000,
            "the bundled client is suspiciously small ({} bytes)",
            BUNDLED_WABBIT_IPC.len()
        );
        assert_eq!(
            &BUNDLED_WABBIT_IPC[..4],
            b"\x7fELF",
            "the bundled client is not an ELF binary"
        );
    }

    /// The client lands in the root filesystem's local bin folder, in
    /// the PATH of every target distro.
    #[test]
    fn the_client_lands_in_the_local_bin() {
        let client = client_binary();
        assert!(client.starts_with("/usr/local/bin/"), "{client}");
        assert!(client.ends_with("-ipc"), "{client}");
    }

    /// The build script really emitted a timestamp: a positive integer
    /// in the plausible past (2023 or later), not a placeholder.
    #[test]
    fn the_build_stamp_is_a_plausible_timestamp() {
        let stamp = build_time();
        assert!(stamp >= 1_700_000_000, "the stamp {stamp} predates 2023");
    }

    /// A stamped file really carries the build time as its mtime — the
    /// whole point of the convention, proven against the real syscall.
    #[test]
    fn a_stamped_file_carries_the_build_time() {
        let path =
            std::env::temp_dir().join(format!("wabbit-install-stamp-{}", std::process::id()));
        fs::write(&path, b"contents").expect("writing the test file");
        stamp_one(path.to_str().expect("the temp dir is UTF-8"), build_time())
            .expect("stamping the test file");
        let modified = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .expect("reading the test file's mtime back");
        let seconds = modified
            .duration_since(std::time::UNIX_EPOCH)
            .expect("mtime is after the epoch")
            .as_secs() as i64;
        assert_eq!(seconds, build_time());
        let _ = fs::remove_file(&path);
    }

    /// The census covers the files the installer actually writes: the
    /// binary and the client always; the policy only with `--policy`;
    /// the hooks per flavor; the switch-wait hook only with the wait on.
    #[test]
    fn the_census_matches_the_install_flow() {
        let options = Options {
            artifact: None,
            client: None,
            policy: None,
            ipc_socket: None,
            flavor: Some(Flavor::InitramfsTools),
            switch_wait: true,
            do_lsm: false,
            remove: false,
            dry_run: true,
        };
        let initramfs_tools = installed_paths(&options, Flavor::InitramfsTools);
        assert!(initramfs_tools.contains(&system_binary()));
        assert!(initramfs_tools.contains(&client_binary()));
        assert!(!initramfs_tools.contains(&system_policy()), "no --policy");
        assert_eq!(
            initramfs_tools
                .iter()
                .filter(|path| path.contains("initramfs-tools"))
                .count(),
            3,
            "hooks + premount + init-bottom with the wait on: {initramfs_tools:?}"
        );

        let dracut = installed_paths(&options, Flavor::Dracut);
        assert_eq!(
            dracut.iter().filter(|path| path.contains("90")).count(),
            3,
            "launch + switch-wait + module-setup: {dracut:?}"
        );
    }
}
