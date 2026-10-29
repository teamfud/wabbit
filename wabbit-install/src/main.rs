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
//! Until the switch-root handoff protocol lands (see AGENTS.md), the
//! default pre-switch wait holds the boot at the initrd until wabbit
//! exits; `--no-switch-wait` omits that hook. Takes effect on the next
//! boot; the initramfs and any kernel command line change activate
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

/// The stable system path for the artifact; both flavors reference it so
/// initramfs rebuilds do not need the repository.
const SYSTEM_BINARY: &str = "/usr/lib/wabbit/wabbit-initrd";

/// The wabbit-initrd artifact, compiled into this installer by its build
/// script (static musl, complete with its embedded bnuuy object and
/// wabbit blob) — the installer carries its artifact and needs no
/// checkout.
const BUNDLED_WABBIT_INITRD: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/wabbit-initrd-blob"));

/// Where the artifact to install comes from.
enum Artifact {
    /// The binary embedded at build time.
    Bundled,
    /// An explicit `--artifact` override.
    Path(PathBuf),
}

// ------------------------------------------------------------------ the hooks

/// The launch hook: the documented `/init` recipe, run from the flavor's
/// launch slot. POSIX sh — initramfs hooks run under busybox too.
const LAUNCH_HOOK: &str = r#"#!/bin/sh
# wabbit: launch the initrd protector (see AGENTS.md, "Initrd integration").
# This slot runs after /proc, /sys, and /dev are mounted, before any root
# mounting. setsid keeps job-control signals away from the protector and
# everything it spawns; the console never blocks when the world freezes
# (a pipe-backed stderr would). RUST_LOG matters: env_logger defaults to
# error-only.
RUST_LOG=info setsid /wabbit-initrd </dev/null >/dev/console 2>&1 &
wabbit_initrd_pid=$!
pidfile=/run/wabbit-initrd.pid
if ! echo "$wabbit_initrd_pid" >"$pidfile" 2>/dev/null; then
    pidfile=/dev/.wabbit-initrd.pid
    echo "$wabbit_initrd_pid" >"$pidfile"
fi

# Cooperation: the kernel discards SIGSTOP for PID 1, so a busybox /init
# (or systemd) cannot be frozen. This hook runs synchronously from the
# init flow, so waiting here means nothing proceeds until bnuuy's first
# pin exists. The freeze may stop this very wait; wabbit-initrd resumes
# it when the world thaws.
while [ ! -e /sys/fs/bpf/boot/bpf ]; do sleep 0.1; done
"#;

/// The pre-switch wait: after the real root is mounted and settled, the
/// rest belongs to wabbit-initrd. Do not race it to switch_root.
const SWITCH_WAIT_HOOK: &str = r#"#!/bin/sh
# wabbit: hold until wabbit-initrd exits (see AGENTS.md). It owns the
# handoff choreography; the boot must not race it to switch_root.
# NOTE: until the switch-root handoff protocol exists, wabbit runs
# indefinitely, so a full deployment holds here until it exits — this is
# the documented choreography, not a defect. Reinstall with
# --no-switch-wait to omit this hook.
for pidfile in /run/wabbit-initrd.pid /dev/.wabbit-initrd.pid; do
    if [ -f "$pidfile" ]; then
        wabbit_initrd_pid=$(cat "$pidfile")
        while kill -0 "$wabbit_initrd_pid" 2>/dev/null; do sleep 0.5; done
    fi
done
"#;

/// The initramfs-tools build hook: carries the binary into the image at
/// mkinitramfs time, with `$DESTDIR` as the staging tree.
const INITRAMFS_TOOLS_BUILD_HOOK: &str = r#"#!/bin/sh
# wabbit: carry wabbit-initrd into the image (see AGENTS.md).
# This is an initramfs-tools build hook: $DESTDIR is the staging tree.
set -e
if [ -z "${DESTDIR:-}" ]; then
    echo "wabbit hook: DESTDIR is not set — run me via mkinitramfs" >&2
    exit 1
fi
mkdir -p "$DESTDIR"
if command -v copy_exec >/dev/null 2>&1; then
    copy_exec /usr/lib/wabbit/wabbit-initrd /wabbit-initrd
else
    cp /usr/lib/wabbit/wabbit-initrd "$DESTDIR/wabbit-initrd"
    chmod 0755 "$DESTDIR/wabbit-initrd"
fi
"#;

/// The dracut module: installs the binary and the hook scripts into the
/// image when the image is generated. `$initdir` is the image staging
/// tree, `$moddir` the module's directory, `$hookdir` the in-image hook
/// root. Hook scripts are sourced into the init shell by busybox-style
/// inits and run as dracut-pre-mount / dracut-pre-pivot services in
/// systemd initrds — the same slots, either way.
const DRACUT_MODULE_SETUP: &str = r#"#!/bin/sh
# dracut module: wabbit-initrd (see AGENTS.md, "Initrd integration").
check() { return 0; }
depends() { return 0; }

install() {
    # The binary at a stable system path; inside the image it is
    # /wabbit-initrd, at the initramfs root.
    inst_binary /usr/lib/wabbit/wabbit-initrd /wabbit-initrd

    # The hooks. $hookdir is dracut's in-image hook root (usr/lib on
    # merged-/usr systems); they run in lexical order within each dir.
    hooks="$initdir${hookdir:-/usr/lib/dracut/hooks}"
    mkdir -p "$hooks/pre-mount" "$hooks/pre-pivot"
    install -m 0755 "$moddir/launch.sh" "$hooks/pre-mount/01-wabbit.sh"
    if [ -e "$moddir/switch-wait.sh" ]; then
        install -m 0755 "$moddir/switch-wait.sh" "$hooks/pre-pivot/99-wabbit.sh"
    fi
}
"#;

/// The grub drop-in: a LATER numbered file wins over a cloud image's
/// `50-cloudimg-settings.cfg` without having to know what it says.
const GRUB_LSM_DROP_IN: &str = r#"# wabbit: enroll the BPF LSM — no bnuuy hook can attach without it.
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=bpf"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX lsm=bpf"
"#;

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
    flavor: Option<Flavor>,
    switch_wait: bool,
    do_lsm: bool,
    remove: bool,
    dry_run: bool,
}

fn die(message: &str) -> ! {
    eprintln!("wabbit-install: {message}");
    std::process::exit(1);
}

fn usage(code: i32) -> ! {
    print!(
        "\
usage: wabbit-install [options]
  --artifact PATH   install this wabbit-initrd binary instead of the one
                    bundled at build time
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
    if flavor == Flavor::InitramfsTools {
        remove_file(options.dry_run, "/etc/initramfs-tools/hooks/wabbit");
        remove_file(
            options.dry_run,
            "/etc/initramfs-tools/scripts/init-premount/wabbit",
        );
        remove_file(
            options.dry_run,
            "/etc/initramfs-tools/scripts/init-bottom/wabbit",
        );
        run(options.dry_run, "update-initramfs", &["-u", "-k", "all"]);
    } else {
        let module = "/usr/lib/dracut/modules.d/90wabbit";
        remove_file(options.dry_run, &format!("{module}/module-setup.sh"));
        remove_file(options.dry_run, &format!("{module}/launch.sh"));
        remove_file(options.dry_run, &format!("{module}/switch-wait.sh"));
        remove_dir_if_empty(options.dry_run, module);
        run(options.dry_run, "dracut", &["--force"]);
    }
    remove_file(options.dry_run, SYSTEM_BINARY);
    remove_dir_if_empty(options.dry_run, "/usr/lib/wabbit");
    // The lsm=bpf addition is deliberately left in place: it is additive
    // (it only enrolls one more LSM) and other tooling may rely on it.
    println!("removed. any lsm=bpf added to the kernel command line was left alone.");
    std::process::exit(0);
}

fn install(options: &Options, flavor: Flavor) {
    let artifact = find_artifact(options);
    let artifact_name = match &artifact {
        Artifact::Bundled => "<bundled wabbit-initrd>".to_string(),
        Artifact::Path(path) => path.display().to_string(),
    };

    println!("flavor: {}", flavor.as_str());
    println!("+ install -m 0755 {artifact_name} {SYSTEM_BINARY}");
    if !options.dry_run {
        if let Some(parent) = Path::new(SYSTEM_BINARY).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let write = match &artifact {
            Artifact::Bundled => fs::write(SYSTEM_BINARY, BUNDLED_WABBIT_INITRD),
            Artifact::Path(path) => fs::copy(path, SYSTEM_BINARY).map(|_| ()),
        };
        if let Err(error) = write {
            die(&format!(
                "installing the artifact to {SYSTEM_BINARY}: {error}"
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(SYSTEM_BINARY, std::fs::Permissions::from_mode(0o755));
    }

    match flavor {
        Flavor::InitramfsTools => {
            write_file(
                options.dry_run,
                0o755,
                "/etc/initramfs-tools/hooks/wabbit",
                INITRAMFS_TOOLS_BUILD_HOOK,
            );
            write_file(
                options.dry_run,
                0o755,
                "/etc/initramfs-tools/scripts/init-premount/wabbit",
                LAUNCH_HOOK,
            );
            if options.switch_wait {
                write_file(
                    options.dry_run,
                    0o755,
                    "/etc/initramfs-tools/scripts/init-bottom/wabbit",
                    SWITCH_WAIT_HOOK,
                );
            }
            run(options.dry_run, "update-initramfs", &["-u", "-k", "all"]);
        }
        Flavor::Dracut => {
            let module = "/usr/lib/dracut/modules.d/90wabbit";
            write_file(
                options.dry_run,
                0o755,
                &format!("{module}/launch.sh"),
                LAUNCH_HOOK,
            );
            if options.switch_wait {
                write_file(
                    options.dry_run,
                    0o755,
                    &format!("{module}/switch-wait.sh"),
                    SWITCH_WAIT_HOOK,
                );
            }
            write_file(
                options.dry_run,
                0o755,
                &format!("{module}/module-setup.sh"),
                DRACUT_MODULE_SETUP,
            );
            run(options.dry_run, "dracut", &["--force", "--add", "wabbit"]);
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

    let switch_summary = if options.switch_wait {
        "waits for wabbit-initrd to exit (see the handoff note in --help)"
    } else {
        "NOT INSTALLED (--no-switch-wait)"
    };
    print!(
        "
installed via {flavor}:
  binary:        /wabbit-initrd in the image (installed from {artifact_name})
  launch:        after /proc, /sys, /dev are mounted, before root mounting;
                 holds the init flow until bnuuy's /sys/fs/bpf/boot/bpf pin
  before
  switch_root:   {switch_summary}

takes effect on the next boot. any wabbit-initrd failure leaves the bnuuy
sign at /run/bnuuy.bin explaining why — the boot itself continues
unprotected rather than not at all.
"
    );
}

/// Best-effort confirmation that the rebuilt image actually carries the
/// wiring; a warning, not a failure.
fn verify_image(flavor: Flavor) {
    let carrying = |listing: String| {
        listing
            .lines()
            .filter(|line| line.contains("wabbit"))
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
        _ => eprintln!("warning: could not confirm wabbit inside the image (lsinitrd/lsinitramfs)"),
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
fn enroll_bpf_lsm(options: &Options) {
    if let Ok(active) = fs::read_to_string("/sys/kernel/security/lsm")
        && active.split(',').any(|lsm| lsm.trim() == "bpf")
    {
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
            "/etc/default/grub.d/99-wabbit-lsm.cfg",
            GRUB_LSM_DROP_IN,
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
        assert!(
            LAUNCH_HOOK
                .contains("RUST_LOG=info setsid /wabbit-initrd </dev/null >/dev/console 2>&1 &")
        );
        assert!(LAUNCH_HOOK.contains("/sys/fs/bpf/boot/bpf"));
    }

    #[test]
    fn the_switch_wait_holds_on_wabbit_initrd() {
        assert!(SWITCH_WAIT_HOOK.contains("kill -0 \"$wabbit_initrd_pid\""));
    }

    #[test]
    fn the_dracut_module_uses_dracut_hook_dirs() {
        assert!(DRACUT_MODULE_SETUP.contains("hooks/pre-mount"));
        assert!(DRACUT_MODULE_SETUP.contains("hooks/pre-pivot"));
    }

    #[test]
    fn the_grub_drop_in_enrolls_the_bpf_lsm() {
        assert!(GRUB_LSM_DROP_IN.contains("lsm=bpf"));
    }

    /// The build script really did bundle an artifact: a non-empty ELF.
    #[test]
    fn the_bundle_is_a_real_artifact() {
        assert!(
            BUNDLED_WABBIT_INITRD.len() > 1_000_000,
            "the bundled wabbit-initrd is suspiciously small ({} bytes)",
            BUNDLED_WABBIT_INITRD.len()
        );
        assert_eq!(
            &BUNDLED_WABBIT_INITRD[..4],
            b"\x7fELF",
            "the bundled wabbit-initrd is not an ELF binary"
        );
    }
}
