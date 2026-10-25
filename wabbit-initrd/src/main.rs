use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::HashMap,
    programs::{Lsm, TracePoint},
};
use log::{debug, info, warn};
use rustix::{
    io::Errno,
    mount::{MountFlags, mount},
    process::getpid,
};

mod freeze;
mod inject;
mod launch;
mod runtime;
mod sign;
mod sysroot;
mod verify;

const BPFFS_ROOT: &str = "/sys/fs/bpf";
/// bpffs's magic, from the kernel UAPI (`include/uapi/linux/magic.h`).
const BPFFS_MAGIC: i64 = 0xcafe4a11;
const BNUUY_PIN_ROOT: &str = "/sys/fs/bpf/boot";
/// Each bnuuy LSM hook, the program variants that can serve it, and whether
/// the hook is required. Variants are tried in order: the file-based hooks
/// exist in two `struct file` layouts — the struct was reordered
/// mid-series, moving `f_path` from offset 16 to 152 — and the verifier
/// validates `bpf_d_path`'s argument against the running kernel's BTF, so
/// the variant with the wrong layout fails to load loudly and the kernel
/// itself picks the right one.
///
/// The required hooks are the core gates — `bpf(2)`, module loading, the
/// module-tree write gate: if one cannot load, `wabbit-initrd` fails
/// loudly rather than boot with a hole in its core protections. One
/// exception is a kernel property, not a load failure: when the running
/// kernel's `sleepable_lsm_hooks` set does not admit the hook, no
/// sleepable program — and therefore no `bpf_d_path` protection — can
/// exist for it there at all (5.14 and 5.15 lack `kernel_read_file` in
/// the set; 6.1 additionally lacks the `path_*` family). Refusing every
/// boot on those distros protects nothing, so the gate degrades with a
/// warning and a sign record, verification skips what it cannot test,
/// and the remaining core gates stay enforced. Everything else is tree
/// hardening around those gates and degrades the same way.
const BNUUY_HOOKS: &[(&str, &[&str], bool)] = &[
    ("bpf", &["bpf"], true),
    ("file_open", &["file_open_modern", "file_open_legacy"], true),
    (
        "kernel_read_file",
        &["kernel_read_file_modern", "kernel_read_file_legacy"],
        true,
    ),
    ("sb_mount", &["sb_mount"], false),
    ("path_unlink", &["path_unlink"], false),
    ("path_mkdir", &["path_mkdir"], false),
    ("path_rmdir", &["path_rmdir"], false),
    ("path_symlink", &["path_symlink"], false),
    ("path_link", &["path_link"], false),
    ("path_rename", &["path_rename"], false),
];

fn main() {
    // Watchdogs and verification workers re-execute this binary in their own
    // PID and must never freeze the world, mount anything, or initialize
    // anything. They never touch the sign either: a worker's exit code is
    // its verdict, and a watchdog's parent is alive by construction.
    if let Some(code) = verify::worker_main() {
        std::process::exit(code);
    }

    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            // Leave the sign explaining why, then fail open: the init script
            // continues, the world is thawed (the `Drop` backstop or the
            // watchdog), and the boot proceeds unprotected.
            sign::failure(&error);
            eprintln!("wabbit-initrd failed: {error:#}");
            1
        }
    };
    // A clean boot leaves no sign behind.
    if code == 0 {
        sign::remove();
    }
    std::process::exit(code);
}

fn run() -> Result<i32> {
    env_logger::init();
    // Panics go through the sign too: the world's rescue is the `Drop`
    // backstop's job, this is only the forensic trail.
    sign::install_panic_hook();
    sign::init();

    // Fail fast, before anything is frozen or mounted: a failed
    // wabbit-initrd must never take the boot down with it, and the freeze
    // is the one thing that could.
    preflight()?;

    // The freeze fail-safe: a process killed by `SIGKILL` or the OOM killer
    // runs no `Drop` backstop, so the watchdog watches this process's
    // lifetime and thaws the world if it dies frozen.
    let watchdog = freeze::Watchdog::spawn()?;
    let protected = [getpid(), watchdog.pid()];

    let mut world = freeze::stop_the_world(&protected)?;
    sign::phase(&format!(
        "stopped the world: {} processes frozen",
        world.frozen_count()
    ));
    let initialized = initialize_bnuuy();
    // The startup sequence keeps the world frozen until the poll for
    // `/sysroot` has started; resume it before propagating any failure, so
    // a failed bnuuy setup boots the system unprotected rather than not at
    // all. The `Drop` backstop would catch this too; resuming explicitly is
    // the logged, deliberate path.
    world.resume().context("resuming the world")?;
    sign::phase("resumed the world");
    let (mut ebpf, module_gates) = initialized.context("initializing bnuuy")?;
    // The binding's lifetime *is* the enforcement: the gate fds detach —
    // and the denials with them — the moment wabbit-initrd exits.
    let _module_gates = module_gates;
    sign::phase("bnuuy protections attached and verified");

    // The startup sequence: poll for the real root (and its nested
    // filesystems) to be mounted, then stop the world again so the handoff
    // steps cannot race anyone.
    let sysroot = sysroot::wait_for_sysroot()?;
    sign::phase(&format!(
        "the real root is mounted at {}",
        sysroot.mount_point.display()
    ));
    let mut world = freeze::stop_the_world(&protected)?;
    info!(
        "stopped the world again; the real root is at {}",
        sysroot.mount_point.display()
    );
    sign::phase(&format!(
        "stopped the world again: {} processes frozen",
        world.frozen_count()
    ));

    // "mount necessary runtime filesystems (cgroupfs...)" and "create
    // wabbit cgroup": cgroup2 at /sys/fs/cgroup (mounted, or verified when
    // a systemd initrd has already mounted it), with the wabbit cgroup
    // inside. The descriptor keeps the cgroup anchored for as long as this
    // process lives; it exits before switch_root, and only wabbit crosses
    // that line.
    let cgroup = runtime::prepare_runtime()?;
    sign::phase(&format!(
        "the wabbit cgroup is ready at {}",
        cgroup.path.display()
    ));

    // wabbit starts on the frozen world, inside its cgroup, with argv[0][0]
    // set to '@' so the switch-root kill spares it, and the initrd babysits
    // it to keep the `Ebpf` handle — and with it every bnuuy link — alive
    // for exactly as long as wabbit runs. The world stays frozen through
    // that in the startup sequence, but a dead initrd must never leave it
    // that way.
    let launched = launch::launch_embedded_wabbit(&mut ebpf, &cgroup.path);
    world.resume().context("resuming the world")?;
    sign::phase("resumed the world");
    let code = launched?;
    sign::phase(&format!("wabbit exited with code {code}"));
    Ok(code)
}

/// Fail fast on an unusable environment, before the first freeze.
///
/// Every mount this program makes lives under `/sys`, at a mount point the
/// kernel pre-creates inside sysfs. If `/sys` is not the real sysfs yet,
/// those mounts would land on the initramfs ramfs and be buried the moment
/// the init script mounts sysfs over it — so refuse instead.
fn preflight() -> Result<()> {
    let sys = runtime::filesystem_type("/sys").context("inspecting /sys")?;
    if sys != runtime::SYSFS_MAGIC {
        bail!(
            "expected sysfs at /sys (magic {:#x}), found magic {sys:#x}: \
             the init script must mount /sys before wabbit-initrd runs",
            runtime::SYSFS_MAGIC
        );
    }
    Ok(())
}

fn initialize_bnuuy() -> Result<(Ebpf, inject::Gates)> {
    fs::create_dir_all(BPFFS_ROOT).context("creating bpffs root")?;
    match mount("bpf", BPFFS_ROOT, "bpf", MountFlags::empty(), None) {
        Ok(()) | Err(Errno::BUSY) => {}
        Err(error) => return Err(error).context("mounting bpffs"),
    }
    // EBUSY only means *something* is mounted at /sys/fs/bpf. Verify it
    // is bpffs before pinning bnuuy into it, so a foreign mount can never
    // become the store for wabbit's protections.
    let mounted = runtime::filesystem_type(BPFFS_ROOT).context("inspecting /sys/fs/bpf")?;
    if mounted != BPFFS_MAGIC {
        bail!(
            "expected bpffs at {BPFFS_ROOT} (magic {BPFFS_MAGIC:#x}), \
             found magic {mounted:#x}"
        );
    }
    fs::create_dir_all(BNUUY_PIN_ROOT).context("creating bnuuy pin directory")?;

    let btf = Btf::from_sys_fs().context("loading kernel BTF")?;
    let mut ebpf = EbpfLoader::new()
        .btf(Some(&btf))
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/wabbit"
        )))
        .context("loading bnuuy eBPF object")?;

    let pid = std::process::id();
    let mut trusted_pids: HashMap<_, u32, u8> = ebpf
        .map_mut("TRUSTED_BPF_PIDS")
        .context("finding bnuuy trusted PID map")?
        .try_into()
        .context("opening bnuuy trusted PID map")?;
    trusted_pids
        .insert(pid, 1, 0)
        .context("trusting wabbit-initrd PID in bnuuy")?;
    trusted_pids
        .pin(Path::new(BNUUY_PIN_ROOT).join("trusted_bpf_pids"))
        .context("pinning bnuuy trusted PID map")?;

    // Hook by hook, try the candidate programs in order: the first that the
    // running kernel accepts is the one whose layout matches it, so a
    // mismatched candidate is skipped, not a failure. Every candidate is
    // pinned under the hook's name, so what serves each hook stays an
    // implementation detail.
    let mut attached: Vec<String> = Vec::new();
    let mut attached_hooks: Vec<&str> = Vec::new();
    for (hook, candidates, required) in BNUUY_HOOKS {
        let mut loaded = false;
        let mut hook_not_sleepable = false;
        for candidate in *candidates {
            let program: &mut Lsm = ebpf
                .program_mut(candidate)
                .with_context(|| format!("finding bnuuy program {candidate}"))?
                .try_into()
                .with_context(|| format!("opening bnuuy program {candidate}"))?;
            if let Err(error) = program.load(hook, &btf) {
                // The kernel's own verdict when the hook is not in its
                // sleepable set: "bpf_lsm_<hook> is not sleepable". That is
                // a property of the running kernel — no sleepable program,
                // and so no bpf_d_path protection, can exist for the hook
                // there — and it does not depend on the candidate, so one
                // sighting is conclusive.
                if format!("{error}").contains("is not sleepable") {
                    hook_not_sleepable = true;
                }
                // The compact reason is operationally important; the full
                // verifier dump can be kilobytes, which is fine on a console
                // but would flood anything pipe-backed.
                warn!("bnuuy program {candidate} does not fit this kernel: {error}");
                debug!("full verifier output for {candidate}: {error:#}");
                continue;
            }
            program
                .attach()
                .with_context(|| format!("attaching bnuuy LSM hook {hook}"))?;
            program
                .pin(Path::new(BNUUY_PIN_ROOT).join(hook))
                .with_context(|| format!("pinning bnuuy LSM hook {hook}"))?;
            attached.push(format!("{hook}={candidate}"));
            attached_hooks.push(hook);
            loaded = true;
            break;
        }
        if !loaded {
            if hook_not_sleepable {
                // Refusing to boot on every 5.14/5.15 system protects
                // nothing: the protection cannot exist on the kernel, so
                // record the limitation and keep the gates that can.
                warn!(
                    "bnuuy hook {hook} is not in this kernel's sleepable set; \
                       the protection cannot exist on this kernel"
                );
                sign::phase(&format!(
                    "bnuuy hook {hook}: not sleepable on this kernel; \
                     the protection cannot exist here (kernel limitation)"
                ));
                attached.push(format!("{hook}=not-sleepable"));
            } else if *required {
                bail!("no bnuuy program fits this kernel for the {hook} hook");
            } else {
                // Tree hardening around the core gates: degrade with a
                // warning and a sign record rather than leaving the distro
                // with no protections at all.
                warn!("bnuuy hook {hook} does not fit this kernel; continuing without it");
                attached.push(format!("{hook}=unavailable"));
            }
        }
    }
    sign::phase(&format!(
        "bnuuy hooks attached ({}): {}",
        attached.len(),
        attached.join(", ")
    ));
    let lsm_module_gate_attached = attached_hooks.contains(&"kernel_read_file");

    // On kernels whose sleepable set cannot host `kernel_read_file`, the
    // path-aware module-load gate cannot exist — but the syscall wrappers
    // of the whole module-loading family are error-injectable there, so
    // the gate moves to the syscall level: denied at entry for every
    // caller outside the trust map and outside the initrd's module
    // loaders. Kernels that do host the LSM gate keep it instead (it is
    // stronger: it allows in-tree loads by anyone).
    let module_gates = if lsm_module_gate_attached {
        inject::Gates::none()
    } else {
        match inject::arm(&btf, &Path::new(BNUUY_PIN_ROOT).join("trusted_bpf_pids")) {
            Ok(gates) => {
                sign::phase(
                    "module-load gate armed at the syscall level (error injection): \
                     finit_module, init_module, delete_module and kexec_load are denied \
                     to every caller outside the trust map and the initrd's loaders",
                );
                gates
            }
            Err(error) => {
                warn!("syscall-level module gates unavailable: {error:#}");
                sign::phase(&format!(
                    "no module-load gate exists on this kernel: {error:#}"
                ));
                inject::Gates::none()
            }
        }
    };
    let module_load_gate_attached = lsm_module_gate_attached || module_gates.armed();

    // Kernel-side observability: the fork watcher sees every task creation
    // regardless of /proc, and the module logger records every successful
    // module load. Tracefs is not mounted in a bare initrd; without it these
    // degrade to skipped verification assertions, while the LSM protections
    // and their tests are unaffected.
    //
    // The fork watcher's `child_pid` offset is read from the running
    // kernel's own format file rather than assumed: RHEL 9's kernel adds a
    // `common_preempt_lazy_count` field to the trace entry header, pushing
    // every sched_process_fork field up four bytes. A tracepoint program
    // with the wrong offset loads fine and silently records comm bytes as
    // PIDs, so the format file — ground truth — picks the variant.
    let tracepoints_attached = if mount_tracefs() {
        match attach_fork_watcher(&mut ebpf).and_then(|()| {
            attach_tracepoint(&mut ebpf, "module_load_logger", "module", "module_load")
        }) {
            Ok(()) => true,
            Err(error) => {
                warn!("tracepoints unavailable, verification degraded: {error:#}");
                false
            }
        }
    } else {
        warn!("tracefs not mountable: fork and module-load verification skipped");
        false
    };

    // The diagram's "verify by spawning another process and doing a bpf
    // syscall" → "not allowed!", plus the module denial tests. The workers
    // run while the world is frozen: nothing else can fork or load modules
    // meanwhile.
    verify::verify_protections(&mut ebpf, tracepoints_attached, module_load_gate_attached)
        .context("verifying bnuuy protections")?;

    Ok((ebpf, module_gates))
}

/// Attach a tracepoint program by its section-defined category and event.
fn attach_tracepoint(ebpf: &mut Ebpf, name: &str, category: &str, event: &str) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("finding {name} program"))?
        .try_into()
        .with_context(|| format!("opening {name} program"))?;
    program.load().with_context(|| format!("loading {name}"))?;
    program
        .attach(category, event)
        .with_context(|| format!("attaching {name} to {category}/{event}"))?;
    Ok(())
}

/// Attach the `sched_process_fork` watcher, selecting the variant whose
/// `child_pid` offset matches the running kernel's record layout.
///
/// The offset is parsed from the tracepoint's own format file. The two
/// compiled variants cover the layouts seen on the target matrix — 44 for
/// a vanilla trace entry header, 48 for RHEL's, which pads the header with
/// `common_preempt_lazy_count` — and an unrecognized layout falls back to
/// attaching both, leaving junk keys in `FORK_EVENTS` but no blind spot.
/// The map is read by PID for verification, so a key that is really four
/// comm bytes never matches a worker.
/// `child_pid`'s offset within the `sched_process_fork` record, as the
/// running kernel's own format file spells it. The field's line looks like
/// `\tfield:pid_t child_pid;\toffset:48;\tsize:4;\tsigned:1;` — tab-prefixed,
/// with the "print fmt" line naming `child_pid` too, so only `field:` lines
/// match — and the offset is the number before the next semicolon.
fn parse_child_pid_offset(format_file: &str) -> Option<usize> {
    format_file
        .lines()
        .find(|line| line.trim_start().starts_with("field:") && line.contains("child_pid"))
        .and_then(|line| line.split_once("offset:"))
        .and_then(|(_, offset)| offset.split(';').next())
        .and_then(|offset| offset.trim().parse().ok())
}

fn attach_fork_watcher(ebpf: &mut Ebpf) -> Result<()> {
    const FORK_EVENT: &str = "events/sched/sched_process_fork/format";
    let format_file = fs::read_to_string(format!("/sys/kernel/tracing/{FORK_EVENT}"))
        .or_else(|_| fs::read_to_string(format!("/sys/kernel/debug/tracing/{FORK_EVENT}")))
        .context("reading the sched_process_fork format file")?;
    let child_pid_offset = parse_child_pid_offset(&format_file)
        .context("parsing child_pid's offset from the format file")?;
    info!("sched_process_fork child_pid sits at record offset {child_pid_offset}");

    let variants: &[&str] = match child_pid_offset {
        44 => &["fork_watcher_vanilla"],
        48 => &["fork_watcher_preempt_lazy"],
        other => {
            warn!(
                "sched_process_fork child_pid offset {other} matches no compiled \
                 fork watcher variant; attaching both known layouts"
            );
            sign::phase(&format!(
                "fork watcher: child_pid at unrecorded offset {other}; \
                 attaching both known layouts"
            ));
            &["fork_watcher_vanilla", "fork_watcher_preempt_lazy"]
        }
    };
    for variant in variants {
        attach_tracepoint(ebpf, variant, "sched", "sched_process_fork")?;
    }
    Ok(())
}

/// Make tracefs visible so tracepoint programs can attach.
///
/// aya looks for `/sys/kernel/tracing` and `/sys/kernel/debug/tracing`, and
/// a bare initrd usually has neither mounted. The mount points themselves
/// are created by the kernel when tracing/debugfs support is built in, so
/// only the mounts are needed. Returns whether an `events` tree is readable
/// afterwards.
fn mount_tracefs() -> bool {
    let has_events = |path: &str| Path::new(path).join("events").is_dir();
    if has_events("/sys/kernel/tracing") || has_events("/sys/kernel/debug/tracing") {
        return true;
    }

    for target in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let _ = fs::create_dir_all(target);
        match mount("tracefs", target, "tracefs", MountFlags::empty(), None) {
            Ok(()) | Err(Errno::BUSY) => {}
            Err(_) => continue,
        }
        if has_events(target) {
            return true;
        }
    }

    // Older arrangements serve the tracepoints out of debugfs.
    let _ = fs::create_dir_all("/sys/kernel/debug");
    match mount(
        "debugfs",
        "/sys/kernel/debug",
        "debugfs",
        MountFlags::empty(),
        None,
    ) {
        Ok(()) | Err(Errno::BUSY) => {}
        Err(_) => return false,
    }
    let _ = fs::create_dir_all("/sys/kernel/debug/tracing");
    match mount(
        "tracefs",
        "/sys/kernel/debug/tracing",
        "tracefs",
        MountFlags::empty(),
        None,
    ) {
        Ok(()) | Err(Errno::BUSY) => {}
        Err(_) => return false,
    }
    has_events("/sys/kernel/debug/tracing")
}

#[cfg(test)]
mod tests {
    use super::parse_child_pid_offset;

    /// The format file verbatim from Ubuntu 24.04 (kernel 6.8): a vanilla
    /// `trace_entry` header, comm arrays inline, `child_pid` at 44.
    const VANILLA_FORMAT: &str = "\
name: sched_process_fork
ID: 324
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;

print fmt: \"comm=%s pid=%d child_comm=%s child_pid=%d\", \
REC->parent_comm, REC->parent_pid, REC->child_comm, REC->child_pid
";

    /// The format file verbatim from Rocky 9 (kernel 5.14.0-687.el9): RHEL's
    /// lazy-preempt backport pads the header with
    /// `common_preempt_lazy_count`, pushing every later field up 4 bytes.
    const RHEL_LAZY_FORMAT: &str = "\
name: sched_process_fork
ID: 296
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;
\tfield:unsigned char common_preempt_lazy_count;\toffset:8;\tsize:1;\tsigned:0;

\tfield:char parent_comm[TASK_COMM_LEN];\toffset:12;\tsize:16;\tsigned:1;
\tfield:pid_t parent_pid;\toffset:28;\tsize:4;\tsigned:1;
\tfield:char child_comm[TASK_COMM_LEN];\toffset:32;\tsize:16;\tsigned:1;
\tfield:pid_t child_pid;\toffset:48;\tsize:4;\tsigned:1;

print fmt: \"comm=%s pid=%d child_comm=%s child_pid=%d\", \
REC->parent_comm, REC->parent_pid, REC->child_comm, REC->child_pid
";

    #[test]
    fn vanilla_kernel_puts_child_pid_at_44() {
        assert_eq!(parse_child_pid_offset(VANILLA_FORMAT), Some(44));
    }

    #[test]
    fn rhel_lazy_preempt_puts_child_pid_at_48() {
        assert_eq!(parse_child_pid_offset(RHEL_LAZY_FORMAT), Some(48));
    }

    #[test]
    fn a_format_file_without_the_field_parses_to_none() {
        assert_eq!(parse_child_pid_offset("nothing here\n"), None);
    }
}
