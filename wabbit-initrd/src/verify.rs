//! Verifying bnuuy's protections from outside wabbit-initrd's own PID.
//!
//! The startup sequence (`architecture/startup.mermaid`) requires the initrd
//! to test its own protections while the world is still frozen:
//!
//! * `test write perms of /l/m` → `EPERM`;
//! * `test loading a dummy module` → denied, no module loaded;
//! * `verify by spawning another process and doing a bpf syscall` → denied.
//!
//! Every denial test runs in a spawned worker process. The initrd PID is in
//! `TRUSTED_BPF_PIDS`, so its own syscalls prove nothing; a worker runs
//! outside that initial PID and therefore hits the deny path. The worker
//! re-executes this binary with a `--wabbit-verify-*` flag, performs exactly
//! one syscall, and encodes its verdict in the exit code:
//!
//! | exit | meaning |
//! | --- | --- |
//! | 0 | the syscall was denied as designed |
//! | 1 | the syscall went through: the protection is broken |
//! | 2 | denied with the wrong errno: the LSM hook did not fire |
//! | 3 | the worker could not set the test up |
//! | 4 | inconclusive (missing capability) |
//!
//! The workers are spawned while the world is frozen, so the only forks the
//! `sched_process_fork` tracepoint can observe are the workers' own, and no
//! one else can load a module between the `module_load` tracepoint attaching
//! and the module test running.

use std::{
    env, fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use aya::{
    Ebpf,
    maps::{HashMap, MapData, MapError},
};
use log::{debug, info};
use rustix::{
    fs::{Mode, OFlags},
    io::Errno,
};

const WORKER_BPF: &str = "--wabbit-verify-bpf";
const WORKER_KMOD: &str = "--wabbit-verify-kmod";
const WORKER_MODULES_WRITE: &str = "--wabbit-verify-modules-write";

/// Exit codes shared by the workers and their spawner.
mod verdict {
    pub const BLOCKED: i32 = 0;
    pub const ALLOWED: i32 = 1;
    pub const WRONG_ERRNO: i32 = 2;
    pub const SETUP_FAILED: i32 = 3;
    pub const INCONCLUSIVE: i32 = 4;
}

/// The first `bpf(2)` command. The value is part of the ABI; it is not
/// spelled by `libc`, so it is declared here.
const BPF_MAP_CREATE: libc::c_long = 0;

/// `BPF_MAP_TYPE_HASH`, the second member of the `bpf_map_type` enum (the
/// first is `BPF_MAP_TYPE_UNSPEC`, which the kernel rejects with `EINVAL`).
/// Not spelled by `libc` either.
const BPF_MAP_TYPE_HASH: u32 = 1;

/// The size the kernel accepts for `union bpf_attr` (larger sizes are
/// allowed when the tail is zero, which it is here).
const BPF_ATTR_SIZE: usize = 128;

/// Capability bit 16: loading kernel modules.
const CAP_SYS_MODULE: u32 = 16;

/// Scratch space for test files. The initrd root is writable, but `/tmp`
/// may not exist yet.
const SCRATCH_DIR: &str = "/tmp/wabbit-verify";

/// Dispatch a verification worker — or the freeze watchdog — if the command
/// line asks for one.
///
/// `Some(exit_code)` means this process is a worker and has already produced
/// its verdict; the caller must exit with it before doing anything else.
/// `None` means this is the real initrd process.
pub fn worker_main() -> Option<i32> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some(crate::freeze::WATCHDOG_ARG) => match args.next() {
            Some(raw) => match crate::freeze::watchdog_main(&raw) {
                Ok(()) => Some(0),
                Err(error) => {
                    eprintln!("wabbit watchdog: {error:#}");
                    Some(1)
                }
            },
            None => {
                eprintln!("usage: {} <pipe-fd>", crate::freeze::WATCHDOG_ARG);
                Some(verdict::SETUP_FAILED)
            }
        },
        Some(WORKER_BPF) => Some(worker_verify_bpf()),
        Some(WORKER_KMOD) => match args.next() {
            Some(path) => Some(worker_verify_kmod(Path::new(&path))),
            None => {
                eprintln!("usage: {WORKER_KMOD} <path-to-dummy-module>");
                Some(verdict::SETUP_FAILED)
            }
        },
        Some(WORKER_MODULES_WRITE) => match args.next() {
            Some(path) => Some(worker_verify_modules_write(Path::new(&path))),
            None => {
                eprintln!("usage: {WORKER_MODULES_WRITE} <path-under-module-tree>");
                Some(verdict::SETUP_FAILED)
            }
        },
        _ => None,
    }
}

/// `bpf()` must be denied for PIDs outside `TRUSTED_BPF_PIDS`.
fn worker_verify_bpf() -> i32 {
    // An all-zero BPF_MAP_CREATE is invalid: if the LSM lets the call
    // through, the kernel itself rejects it with EINVAL. EPERM is therefore
    // proof that the bnuuy `bpf` hook denied us, not the argument checking.
    let mut attr = [0u8; BPF_ATTR_SIZE];
    let ret =
        unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_CREATE, attr.as_mut_ptr(), attr.len()) };
    if ret >= 0 {
        eprintln!("bpf() succeeded for a PID outside TRUSTED_BPF_PIDS");
        return verdict::ALLOWED;
    }
    match last_errno() {
        libc::EPERM => verdict::BLOCKED,
        other => {
            eprintln!("bpf() failed with errno {other}, not EPERM: the bpf LSM hook did not fire");
            verdict::WRONG_ERRNO
        }
    }
}

/// `finit_module(2)` of an out-of-tree image must be denied with EPERM.
///
/// The image is deliberately not an ELF module. If the LSM hook does not
/// fire, the loader reads the garbage itself and fails with ENOEXEC, which
/// is a distinguishable, damning verdict.
fn worker_verify_kmod(path: &Path) -> i32 {
    // Without CAP_SYS_MODULE the call would be denied by the capability
    // check before the LSM ever runs, making an EPERM verdict meaningless.
    if !has_capability(CAP_SYS_MODULE) {
        eprintln!("missing CAP_SYS_MODULE: an EPERM here would not prove LSM enforcement");
        return verdict::INCONCLUSIVE;
    }
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("opening {path:?} failed: {error}");
            return verdict::SETUP_FAILED;
        }
    };
    let params = std::ffi::CString::new("").expect("empty params are valid");
    let ret =
        unsafe { libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0) };
    if ret >= 0 {
        eprintln!("finit_module() loaded a module: the kernel_read_file hook did not deny us");
        return verdict::ALLOWED;
    }
    match last_errno() {
        libc::EPERM => verdict::BLOCKED,
        libc::ENOEXEC => {
            eprintln!(
                "finit_module() reached the module loader (ENOEXEC): the kernel_read_file hook did not fire"
            );
            verdict::WRONG_ERRNO
        }
        other => {
            eprintln!("finit_module() failed with errno {other}: expected EPERM from bnuuy");
            verdict::WRONG_ERRNO
        }
    }
}

/// A writable open under the module trees must be denied with EPERM.
fn worker_verify_modules_write(path: &Path) -> i32 {
    match rustix::fs::open(
        path,
        OFlags::WRONLY | OFlags::CREATE,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(_file) => {
            eprintln!("writable open under a module tree succeeded: {path:?}");
            verdict::ALLOWED
        }
        Err(Errno::PERM) => verdict::BLOCKED,
        Err(error) => {
            eprintln!("open failed with {error}: expected EPERM from bnuuy");
            verdict::WRONG_ERRNO
        }
    }
}

/// Parse `CapEff` out of `/proc/self/status` and test one capability bit.
fn has_capability(cap: u32) -> bool {
    parse_cap_eff(&fs::read_to_string("/proc/self/status").unwrap_or_default())
        .is_some_and(|caps| caps & (1u128 << cap) != 0)
}

/// Extract the `CapEff:` line of a `/proc/self/status` body as a bitmask.
fn parse_cap_eff(status: &str) -> Option<u128> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u128::from_str_radix(hex.trim(), 16).ok())
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Run every denial test against the loaded protections.
///
/// `tracepoints_attached` records whether the fork watcher and the module
/// logger could be attached (tracefs availability); their assertions are
/// skipped when it is false, while the LSM tests always run.
pub fn verify_protections(
    ebpf: &mut Ebpf,
    tracepoints_attached: bool,
    module_load_gate_attached: bool,
) -> Result<()> {
    info!("verifying bnuuy protections from spawned workers");
    trusted_bpf_syscall_works()?;

    let mut fork_events: HashMap<MapData, u32, u8> = ebpf
        .take_map("FORK_EVENTS")
        .context("finding FORK_EVENTS map")?
        .try_into()
        .context("opening FORK_EVENTS map")?;
    let module_loads: HashMap<MapData, u32, u8> = ebpf
        .take_map("MODULE_LOADS")
        .context("finding MODULE_LOADS map")?
        .try_into()
        .context("opening MODULE_LOADS map")?;

    let scratch = scratch_dir()?;

    // The diagram: "test loading a dummy module" → "errno 0 but no action
    // taken". An EPERM from the LSM is the "no action taken": the module
    // loader never saw a byte of the image.
    //
    // Skipped whole on kernels whose `sleepable_lsm_hooks` set does not
    // admit `kernel_read_file` (5.14, 5.15): the gate cannot exist there,
    // so its denial has nothing to come from, and running the worker would
    // only "prove" a protection the kernel never offered.
    if module_load_gate_attached {
        let dummy_module = scratch.join("wabbit-dummy.ko");
        fs::write(
            &dummy_module,
            "wabbit verification: this is not an ELF module\n",
        )
        .with_context(|| format!("writing {}", dummy_module.display()))?;
        let (pid, code) = run_worker(WORKER_KMOD, Some(&dummy_module))?;
        check_verdict(code, "finit_module() of an out-of-tree image is denied")?;
        if tracepoints_attached {
            verify_fork_event(&mut fork_events, pid)
                .with_context(|| format!("kmod worker fork (pid {pid})"))?;
        } else {
            debug!("fork watcher not attached; skipping fork verification");
        }
    } else {
        let note = "module-load gate not sleepable on this kernel; \
                    skipping the kmod denial test (the module-tree write \
                    gate and the bpf gate remain under test)";
        debug!("{note}");
        crate::sign::phase(note);
    }

    // The diagram: "verify by spawning another process and doing a bpf
    // syscall" → "not allowed!".
    let (pid, code) = run_worker(WORKER_BPF, None)?;
    check_verdict(code, "bpf() from a PID outside TRUSTED_BPF_PIDS is denied")?;
    if tracepoints_attached {
        verify_fork_event(&mut fork_events, pid)
            .with_context(|| format!("bpf worker fork (pid {pid})"))?;
    }

    // The diagram: "test write perms of /l/m" → "EPERM". Only meaningful
    // when the initrd carries a module tree to protect.
    if Path::new("/lib/modules").is_dir() {
        let target = Path::new("/lib/modules/wabbit-verify-write");
        let (pid, code) = run_worker(WORKER_MODULES_WRITE, Some(target))?;
        // The file_open hook records what it decided and why in its trace
        // map; a failed writable-open test is undecipherable without it
        // (was the hook called? was f_mode read? did d_path resolve?), so
        // it goes into the log and the sign before the verdict is checked.
        let trace = file_open_trace(ebpf)?;
        info!("file_open trace: {trace:?}");
        crate::sign::phase(&format!("file_open trace: {trace:?}"));
        check_verdict(code, "writable open under /lib/modules is denied")?;
        if tracepoints_attached {
            verify_fork_event(&mut fork_events, pid)
                .with_context(|| format!("modules-write worker fork (pid {pid})"))?;
        }
        let _ = fs::remove_file(target);
    } else {
        debug!("/lib/modules does not exist; skipping the modules write test");
    }

    // Nothing may have loaded a module: the world is frozen, the only tasks
    // running are ours, and they were all denied.
    if tracepoints_attached {
        let loaders: Vec<Result<u32, MapError>> = module_loads.keys().collect();
        let loaders = loaders
            .into_iter()
            .collect::<Result<Vec<u32>, MapError>>()
            .context("reading MODULE_LOADS")?;
        if !loaders.is_empty() {
            bail!("modules were loaded during verification by PIDs {loaders:?}");
        }
    }

    let _ = fs::remove_file(scratch.join("wabbit-dummy.ko"));
    let _ = fs::remove_dir(&scratch);
    info!("bnuuy protections verified");
    Ok(())
}

/// Positive control: the initrd PID is trusted, so a valid `BPF_MAP_CREATE`
/// must go through. Without this, a hook that denies everyone would make the
/// workers' EPERM verdicts meaningless.
fn trusted_bpf_syscall_works() -> Result<()> {
    let mut attr = [0u8; BPF_ATTR_SIZE];
    // BPF_MAP_TYPE_HASH — the enum's second member, after UNSPEC=0 — with
    // key_size = 4, value_size = 4, max_entries = 1.
    attr[0..4].copy_from_slice(&BPF_MAP_TYPE_HASH.to_ne_bytes());
    attr[4..8].copy_from_slice(&4u32.to_ne_bytes());
    attr[8..12].copy_from_slice(&4u32.to_ne_bytes());
    attr[12..16].copy_from_slice(&1u32.to_ne_bytes());
    let ret = unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_CREATE, attr.as_ptr(), attr.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error())
            .context("bpf() denied for the trusted initrd PID: the bpf hook is denying everyone");
    }
    drop(unsafe { OwnedFd::from_raw_fd(ret as i32) });
    debug!("positive control: trusted bpf() call succeeded");
    Ok(())
}

/// Spawn a worker outside this PID and wait for its verdict.
///
/// Returns the worker's PID (for the fork watcher) and its exit code.
fn run_worker(flag: &str, extra: Option<&Path>) -> Result<(u32, i32)> {
    let executable = env::current_exe().context("resolving the current executable")?;
    let mut command = Command::new(executable);
    command.arg(flag);
    if let Some(path) = extra {
        command.arg(path);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning verification worker {flag}"))?;
    let pid = child.id();
    let status = child
        .wait()
        .with_context(|| format!("waiting for worker {flag}"))?;
    let code = match status.code() {
        Some(code) => code,
        None => bail!("worker {flag} terminated by signal: {status}"),
    };
    Ok((pid, code))
}

/// Assert that the fork watcher recorded `pid` from the kernel side, then
/// clean the entry so later rounds see a fresh map.
fn verify_fork_event(fork_events: &mut HashMap<MapData, u32, u8>, pid: u32) -> Result<()> {
    match fork_events.get(&pid, 0) {
        Ok(_) => {
            debug!("fork watcher recorded pid {pid}");
            fork_events.remove(&pid).context("cleaning FORK_EVENTS")?;
            Ok(())
        }
        Err(MapError::KeyNotFound) => {
            // Without knowing what the map *does* hold, a miss is
            // ambiguous: an empty map means the tracepoint is not running
            // at all; a map full of other pids means it runs but reads the
            // wrong field.
            let mut seen: Vec<u32> = Vec::new();
            for key in fork_events.keys() {
                match key {
                    Ok(key) if seen.len() < 16 => seen.push(key),
                    Ok(_) => break,
                    Err(error) => {
                        debug!("skipping a FORK_EVENTS key: {error:#}");
                        break;
                    }
                }
            }
            bail!(
                "the fork watcher did not record the worker's fork (pid {pid}): \
                 the sched_process_fork tracepoint is not seeing forks; \
                 the map holds {seen:?}"
            );
        }
        Err(error) => Err(error).context("reading FORK_EVENTS"),
    }
}

/// Read the eBPF-side trace of what `file_open` decided and why, as
/// `(code, count)` pairs; the codes are documented on bnuuy's
/// `FILE_OPEN_TRACE` map.
fn file_open_trace(ebpf: &mut Ebpf) -> Result<Vec<(u32, u32)>> {
    let trace: HashMap<MapData, u32, u32> = ebpf
        .take_map("FILE_OPEN_TRACE")
        .context("finding FILE_OPEN_TRACE map")?
        .try_into()
        .context("opening FILE_OPEN_TRACE map")?;
    trace
        .iter()
        .collect::<Result<Vec<(u32, u32)>, _>>()
        .context("reading FILE_OPEN_TRACE")
}

fn check_verdict(code: i32, what: &str) -> Result<()> {
    match code {
        verdict::BLOCKED => Ok(()),
        verdict::ALLOWED => bail!("{what}: FAILED, the syscall went through"),
        verdict::WRONG_ERRNO => bail!("{what}: FAILED, the LSM hook did not fire"),
        verdict::SETUP_FAILED => bail!("{what}: the worker could not set the test up"),
        verdict::INCONCLUSIVE => bail!("{what}: inconclusive (missing capability)"),
        other => bail!("{what}: unexpected worker exit code {other}"),
    }
}

fn scratch_dir() -> Result<PathBuf> {
    let dir = PathBuf::from(SCRATCH_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_eff_parses() {
        let status = "Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nGid:\t0\n";
        let caps = parse_cap_eff(status).expect("CapEff line present");
        assert!(caps & (1u128 << CAP_SYS_MODULE) != 0);
        assert!(caps & (1u128 << 12) != 0);
    }

    #[test]
    fn cap_eff_absent_is_none() {
        assert_eq!(parse_cap_eff("Uid:\t0\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tnot hex\n"), None);
        assert_eq!(parse_cap_eff(""), None);
    }

    #[test]
    fn capability_bits() {
        assert_eq!(
            parse_cap_eff("CapEff:\t0000000000010000\n")
                .is_some_and(|caps| caps & (1u128 << CAP_SYS_MODULE) != 0),
            true
        );
        assert!(
            !parse_cap_eff("CapEff:\t0000000000000000\n")
                .is_some_and(|caps| caps & (1u128 << CAP_SYS_MODULE) != 0)
        );
    }
}
