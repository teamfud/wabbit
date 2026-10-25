//! Stopping and resuming the world.
//!
//! The startup sequence in `architecture/startup.mermaid` starts with
//! `wabbit-initrd` freezing the rest of the system so that nothing can observe
//! or interfere with the early eBPF protections: "stop the world. freeze all
//! other processes by walking process tree and calling SIGSTOP".
//!
//! [`stop_the_world`] walks the process tree from PID 1 sending `SIGSTOP` to
//! every process but ourselves, then rescans `/proc` until nothing is left
//! running: processes can fork while they are being frozen, and a `SIGSTOP`
//! is only consumed once its victim is next scheduled. Only a frozen world is
//! returned.
//!
//! Two kinds of processes are deliberately left alone:
//!
//! * kernel threads, which have no userspace, cannot be stopped, and are
//!   recognizable by their empty `cmdline`;
//! * zombies, which are dead already.
//!
//! The kernel protects PID 1 from `SIGSTOP` (it discards signals for which
//! init has installed no handler, and no handler can be installed for
//! `SIGSTOP`), so the initrd's init keeps running; it is normally blocked
//! waiting on us, its child. [`FrozenWorld::resume`] thaws exactly the
//! processes that were stopped, so processes that were stopped before the
//! freeze stay stopped.
//!
//! # Seeing deeper than `readdir`
//!
//! A `readdir` pass over `/proc` is the traditional way to enumerate
//! processes, and the least trustworthy one: it is snapshot-based, so
//! processes created mid-scan are invisible until the next scan, and it can
//! be neutered outright by a `hidepid`-mounted `/proc`. The settle loop
//! therefore enumerates three independent sources each round:
//!
//! * `readdir` over `/proc` — the traditional view;
//! * a direct sweep of every PID up to `ns_last_pid` (or `pid_max`),
//!   probing `/proc/<pid>` without trusting any directory listing. This
//!   sees through `hidepid=1`, which hides entries from `readdir` but not
//!   from direct lookups;
//! * `cgroup.procs` files under `/sys/fs/cgroup` — an enumeration path that
//!   never involves `/proc` at all and has no mount option that can hide
//!   processes, so it also covers `hidepid=2`.
//!
//! Deeper mechanisms exist and are deliberately left for later: the netlink
//! process connector (`PROC_CN_MCAST_LISTEN`) can stream fork/exec/exit
//! events to prove nothing moved after the freeze, and an eBPF task iterator
//! (`bpf_iter`) would enumerate from the kernel side with no userspace view
//! involved at all.

use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    io::{self, Read},
    os::fd::{FromRawFd, RawFd},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
use rustix::{
    io::Errno,
    process::{Pid, Signal, getpid, kill_process},
};

/// Where the process table lives.
const PROC: &str = "/proc";

/// Where cgroups live. Their `cgroup.procs` files are an independent view of
/// the process table that no `/proc` mount option can hide.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The kernel's exact "last PID allocated" counter
/// (`CONFIG_CHECKPOINT_RESTORE`), bounding the direct PID sweep.
const NS_LAST_PID: &str = "/proc/sys/kernel/ns_last_pid";

/// The kernel's configured PID upper bound, used when `ns_last_pid` is
/// unavailable.
const PID_MAX: &str = "/proc/sys/kernel/pid_max";

/// Upper bound for the direct PID sweep. `pid_max` can be as large as 2^22 -
/// 1, and probing four million paths would stall the freeze for seconds on a
/// pathological host, so the sweep stops here and says so.
const SWEEP_HARD_CAP: u32 = 1 << 20;

/// The root of the process tree: the initrd's `init`.
const INIT_PID: Pid = Pid::INIT;

/// How many times [`stop_the_world`] rescans `/proc`, waiting for processes to
/// consume their `SIGSTOP` and catching processes that forked during the
/// freeze.
const SETTLE_ATTEMPTS: u32 = 100;

/// How long to wait between settle scans.
const SETTLE_DELAY: Duration = Duration::from_millis(10);

/// Stop the world.
///
/// Freeze every process on the system except ourselves — and except
/// `protected`, the PIDs that must keep running for the freeze to be
/// fail-safe (see [`Watchdog`]) — by walking the process tree from PID 1 and
/// sending `SIGSTOP`, then wait until the freeze has taken hold. A returned
/// [`FrozenWorld`] is really frozen: every other process is either stopped,
/// about to stop as soon as it returns from the kernel, or dead. If the
/// freeze cannot complete, the world is resumed before an error is returned;
/// a half-frozen system must not outlive this function.
pub fn stop_the_world(protected: &[Pid]) -> Result<FrozenWorld> {
    let mut world = FrozenWorld::default();
    if let Err(error) =
        freeze_tree(protected, &mut world).and_then(|()| settle(protected, &mut world))
    {
        // Never leave the system frozen on the way out of an error.
        if let Err(resume_error) = world.resume() {
            warn!("failed to resume the world after a failed freeze: {resume_error}");
        }
        return Err(error.context("stopping the world"));
    }
    info!(
        "stopped the world: {} processes frozen",
        world.stopped.len()
    );
    Ok(world)
}

/// The processes frozen by [`stop_the_world`].
///
/// Resuming is guaranteed on every exit path: an explicit [`resume`](Self::resume)
/// clears the bookkeeping, and anything that forgets — a panic unwinding
/// through the frozen period, an early `?` — hits the [`Drop`] backstop,
/// which resumes whatever the bookkeeping still holds. A frozen system must
/// never outlive a failed `wabbit-initrd`: the boot continues without it.
#[derive(Debug, Default)]
pub struct FrozenWorld {
    /// The PIDs that were sent `SIGSTOP`, and need `SIGCONT` to resume.
    stopped: HashSet<Pid>,
    /// Whether the `SIGSTOP`s have been undone, so [`Drop`] can tell an
    /// abandoned world from an already-resumed one.
    resumed: bool,
}

impl FrozenWorld {
    /// Resume the world: send `SIGCONT` to exactly the processes that were
    /// stopped by [`stop_the_world`].
    ///
    /// Processes that were stopped before the freeze are not resumed: we did
    /// not stop them, so starting them again is not our call.
    pub fn resume(&mut self) -> Result<()> {
        info!("resuming the world: {} processes", self.stopped.len());
        self.resume_stopped()?;
        self.resumed = true;
        Ok(())
    }

    fn resume_stopped(&self) -> Result<()> {
        for pid in &self.stopped {
            debug!("sending SIGCONT to pid {pid}");
            send(*pid, Signal::CONT)?;
        }
        Ok(())
    }

    /// How many processes this world holds, for the sign's records.
    pub fn frozen_count(&self) -> usize {
        self.stopped.len()
    }

    /// Freeze `pid` according to its `class`, recording it for
    /// [`resume`](Self::resume).
    ///
    /// Returns whether `pid` is now frozen, or beyond stopping: a kernel
    /// thread, dead, stopped already, or stopped the moment it next returns
    /// from the kernel. `false` means it is still live and has not consumed
    /// its `SIGSTOP` yet, so the caller has to look at it again.
    fn freeze(&mut self, pid: Pid, class: Class) -> Result<bool> {
        match class {
            Class::KernelThread | Class::Dead | Class::Stopped => Ok(true),
            Class::Uninterruptible => {
                // The SIGSTOP stays pending until the process leaves the
                // kernel; it cannot run userspace code until then.
                self.stop(pid)?;
                Ok(true)
            }
            Class::Live => {
                let sent = self.stop(pid)?;
                if sent && pid.is_init() {
                    warn!("cannot freeze pid 1: the kernel discards SIGSTOP for init");
                }
                // The kernel protects init from SIGSTOP, and waiting for it
                // to consume a signal it never will would hang the freeze
                // forever.
                Ok(pid.is_init())
            }
        }
    }

    /// Send `SIGSTOP` to `pid`, recording it for [`resume`](Self::resume)
    /// only once the signal has actually been sent. Returns whether this
    /// call is the one that sent it.
    fn stop(&mut self, pid: Pid) -> Result<bool> {
        if self.stopped.contains(&pid) {
            return Ok(false);
        }
        debug!("sending SIGSTOP to pid {pid}");
        send(pid, Signal::STOP)?;
        self.stopped.insert(pid);
        Ok(true)
    }
}

impl Drop for FrozenWorld {
    /// The fail-safe: a world that is dropped without having been resumed is
    /// resumed now. This covers every path that abandons the frozen world —
    /// a panic unwinding through `main`, an early `?` — and turns them into
    /// a boot that continues unprotected rather than a machine that never
    /// comes up.
    fn drop(&mut self) {
        if self.resumed {
            return;
        }
        warn!(
            "a frozen world was dropped without being resumed; \
             resuming {} processes",
            self.stopped.len()
        );
        if let Err(error) = self.resume_stopped() {
            warn!("resuming the dropped world failed: {error:#}");
        }
    }
}

/// The command-line flag that re-execs this binary as the watchdog.
pub const WATCHDOG_ARG: &str = "--wabbit-watchdog";

/// The watchdog that thaws the world if `wabbit-initrd` dies frozen.
///
/// `Drop` covers every path that runs userspace code, but a `SIGKILL` — the
/// init script cleaning up, the OOM killer — runs none of it, and a frozen
/// world would otherwise stay frozen forever: an unbootable machine. The
/// watchdog is the second line of defense:
///
/// * it is spawned *before* the first freeze, so it is never itself stopped
///   (every freeze exempts it);
/// * it blocks reading a pipe whose only write-end is held by this process
///   — with `FD_CLOEXEC`, so wabbit and the verify workers never inherit a
///   copy — which means the read returns exactly when this process dies, by
///   any cause, kernel-closed fds included;
/// * when that happens it sends `SIGCONT` to every process it can find: a
///   superset of the frozen set, and a no-op for anything already running.
///
/// The result is fail-open by construction: a dead `wabbit-initrd` means an
/// unprotected boot, never a frozen one.
pub struct Watchdog {
    /// The pipe write-end whose lifetime is this process's lifetime: held,
    /// never read. Its existence is the whole point — dropping it (or this
    /// process dying) is what closes the pipe and triggers the watchdog.
    #[expect(
        dead_code,
        reason = "the descriptor is held for its lifetime effect, not read"
    )]
    keepalive: File,
    /// The watchdog's PID, so freezes can exempt it.
    pid: Pid,
    /// The child handle, so a watchdog that dies first does not linger as a
    /// zombie: it is reaped by `init` when this process exits, and the
    /// exemption list merely carries a harmless dead PID afterwards. Held
    /// for its lifetime effect, never waited on by this process.
    #[expect(
        dead_code,
        reason = "the handle is held for its lifetime effect, not read"
    )]
    child: Child,
}

impl Watchdog {
    /// Spawn the watchdog child. Call this before the first freeze.
    pub fn spawn() -> Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a valid two-slot buffer for `pipe(2)`.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error()))
                .context("creating the watchdog pipe");
        }
        let [read_end, write_end] = fds;
        // The keepalive end must die with this process: give it FD_CLOEXEC
        // so no re-exec of this binary (watchdog, verify workers, wabbit)
        // inherits a copy that would outlive us and block the EOF.
        // SAFETY: plain `fcntl(F_SETFD)` on a live descriptor.
        if unsafe { libc::fcntl(write_end, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error()))
                .context("cloexec-ing the watchdog keepalive");
        }

        let executable = env::current_exe().context("resolving the current executable")?;
        let child = Command::new(executable)
            .arg(WATCHDOG_ARG)
            .arg(read_end.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawning the freeze watchdog")?;
        let pid = Pid::from_raw(child.id() as i32).expect("a spawned child has a nonzero PID");

        // This side of the pipe is the watchdog's to block on; dropping the
        // parent's copy does not affect the EOF the watchdog waits for.
        drop(unsafe { File::from_raw_fd(read_end) });
        Ok(Self {
            keepalive: unsafe { File::from_raw_fd(write_end) },
            pid,
            child,
        })
    }

    /// The watchdog's PID, for the freeze exemption list.
    pub fn pid(&self) -> Pid {
        self.pid
    }
}

/// The watchdog child: thaw the world when this binary's parent dies.
pub fn watchdog_main(raw: &str) -> Result<()> {
    let raw: RawFd = raw
        .parse()
        .with_context(|| format!("parsing the watchdog pipe fd {raw:?}"))?;
    // Validate before wrapping: `File::from_raw_fd` on a bogus descriptor
    // would abort on IO-safety grounds at best, and close a descriptor this
    // process does not own at worst.
    // SAFETY: `fcntl(F_GETFD)` on a raw descriptor is a pure query.
    if unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        bail!(
            "the watchdog pipe fd {raw} is not open: {}",
            std::io::Error::last_os_error()
        );
    }
    // Best effort: the watchdog is the one process the OOM killer must
    // never take, since it exists to clean up after exactly that.
    let _ = fs::write("/proc/self/oom_score_adj", b"-1000");

    let mut pipe = unsafe { File::from_raw_fd(raw) };
    // Block until the parent's death closes the pipe. Any byte is treated
    // the same as EOF: the sweep below is a no-op for running processes, so
    // standing down and thawing are the same action.
    let mut byte = [0u8; 1];
    let _ = pipe.read(&mut byte);

    let me = getpid();
    eprintln!("wabbit watchdog: the parent is gone; thawing the world");
    for pid in scan_pids(Path::new(PROC)).context("watchdog scanning /proc")? {
        if pid == me {
            continue;
        }
        // SIGCONT to a running process is a no-op, and kernel threads
        // cannot receive signals at all, so the sweep is harmless to
        // everything it did not mean to touch.
        let _ = send(pid, Signal::CONT);
    }
    // Recorded after the sweep, so a sign carrying this record proves the
    // thaw happened. On a clean boot the sign is gone and this record lands
    // nowhere.
    crate::sign::watchdog("parent gone; thawed the world");
    Ok(())
}

/// What [`stop_the_world`] should do with a process it found in `/proc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A kernel thread. It has no `argv` (its `cmdline` is empty), never runs
    /// userspace code, and cannot be stopped. Leave it alone.
    KernelThread,
    /// A zombie or dead process. There is nothing left to stop.
    Dead,
    /// Stopped already, by job control or a debugger.
    Stopped,
    /// In uninterruptible sleep. A sent `SIGSTOP` stays pending until the
    /// process next returns from the kernel, and it cannot run userspace
    /// code until then.
    Uninterruptible,
    /// Running or interruptibly sleeping. It must be sent `SIGSTOP`.
    Live,
}

/// Map a `/proc/<pid>/stat` state character to a [`Class`].
///
/// The states not worth telling apart (`I`, `W`, ...) all mean "alive and
/// stoppable" as far as we are concerned.
fn class_from_state(state: char) -> Class {
    match state {
        'Z' | 'X' => Class::Dead,
        'T' | 't' => Class::Stopped,
        'D' => Class::Uninterruptible,
        _ => Class::Live,
    }
}

/// Read the state character out of `/proc/<pid>/stat` contents.
///
/// `comm` is the executable name wrapped in parentheses and may contain both
/// spaces and parentheses, so the state follows the last `)`.
fn parse_state(stat: &str) -> Option<char> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.trim_start().chars().next()
}

/// Classify `pid` by reading `/proc`.
///
/// `Ok(None)` means the process died while we were reading it. `Err` means
/// `/proc` could not be read at all, which [`stop_the_world`] treats as a
/// failed freeze: a half-frozen world is worse than none.
fn classify(pid: Pid) -> Result<Option<Class>> {
    let stat = match fs::read_to_string(proc_dir(pid).join("stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading /proc/{pid}/stat")),
    };
    let state = parse_state(&stat).with_context(|| format!("parsing /proc/{pid}/stat"))?;
    let class = class_from_state(state);
    if class == Class::Dead {
        return Ok(Some(class));
    }
    // Kernel threads have no `argv`: an empty `cmdline` never runs
    // userspace code and ignores signals.
    let cmdline = match fs::read(proc_dir(pid).join("cmdline")) {
        Ok(cmdline) => cmdline,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading /proc/{pid}/cmdline")),
    };
    if cmdline.is_empty() {
        return Ok(Some(Class::KernelThread));
    }
    Ok(Some(class))
}

/// `/proc/<pid>`.
fn proc_dir(pid: Pid) -> PathBuf {
    Path::new(PROC).join(pid.to_string())
}

/// List the process (or task) IDs named by the numeric entries of `dir`.
///
/// Reading `/proc` races with the processes it describes, so unreadable
/// entries are skipped.
fn scan_pids(dir: &Path) -> io::Result<Vec<Pid>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Ok(raw) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Some(pid) = Pid::from_raw(raw) else {
            continue;
        };
        pids.push(pid);
    }
    Ok(pids)
}

/// Read the task IDs of the direct children of `pid`.
///
/// `/proc/<pid>/task/<tid>/children` lists the tasks forked by a single
/// thread, so every thread of `pid` is visited. A missing file (a kernel
/// without `CONFIG_PROC_CHILDREN`, or a process that died while we were
/// reading it) yields no children; the settle scan after the tree walk
/// scans all of `/proc` and freezes whatever the walk missed.
fn children(pid: Pid) -> Result<Vec<Pid>> {
    let mut children = Vec::new();
    let tids = match scan_pids(&proc_dir(pid).join("task")) {
        Ok(tids) => tids,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(children),
        Err(error) => return Err(error).with_context(|| format!("listing threads of pid {pid}")),
    };
    for tid in tids {
        let file = proc_dir(pid)
            .join("task")
            .join(tid.to_string())
            .join("children");
        let content = match fs::read_to_string(&file) {
            Ok(content) => content,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading children of thread {tid}"));
            }
        };
        children.extend(parse_pid_list(&content));
    }
    Ok(children)
}

/// Walk the process tree from [`INIT_PID`], freezing each process before
/// visiting its children. `protected` PIDs are never stopped.
fn freeze_tree(protected: &[Pid], world: &mut FrozenWorld) -> Result<()> {
    let mut stack = vec![INIT_PID];
    while let Some(pid) = stack.pop() {
        if protected.contains(&pid) {
            // Never stop the freezer or its watchdog, but their own
            // children are part of the world too.
            stack.extend(children(pid)?);
            continue;
        }
        let Some(class) = classify(pid)? else {
            continue; // died while we were looking at it
        };
        if class == Class::KernelThread {
            // Kernel threads only ever parent other kernel threads.
            continue;
        }
        world.freeze(pid, class)?;
        stack.extend(children(pid)?);
    }
    Ok(())
}

/// Rescan the system until the freeze has taken hold.
///
/// The tree walk alone cannot see a process that forked while it was being
/// frozen, and a `SIGSTOP` is only consumed once its victim is next
/// scheduled, so [`stop_the_world`] rescans until a full scan finds nothing
/// left running. Each round enumerates through three independent sources —
/// `readdir`, a direct PID sweep, and the cgroups — so a process hidden from
/// one of them is still seen by the others; see the module documentation.
/// The PID bound is re-read every round so that sweeps cover processes forked
/// since the previous one.
fn settle(protected: &[Pid], world: &mut FrozenWorld) -> Result<()> {
    let mut runaways: Vec<Pid> = Vec::new();
    for _ in 0..SETTLE_ATTEMPTS {
        runaways.clear();

        // Source 1: the traditional `readdir` view of `/proc`.
        for pid in scan_pids(Path::new(PROC)).context("scanning /proc")? {
            freeze_candidate(pid, protected, world, &mut runaways)?;
        }
        // Source 2: a direct sweep of every PID the kernel may have handed
        // out, trusting no directory listing at all.
        if let Some(limit) = pid_sweep_limit() {
            for raw in 1..=limit {
                let Some(pid) = Pid::from_raw(raw as i32) else {
                    continue;
                };
                freeze_candidate(pid, protected, world, &mut runaways)?;
            }
        } else {
            debug!("no PID upper bound available; settling on readdir and cgroups");
        }
        // Source 3: `cgroup.procs`, readable no matter how `/proc` is
        // mounted. Absent during the first freeze — cgroupfs is mounted for
        // the second one — and exhaustive for the second.
        if let Some(pids) = cgroup_pids()? {
            for pid in pids {
                freeze_candidate(pid, protected, world, &mut runaways)?;
            }
        }

        if runaways.is_empty() {
            return Ok(());
        }
        debug!("waiting for {} processes to stop", runaways.len());
        thread::sleep(SETTLE_DELAY);
    }
    bail!("processes refused to stop: {runaways:?}");
}

/// Freeze a single candidate PID, pushing it into `runaways` when it has not
/// consumed its `SIGSTOP` yet. `protected` PIDs are never stopped.
fn freeze_candidate(
    pid: Pid,
    protected: &[Pid],
    world: &mut FrozenWorld,
    runaways: &mut Vec<Pid>,
) -> Result<()> {
    if protected.contains(&pid) {
        return Ok(());
    }
    let Some(class) = classify(pid)? else {
        return Ok(()); // died while we were looking at it
    };
    if !world.freeze(pid, class)? {
        runaways.push(pid);
    }
    Ok(())
}

/// The highest PID worth sweeping, read from the kernel.
///
/// `ns_last_pid` is the exact last-allocated PID; `pid_max` is always
/// available but only an upper bound. `None` means `/proc/sys` could not be
/// read and only `readdir` and cgroup enumeration are possible.
fn pid_sweep_limit() -> Option<u32> {
    let read = |path: &str| {
        fs::read_to_string(path)
            .ok()
            .and_then(|content| content.trim().parse::<u32>().ok())
    };
    let limit = read(NS_LAST_PID).or_else(|| read(PID_MAX))?;
    if limit > SWEEP_HARD_CAP {
        warn!("capping PID sweep at {SWEEP_HARD_CAP} (kernel reported {limit})");
        return Some(SWEEP_HARD_CAP);
    }
    Some(limit)
}

/// All PIDs named by `cgroup.procs` files under [`CGROUP_ROOT`].
///
/// `Ok(None)` means cgroupfs is not mounted: the first freeze happens before
/// the runtime filesystems exist, the second after they do. Unlike `/proc`,
/// cgroupfs has no mount option that hides processes, so when it is present
/// it is the view that cannot lie.
fn cgroup_pids() -> Result<Option<Vec<Pid>>> {
    match fs::metadata(CGROUP_ROOT) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            debug!("{CGROUP_ROOT} not mounted; no cgroup enumeration");
            return Ok(None);
        }
        Err(error) => return Err(error).context("inspecting cgroup root"),
        Ok(_) => {}
    }
    let mut pids = Vec::new();
    walk_cgroups(Path::new(CGROUP_ROOT), &mut pids).context("walking cgroups")?;
    Ok(Some(pids))
}

/// Recursively collect the PIDs of one cgroup directory into `pids`.
///
/// The walk works for both cgroup v2 (one hierarchy) and v1 (several
/// controller hierarchies listing the same processes: harmless duplicates,
/// deduplicated by the freeze bookkeeping), and never follows symlinks, so
/// it cannot cycle.
fn walk_cgroups(dir: &Path, pids: &mut Vec<Pid>) -> io::Result<()> {
    match fs::read_to_string(dir.join("cgroup.procs")) {
        Ok(content) => pids.extend(parse_pid_list(&content)),
        // The cgroup was removed while we were walking it.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    for entry in fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => walk_cgroups(&entry.path(), pids)?,
            Ok(_) => {}
            Err(_) => continue,
        }
    }
    Ok(())
}

/// Parse a `cgroup.procs`/`cgroup.threads` file: whitespace-separated IDs.
fn parse_pid_list(content: &str) -> Vec<Pid> {
    content
        .split_whitespace()
        .filter_map(|raw| raw.parse::<i32>().ok())
        .filter(|raw| *raw > 0)
        .filter_map(Pid::from_raw)
        .collect()
}

/// Send `signal` to `pid`. A process that died in the meantime counts as
/// stopped for good.
fn send(pid: Pid, signal: Signal) -> Result<()> {
    match kill_process(pid, signal) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(error) => Err(error).with_context(|| format!("signaling pid {pid}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_follows_the_last_parenthesis() {
        // A truncated real `/proc/<pid>/stat` line.
        let stat = "129656 (cat) R 129648 129648 129648 0 -1 4194304";
        assert_eq!(parse_state(stat), Some('R'));
    }

    #[test]
    fn drop_thaws_an_abandoned_world() {
        // Prove the fail-safe on a real child: SIGSTOP it, record it the way
        // a freeze would, abandon the world, and confirm the drop resumes it.
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning a sleep child");
        let pid = Pid::from_raw(child.id() as i32).expect("a spawned child has a PID");

        send(pid, Signal::STOP).expect("SIGSTOPping the child");
        // Wait for the stop to be consumed before abandoning the world, so
        // the SIGCONT cannot race an unconsumed SIGSTOP.
        wait_for_state(pid, |state| state == Some('T'));

        let mut world = FrozenWorld::default();
        world.stopped.insert(pid);
        drop(world);

        wait_for_state(pid, |state| state != Some('T'));
        send(pid, Signal::KILL).expect("SIGKILLing the child");
        child.wait().expect("reaping the child");
    }

    #[test]
    fn an_explicit_resume_is_remembered() {
        let mut world = FrozenWorld::default();
        // A PID that does not exist: `send` treats ESRCH as stopped for
        // good, so this exercises the bookkeeping without a real process.
        world
            .stopped
            .insert(Pid::from_raw(424242).expect("a nonzero PID is valid"));
        world.resume().expect("resuming a nonexistent PID is fine");
        assert!(world.resumed);
        // Dropping a resumed world must not send anything.
        drop(world);
    }

    /// Wait up to a second for `/proc/<pid>/stat` to satisfy `predicate`.
    fn wait_for_state(pid: Pid, predicate: impl Fn(Option<char>) -> bool) {
        for _ in 0..100 {
            thread::sleep(Duration::from_millis(10));
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("reading the stat");
            if predicate(parse_state(&stat)) {
                return;
            }
        }
    }

    #[test]
    fn comm_may_contain_parens_and_spaces() {
        let stat = "1234 (systemd (thing)) S 1 1 1 0 -1";
        assert_eq!(parse_state(stat), Some('S'));
        let stat = "1234 (weird )name) T 1 1 1 0 -1";
        assert_eq!(parse_state(stat), Some('T'));
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(parse_state(""), None);
        assert_eq!(parse_state("1 (unclosed R 1 1"), None);
        assert_eq!(parse_state("1234 ()"), None);
    }

    #[test]
    fn classes() {
        assert_eq!(class_from_state('R'), Class::Live);
        assert_eq!(class_from_state('S'), Class::Live);
        assert_eq!(class_from_state('I'), Class::Live);
        assert_eq!(class_from_state('T'), Class::Stopped);
        assert_eq!(class_from_state('t'), Class::Stopped);
        assert_eq!(class_from_state('D'), Class::Uninterruptible);
        assert_eq!(class_from_state('Z'), Class::Dead);
        assert_eq!(class_from_state('X'), Class::Dead);
    }

    #[test]
    fn cgroup_id_lists_parse() {
        let pids = parse_pid_list("12\n34\n");
        assert_eq!(
            pids,
            vec![Pid::from_raw(12).unwrap(), Pid::from_raw(34).unwrap(),]
        );
        assert!(parse_pid_list("").is_empty());
        assert!(parse_pid_list("  \n").is_empty());
        assert_eq!(parse_pid_list("12 garbage 34").len(), 2);
        // Zero and negative IDs are never valid.
        assert!(parse_pid_list("0 -3").is_empty());
    }
}
