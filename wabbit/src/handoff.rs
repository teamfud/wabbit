//! The initrd handoff and the crossing of `switch_root`
//! (`docs/startup.mermaid`): the trust rendezvous, announcing enforcement,
//! waiting out the initrd's pre-shutdown self-test, then joining the
//! booted system.
//!
//! # The protocol
//!
//! `wabbit-initrd` launches this process with a socketpair duped to
//! [`handoff::SOCKET_FD`] and the descriptor number in
//! `<prefix>_HANDOFF_FD`. The exchange, in order:
//!
//! 1. `trusted` ← the `bpf(2)` trust grant (bnuuy's `TRUSTED_BPF_PIDS`)
//!    has landed. **This process waits for it** before its first `bpf(2)`
//!    call: both sides run after the same fork, and nothing else orders
//!    the grant against the guard object's map creates. A lost race
//!    reads the trust map without this PID and denies the creates
//!    (`EPERM`) — a failure the lab measured as *nondeterministic*
//!    across boots of the same artifact — so [`Handoff::await_trust`]
//!    makes it a rendezvous instead.
//! 2. `ready` → the initrd runs its pre-shutdown self-test (its workers
//!    spawn from outside every trust map, and the enforcing guard — plus,
//!    until the initrd exits, bnuuy's shadowing gates — must deny each
//!    one) and then answers `die`;
//! 3. `ack` → the initrd exits, its bnuuy links detach, the world thaws,
//!    and the init resumes into `switch_root`.
//!
//! EOF instead of the expected message is fail-open: the initrd died by
//! any cause, its watchdog thawed the world, and the boot proceeds — into
//! the polls below, same as a clean handoff.
//!
//! # Crossing `switch_root`
//!
//! This process starts in the initramfs with a *private* mount namespace
//! (its inner rootfs policy is namespace-local, per
//! [`crate::filesystem`]). `switch_root` moves the real root onto `/` in
//! the *init's* namespace — a busybox `switch_root` deletes the initramfs
//! underneath this process's root, and a systemd one kills everything not
//! marked with `argv[0][0] == '@'` — so after the transition this
//! process's absolute paths resolve into a deleted ramfs, and everything
//! the booted system mounts lands in a namespace this process is not in.
//!
//! The startup diagram's answer is `/proc/1/root`: "see systemd's view of
//! the rootfs". The descriptors [`crate::runtime`] captured before the
//! transition still anchor their mounts, so the polls resolve through
//! them:
//!
//! * PID 1's root (`1/root` through the held procfs descriptor) becomes
//!   the real root the moment `switch_root` completes — until then it is
//!   the same initramfs root this process holds, so the poll is "PID 1's
//!   root differs from mine".
//! * joining PID 1's mount namespace (`1/ns/mnt`) is what makes that view
//!   *complete*: without it, `chroot` would land in the real root but
//!   every later mount — systemd's `/run` above all — would stay in the
//!   old namespace, invisible to every path this process resolves.
//! * `chroot` through `1/root` then makes the view this process's own.
//!
//! Like the namespace *creation* in `main`, the namespace *join* is
//! thread-local (`setns(CLONE_NEWNS)` fails on a shared `fs_struct`, which
//! every tokio worker thread holds) — so [`Handoff::ready`] and
//! [`join_root`] run on the main thread, before the runtime's threads
//! exist.
//!
//! # Not an initramfs launch
//!
//! A `wabbit` started outside the initrd (the VM lab's `test` flow, a
//! standalone run) sits on a real root, not a rootfs: the polls do not
//! apply, and both steps say so and return. The readiness exchange runs
//! whenever the descriptor is provided, wherever the process started.

use std::{
    env,
    ffi::CString,
    io::{self, Read as _, Write as _},
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use log::{info, warn};
use rustix::fs::{Mode, OFlags, fstatfs, open, openat};
use wabbit_common::{brand, handoff};

use crate::runtime::RuntimeFds;

/// How long to wait between switch-root and readiness polls.
const POLL: Duration = Duration::from_millis(200);

/// Polls between progress log lines.
const PROGRESS_EVERY: u64 = 100;

/// `rootfs` — the initramfs root — from the kernel UAPI
/// (`include/uapi/linux/magic.h`): the magic that marks "this process
/// started in an initramfs" for the switch-root polls.
const ROOTFS_MAGIC: i64 = 0x858458f6;

/// The environment variable carrying the handoff descriptor's number.
fn handoff_fd_var() -> String {
    format!("{}_HANDOFF_FD", brand::ENV_PREFIX)
}

/// The handoff socketpair, when the environment hands one over.
///
/// One handle for the process's whole life: the trust rendezvous and the
/// readiness exchange share it, in order, and the descriptor is only
/// `from_raw_fd`-owned once.
pub struct Handoff {
    socket: Option<UnixStream>,
}

impl Handoff {
    /// Take the handoff socket from the environment: `wabbit-initrd` dups
    /// its end to [`handoff::SOCKET_FD`] and passes the number in
    /// `<prefix>_HANDOFF_FD`. `None` means no initrd launched this
    /// process — every step below is a no-op.
    pub fn from_env() -> Result<Self> {
        let Some(fd) = env::var_os(handoff_fd_var()) else {
            return Ok(Self { socket: None });
        };
        let number: i32 = fd
            .to_str()
            .and_then(|value| value.trim().parse().ok())
            .with_context(|| format!("{} must carry a descriptor number", handoff_fd_var()))?;
        // SAFETY: the descriptor is wabbit-initrd's socketpair end, inherited
        // through the launch and owned solely by this process from here.
        let socket = unsafe { <UnixStream as std::os::unix::io::FromRawFd>::from_raw_fd(number) };
        Ok(Self {
            socket: Some(socket),
        })
    }

    /// Wait for `wabbit-initrd`'s `bpf(2)` trust grant before this
    /// process's first `bpf(2)` call (see the module docs: the guard
    /// object's map creates race the grant, and a lost race reads the
    /// trust map without this PID).
    ///
    /// Call once at startup, before anything touches `bpf(2)` — the guard
    /// load, the logger's ring buffer, anything. EOF is fail-open: the
    /// initrd is dead, its gates detached, and `bpf(2)` is unrestricted
    /// from here.
    pub fn await_trust(&mut self) -> Result<()> {
        let Some(socket) = self.socket.as_mut() else {
            info!(
                "no handoff socket ({} unset): running standalone",
                handoff_fd_var()
            );
            return Ok(());
        };
        match read_message(socket) {
            Ok(Some(message)) if message == "trusted" => {
                info!("the initrd granted bpf(2) trust; loading the guard");
                Ok(())
            }
            Ok(Some(message)) => {
                bail!("unexpected handoff message {message:?} before the trust grant")
            }
            // The initrd is dead: its watchdog thaws the world, its gates
            // detached with it, and `bpf(2)` is unrestricted. Proceed.
            Ok(None) => {
                warn!(
                    "the initrd closed the handoff socket before the trust grant; \
                     continuing (its watchdog thaws the boot and it proceeds)"
                );
                Ok(())
            }
            Err(error) => Err(error).context("reading the handoff trust grant"),
        }
    }

    /// Announce that the guard is enforcing, then wait for the initrd's
    /// go-ahead. Call once the self-test has passed and the enforcing flip
    /// has happened, and only on the main thread: the other side blocks
    /// here for the duration of its pre-shutdown self-test, and no runtime
    /// threads exist yet to block instead.
    pub fn ready(&mut self) -> Result<()> {
        let Some(socket) = self.socket.as_mut() else {
            info!("no handoff socket: running standalone");
            return Ok(());
        };
        socket
            .write_all(handoff::READY)
            .context("announcing readiness on the handoff socket")?;
        match read_message(socket) {
            // The go-ahead: the initrd's pre-shutdown self-test passed. The
            // ack releases it to exit; its bnuuy links detach with it, the
            // world thaws, and the init resumes into switch_root.
            Ok(Some(message)) if message == "die" => {}
            Ok(Some(message)) => bail!("unexpected handoff message {message:?}"),
            // The initrd is gone: its watchdog thawed the world, and the boot
            // proceeds. The protections ended with it either way — fail-open.
            Ok(None) => warn!(
                "the initrd closed the handoff socket without a go-ahead; \
                 continuing (its watchdog thaws the boot and it proceeds)"
            ),
            Err(error) => return Err(error).context("reading the handoff go-ahead"),
        }
        // The ack's only reader is a live initrd; an error here means it is
        // not, and its own side of the socket explains that.
        let _ = socket.write_all(handoff::ACK);
        info!("the initrd handed off: it exits, the boot switches root, and this process crosses");
        Ok(())
    }
}

/// Wait out `switch_root` and join the booted system: PID 1's root, PID 1's
/// mount namespace, and then systemd's readiness. Call on the main thread
/// before the runtime's threads exist (see the module docs).
pub fn join_root(fds: &RuntimeFds) -> Result<()> {
    if !started_in_initramfs()? {
        info!("the root is not the initramfs rootfs: no switch_root to wait out");
        return Ok(());
    }

    // Poll for PID 1's crossing. Until switch_root, PID 1 holds the same
    // initramfs root this process does, so `1/root` and `/` state
    // identically; the moment it crosses, they do not.
    let own = stat_pair(libc::AT_FDCWD, "/").context("stating this root")?;
    let procfs = fds.procfs.as_raw_fd();
    let mut polls: u64 = 0;
    loop {
        match stat_pair(procfs, "1/root") {
            Ok(target) if target != own => break,
            // PID 1 is between roots mid-crossing; the next poll sees it.
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("stating PID 1's root through the procfs descriptor");
            }
        }
        if polls > 0 && polls % PROGRESS_EVERY == 0 {
            info!("still waiting for PID 1 to cross to the real root");
        }
        polls += 1;
        std::thread::sleep(POLL);
    }
    info!("PID 1 has crossed to the real root: switch_root is done");

    // Join PID 1's mount namespace: the booted system's mounts — the
    // fresh `/run` systemd puts its private socket dir into above all —
    // live there, and this process's private namespace would leave every
    // later path resolving into a deleted ramfs.
    let namespace = openat(&fds.procfs, "1/ns/mnt", OFlags::RDONLY, Mode::empty())
        .context("opening PID 1's mount namespace through the procfs descriptor")?;
    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
        return Err(std::io::Error::last_os_error()).context("joining PID 1's mount namespace");
    }
    drop(namespace);

    // See systemd's view of the rootfs, and keep it: opening `1/root`
    // resolves the magic procfs symlink to PID 1's root whatever
    // namespace it landed in, and chroot takes the directory from there.
    let root = openat(
        &fds.procfs,
        "1/root",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("opening PID 1's root through the procfs descriptor")?;
    let dot = CString::new(".").expect("a period holds no NUL");
    // SAFETY: both calls take live, plain descriptors and paths prepared
    // in this thread; `chroot` resolves "." from the working directory
    // set by the `fchdir` immediately before it.
    unsafe {
        if libc::fchdir(root.as_raw_fd()) != 0 {
            return Err(std::io::Error::last_os_error()).context("entering PID 1's root");
        }
        if libc::chroot(dot.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error()).context("chrooting into PID 1's root");
        }
        if libc::chdir(b"/\0".as_ptr().cast()) != 0 {
            return Err(std::io::Error::last_os_error()).context("resetting the working directory");
        }
    }
    info!("joined the booted system: PID 1's mount namespace and root");

    // Poll for the appearance of `/run/systemd/private`: systemd creates
    // its private socket directory early in its boot. Absolute paths
    // resolve through the joined namespace now, so this is the booted
    // system's `/run`.
    loop {
        if std::fs::metadata("/run/systemd/private").is_ok() {
            break;
        }
        std::thread::sleep(POLL);
    }
    info!("systemd is up: /run/systemd/private exists; serving from the booted root");
    Ok(())
}

/// Whether this process started in the initramfs: the root is `rootfs`
/// (the ramfs the kernel unpacks the initramfs into), which is exactly
/// what `switch_root` later replaces in PID 1.
fn started_in_initramfs() -> Result<bool> {
    let root = open("/", OFlags::PATH | OFlags::DIRECTORY, Mode::empty())
        .context("opening the root as a descriptor")?;
    let magic = fstatfs(&root)
        .context("stating the root filesystem")?
        .f_type;
    Ok(magic == ROOTFS_MAGIC)
}

/// The `(st_dev, st_ino)` of `path`, resolved relative to `dirfd`
/// (`AT_FDCWD` for absolute paths). Symlinks are followed: through
/// procfs, `1/root` must state the *target* — PID 1's root — not the
/// procfs symlink's own inode.
fn stat_pair(dirfd: i32, path: &str) -> std::io::Result<(u64, u64)> {
    let path = CString::new(path)?;
    let mut stat: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: `path` is a valid NUL-terminated string for the duration of
    // the call, and `stat` is a plain, writable, fully-sized buffer.
    if unsafe { libc::fstatat(dirfd, path.as_ptr(), &mut stat, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((stat.st_dev as u64, stat.st_ino))
}

/// Read one `\n`-terminated message. `Ok(None)` is a clean EOF: the other
/// side closed its socket.
fn read_message(socket: &mut UnixStream) -> Result<Option<String>> {
    let mut message = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match socket.read(&mut byte) {
            Ok(0) => {
                if message.is_empty() {
                    return Ok(None);
                }
                bail!(
                    "the handoff message {:?} is not newline-terminated",
                    message
                );
            }
            Ok(_) if byte[0] == b'\n' => return Ok(Some(String::from_utf8(message)?)),
            Ok(_) => message.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("reading a handoff message"),
        }
        if message.len() > 64 {
            bail!("the handoff message is longer than any sent");
        }
    }
}
