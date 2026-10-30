//! Runtime filesystem handles: the startup diagram's first `wabbit` step —
//! "open file descriptors for /proc, /sys, /dev, etc", then "keep those
//! for later".
//!
//! `wabbit` starts from the initramfs, before `switch_root` moves the real
//! root (mounted at `/sysroot`) onto `/`. Every filesystem the later
//! lifecycle reads through is alive at that moment — procfs, sysfs
//! (carrying the bnuuy pins at `/sys/fs/bpf` and cgroup2 at
//! `/sys/fs/cgroup` as submounts), devtmpfs, `/run` — but their *paths*
//! will not survive the transition: the booted system mounts fresh ones
//! over the names, and busybox `switch_root` deletes the initramfs
//! underneath them. A file descriptor refers to its mount object, not to
//! a path, so descriptors opened here keep referring to the same mounts
//! whatever the transition does to the names, and resolving paths
//! *relative to a descriptor* (`openat`) crosses the living submounts as
//! usual. Holding them is how the handoff's later steps find the live
//! system after the boot: `/proc/1/root` for systemd's view of the real
//! root, the pinned maps under `/sys/fs/bpf`, `/run/systemd/private` for
//! the systemd poll (`crate::handoff`).
//!
//! The descriptors are opened `O_PATH` and without `CLOEXEC`: they exist
//! to anchor their mounts and to serve as `openat` bases, and they stay
//! open — and inheritable — for this process's whole lifetime, including
//! across the `exec`s it spawns.
//!
//! # Verification
//!
//! wabbit-initrd's house rule applies here too: a mount proves itself by
//! filesystem magic, because nothing else does (`EBUSY` alone proves
//! nothing). The procfs and sysfs descriptors are load-bearing — every
//! later step reads through them — so they must present [`PROC_SUPER_MAGIC`]
//! and [`SYSFS_MAGIC`], and a startup that cannot get them fails loudly
//! instead of running blind. `/dev` (devtmpfs from an initrd, tmpfs in a
//! sandbox) and `/run` (the bnuuy sign, systemd's private socket) are
//! conveniences: a foreign filesystem there warns but keeps the descriptor,
//! because nothing security-critical reads through them yet.

use std::os::fd::OwnedFd;

use anyhow::{Context, Result, bail};
use log::{info, warn};
use rustix::{
    fs::{Mode, OFlags, fstatfs, open},
    io::Errno,
};
use wabbit_common::brand::NAME;

/// Filesystem magics, from the kernel UAPI (`include/uapi/linux/magic.h`).
const PROC_SUPER_MAGIC: i64 = 0x9fa0;
const SYSFS_MAGIC: i64 = 0x62656572;
const TMPFS_MAGIC: i64 = 0x01021994;
const DEVTMPFS_SUPER_MAGIC: i64 = 0x958458f6;

/// Descriptors on the runtime filesystems, held for this process's
/// lifetime: the "keep those for later" of the startup diagram.
#[derive(Debug)]
pub struct RuntimeFds {
    /// procfs at `/proc`. The systemd step reads systemd's view of the
    /// real root through this descriptor (`openat` of `1/root`).
    pub procfs: OwnedFd,
    /// sysfs at `/sys`, carrying bpffs (`/sys/fs/bpf`, the bnuuy pins) and
    /// cgroup2 (`/sys/fs/cgroup`) as submounts.
    pub sysfs: OwnedFd,
    /// devtmpfs at `/dev`: the console wabbit's own diagnostics write to.
    pub dev: OwnedFd,
    /// The `/run` the initrd provides: the bnuuy sign at `run/bnuuy.bin`,
    /// systemd's private socket at `run/systemd/private`.
    pub run: OwnedFd,
}

impl RuntimeFds {
    /// Open descriptors on `/proc`, `/sys`, `/dev`, and `/run`, each
    /// verified against its own mount, and hold them for later.
    ///
    /// Call before anything moves under `/sysroot` — and before touching
    /// the first mount: a captured environment that cannot pass
    /// verification fails fast here, before [`crate::filesystem`] applies
    /// anything.
    pub fn capture() -> Result<Self> {
        // Load-bearing: everything the later lifecycle reads flows through
        // these two, so the wrong filesystem here must fail loudly.
        let procfs = capture_required("/proc", PROC_SUPER_MAGIC)?;
        let sysfs = capture_required("/sys", SYSFS_MAGIC)?;
        // Conveniences: kept whatever they turn out to be.
        let dev = capture_preferred("/dev", &[DEVTMPFS_SUPER_MAGIC, TMPFS_MAGIC])?;
        let run = capture_preferred("/run", &[TMPFS_MAGIC])?;
        info!("captured runtime fds: /proc, /sys, /dev, /run");
        Ok(Self {
            procfs,
            sysfs,
            dev,
            run,
        })
    }
}

/// Open a directory descriptor whose filesystem must present `magic`.
fn capture_required(path: &str, magic: i64) -> Result<OwnedFd> {
    let fd = open_dir(path)?;
    // Verify the mount the descriptor grabbed, not whatever a fresh path
    // walk resolves to: the two can differ under an init script that is
    // still mounting things.
    let found = fd_type(&fd).with_context(|| format!("verifying {path}"))?;
    if found != magic {
        bail!(
            "expected filesystem magic {magic:#x} at {path}, found {found:#x}: \
             {NAME} reads the live system through this descriptor and refuses \
             to start blind"
        );
    }
    Ok(fd)
}

/// Open a directory descriptor whose filesystem should be one of `expected`.
///
/// Nothing security-critical reads through these yet, so an unexpected —
/// or unverifiable — filesystem degrades to a warning and the descriptor
/// is kept anyway: a held handle beats a failed startup.
fn capture_preferred(path: &str, expected: &[i64]) -> Result<OwnedFd> {
    let fd = open_dir(path)?;
    match fd_type(&fd) {
        Ok(found) if expected.contains(&found) => {}
        Ok(found) => warn!(
            "unexpected filesystem (magic {found:#x}) at {path}; keeping the \
             descriptor anyway"
        ),
        Err(error) => warn!(
            "could not verify the filesystem at {path} ({error}); keeping the \
             descriptor anyway"
        ),
    }
    Ok(fd)
}

/// Open `path` as a directory descriptor: `O_PATH` to anchor the mount,
/// no `CLOEXEC` so it survives into everything wabbit execs.
fn open_dir(path: &str) -> Result<OwnedFd> {
    open(path, OFlags::DIRECTORY | OFlags::PATH, Mode::empty())
        .with_context(|| format!("opening {path}"))
}

/// The filesystem magic behind a descriptor, straight from `fstatfs(2)` on
/// the descriptor itself.
fn fd_type(fd: &OwnedFd) -> Result<i64, Errno> {
    fstatfs(fd).map(|statfs| statfs.f_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptors the host hands out must be the real kernel
    /// interfaces, straight from `fstatfs` on each descriptor.
    #[test]
    fn capture_finds_the_kernel_filesystems() {
        let fds = RuntimeFds::capture().expect("capturing the runtime fds");
        assert_eq!(fd_type(&fds.procfs).unwrap(), PROC_SUPER_MAGIC);
        assert_eq!(fd_type(&fds.sysfs).unwrap(), SYSFS_MAGIC);
        // The conveniences are held open, whatever they turned out to be.
        assert!(fd_type(&fds.dev).is_ok());
        assert!(fd_type(&fds.run).is_ok());
    }

    /// A required descriptor with the wrong magic must fail loudly, with
    /// the path in the message.
    #[test]
    fn a_wrong_required_magic_fails_loudly() {
        let error = capture_required("/proc", SYSFS_MAGIC)
            .expect_err("procfs does not present sysfs's magic");
        assert!(error.to_string().contains("/proc"), "{error}");
    }

    /// A preferred capture keeps the descriptor whatever it finds there.
    #[test]
    fn a_preferred_capture_keeps_unexpected_mounts() {
        let fd = capture_preferred("/proc", &[SYSFS_MAGIC]).expect("opening /proc");
        assert_eq!(fd_type(&fd).unwrap(), PROC_SUPER_MAGIC);
    }
}
