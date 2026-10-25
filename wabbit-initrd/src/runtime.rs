//! Runtime filesystems and the wabbit cgroup.
//!
//! The startup sequence, once the real root is settled and the world is
//! frozen again: "mount necessary runtime filesystems (cgroupfs...)" →
//! "create wabbit cgroup" → "start wabbit".
//!
//! cgroup2 goes to `/sys/fs/cgroup`, the same place dracut and systemd
//! initrds mount it and wabbit's own cgroup handling expects it. If it is
//! already mounted (a systemd initrd mounts it before its targets run),
//! that mount is verified and reused; otherwise this mounts it. The
//! wabbit cgroup is created inside it (a directory in cgroupfs *is* a
//! cgroup), verified empty, and an open descriptor is kept on it — the
//! "done, here's fd" of the startup diagram. `launch` then writes the
//! spawned wabbit's PID into its `cgroup.procs`, so wabbit runs inside the
//! cgroup the authorization maps key on, and everything it forks inherits
//! that membership.
//!
//! wabbit-initrd exits before `switch_root` happens; only wabbit crosses
//! the transition (through its `argv[0]` marking). Whether the cgroup2
//! mount follows `/sys` into the booted system or dies with the initrd
//! does not matter to wabbit: its cgroup membership, and the descriptor
//! this process held on it, outlive the mount topology.
//!
//! # Interference with the initrd
//!
//! Every mount wabbit-initrd makes — bpffs at `/sys/fs/bpf`, tracefs at
//! `/sys/kernel/tracing`, cgroup2 at [`CGROUP_ROOT`] — targets a mount
//! point the kernel itself pre-creates inside sysfs
//! (`sysfs_create_mount_point`), in the initrd's shared mount namespace
//! (wabbit-initrd never unshares), so:
//!
//! * nothing of the initrd's own is shadowed: these directories are empty
//!   kernel-provided mount points, not initrd files;
//! * if the initrd already mounted one of them — a systemd initrd mounts
//!   cgroup2 and bpffs for its own use — the existing mount is verified by
//!   filesystem magic and reused; `EBUSY` is never mistaken for success;
//! * the mounts are submounts of `/sys`, so the init script's usual move of
//!   `/sys` into the real root (dracut-style, or initramfs-tools'
//!   init-bottom) carries them into the booted system, which is the point
//!   of mounting them early;
//! * mounting cgroup2 moves no one: processes change cgroups only through
//!   the explicit `cgroup.procs` write for wabbit;
//! * the sysroot poll only counts mounts below the real root, so these
//!   mounts cannot confuse it.
//!
//! The one way these mounts could genuinely interfere is mounting them
//! before `/sys` is sysfs: they would land on the initramfs ramfs and be
//! buried the moment the init script mounts sysfs over it. Every mount is
//! therefore guarded by a sysfs check, and verified by magic afterwards.

use std::{
    fs,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use log::info;
use rustix::{
    fs::{Mode, OFlags, statfs},
    io::Errno,
    mount::{MountFlags, mount},
};

/// Where the unified cgroup hierarchy lives.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The name of wabbit's cgroup inside [`CGROUP_ROOT`], matching
/// `wabbit::cgroup`'s convention.
const WABBIT_CGROUP: &str = "wabbit";

/// Filesystem magics, from the kernel UAPI (`include/uapi/linux/magic.h`).
pub(crate) const SYSFS_MAGIC: i64 = 0x62656572;
const CGROUP2_MAGIC: i64 = 0x63677270;
const CGROUP_V1_MAGIC: i64 = 0x27e0eb;

/// The wabbit cgroup, with the descriptor kept on it.
#[derive(Debug)]
pub struct WabbitCgroup {
    /// `/sys/fs/cgroup/wabbit`.
    pub path: PathBuf,
    /// An open descriptor on the cgroup directory, held for this process's
    /// lifetime so the cgroup stays anchored no matter what later happens
    /// to the cgroupfs mount.
    #[expect(
        dead_code,
        reason = "the descriptor is held for its anchor effect, not read"
    )]
    pub fd: OwnedFd,
}

/// Mount the runtime filesystems and create the wabbit cgroup.
pub fn prepare_runtime() -> Result<WabbitCgroup> {
    ensure_cgroupfs()?;
    ensure_wabbit_cgroup()
}

/// Mount cgroup2 at [`CGROUP_ROOT`], or verify that it already is.
fn ensure_cgroupfs() -> Result<()> {
    // Mounting cgroup2 under an unmounted /sys would bury the mount the
    // moment the init script mounts sysfs over it, so /sys must be sysfs
    // first.
    let sys = filesystem_type("/sys").context("inspecting /sys")?;
    if sys != SYSFS_MAGIC {
        bail!(
            "expected sysfs at /sys (magic {SYSFS_MAGIC:#x}), found magic \
             {sys:#x}: the init script must mount /sys before wabbit-initrd runs"
        );
    }

    match filesystem_type(CGROUP_ROOT) {
        Ok(CGROUP2_MAGIC) => {
            info!("cgroup2 is already mounted at {CGROUP_ROOT}");
            return Ok(());
        }
        // A cgroup v1 hierarchy cannot back the unified-hierarchy
        // authorization model.
        Ok(CGROUP_V1_MAGIC) => {
            bail!("found a cgroup v1 hierarchy at {CGROUP_ROOT}; wabbit needs cgroup2")
        }
        // The kernel creates an empty mount point for cgroup2 in sysfs
        // (4.6+); nothing is mounted there yet.
        Ok(SYSFS_MAGIC) => {}
        // The mount point directory does not exist yet.
        Err(Errno::NOENT) => {
            fs::create_dir_all(CGROUP_ROOT)
                .context("creating the cgroup2 mount point under sysfs")?;
        }
        Ok(other) => bail!("unexpected filesystem (magic {other:#x}) at {CGROUP_ROOT}"),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {CGROUP_ROOT}"));
        }
    }

    mount("cgroup2", CGROUP_ROOT, "cgroup2", MountFlags::empty(), None)
        .with_context(|| format!("mounting cgroup2 at {CGROUP_ROOT}"))?;

    // A mount that does not present as cgroup2 would defeat the point of
    // this step, and wabbit would silently run on the wrong hierarchy.
    let mounted = filesystem_type(CGROUP_ROOT).context("verifying the cgroup2 mount")?;
    if mounted != CGROUP2_MAGIC {
        bail!("mounted {CGROUP_ROOT} but found magic {mounted:#x} instead of cgroup2");
    }
    info!("mounted cgroup2 at {CGROUP_ROOT}");
    Ok(())
}

/// Create the wabbit cgroup, or verify the existing one is usable.
fn ensure_wabbit_cgroup() -> Result<WabbitCgroup> {
    let path = Path::new(CGROUP_ROOT).join(WABBIT_CGROUP);
    match fs::metadata(&path) {
        Ok(_) => {
            // Reuse only an empty cgroup: anything already living in
            // wabbit's cgroup would inherit whatever protection it grants.
            let procs = fs::read_to_string(path.join("cgroup.procs"))
                .with_context(|| format!("reading {}", path.join("cgroup.procs").display()))?;
            if !procs_is_empty(&procs) {
                bail!(
                    "the wabbit cgroup at {} already contains processes: {:?}",
                    path.display(),
                    procs
                );
            }
            info!("reusing the existing wabbit cgroup at {}", path.display());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A directory created inside cgroupfs *is* a cgroup.
            fs::create_dir(&path)
                .with_context(|| format!("creating the wabbit cgroup at {}", path.display()))?;
            info!("created the wabbit cgroup at {}", path.display());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspecting the wabbit cgroup at {}", path.display()));
        }
    }

    // The "done, here's fd" of the startup diagram: a descriptor on the
    // cgroup directory, held until this process exits.
    let fd = rustix::fs::open(&path, OFlags::DIRECTORY | OFlags::PATH, Mode::empty())
        .with_context(|| format!("opening the wabbit cgroup at {}", path.display()))?;
    Ok(WabbitCgroup { path, fd })
}

/// The filesystem magic at `path`, straight from `statfs(2)`.
pub(crate) fn filesystem_type(path: &str) -> Result<i64, Errno> {
    statfs(path).map(|statfs| statfs.f_type)
}

/// `cgroup.procs` contents count as empty when they hold nothing but
/// whitespace.
fn procs_is_empty(procs: &str) -> bool {
    procs.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_procs_emptiness() {
        assert!(procs_is_empty(""));
        assert!(procs_is_empty("\n"));
        assert!(procs_is_empty("  \n\n"));
        assert!(!procs_is_empty("42\n"));
        assert!(!procs_is_empty("42\n1337\n"));
    }
}
