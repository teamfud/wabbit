use std::path::Path;

use rustix::{
    mount::{MountFlags, MountPropagationFlags, mount, mount_bind, mount_change, mount_remount},
    thread::{UnshareFlags, unshare_unsafe},
};

use crate::policy::rootfs::{PathOverride, RootFSConfig};

/// Create a private mount namespace for the calling thread.
pub fn create_namespace() -> rustix::io::Result<()> {
    // SAFETY: NEWNS changes only the calling thread's mount namespace.
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }
}

/// Apply a root filesystem policy in the current mount namespace.
///
/// `inner` selects the namespace-local values on each `PathOverride`; pass
/// `false` before creating a namespace and `true` after creating one. The
/// operation is intentionally reusable and may be called repeatedly.
pub fn apply_rootfs_config(config: &RootFSConfig, inner: bool) -> rustix::io::Result<()> {
    remount(
        "/",
        config.flags.writable(),
        config.flags.executable(),
        true,
    )?;

    let mut overrides: Vec<&PathOverride> = config.overrides.iter().collect();
    overrides.sort_by_key(|override_| override_.priority);
    for override_ in overrides {
        let flags = override_.flags;
        let (writable, executable) = if inner {
            (flags.inner_writable(), flags.inner_executable())
        } else {
            (flags.outer_writable(), flags.outer_executable())
        };
        for path in &override_.path {
            remount(path, writable, executable, false)?;
        }
    }
    Ok(())
}

/// Make the mount tree private. This is required before applying namespace-local
/// remounts so they cannot propagate to the parent namespace.
pub fn make_mount_tree_private() -> rustix::io::Result<()> {
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
}

fn remount(
    path: impl AsRef<Path>,
    writable: bool,
    executable: bool,
    recursive: bool,
) -> rustix::io::Result<()> {
    let path = path.as_ref();
    mount_bind(path, path)?;
    let mut flags = MountFlags::BIND;
    if !writable {
        flags |= MountFlags::RDONLY;
    }
    if !executable {
        flags |= MountFlags::NOEXEC;
    }
    if recursive {
        flags |= MountFlags::REC;
    }
    mount_remount(path, flags, &b""[..])
}

pub fn make_read_only(path: &Path) -> rustix::io::Result<()> {
    remount(path, false, true, false)
}

/// Compatibility helper for callers that only need the old writable-path setup.
pub fn prepare_namespace(writable_paths: &[impl AsRef<Path>]) -> rustix::io::Result<()> {
    make_mount_tree_private()?;
    for path in writable_paths {
        remount(path, true, true, false)?;
    }
    Ok(())
}

pub fn generate_tmpfs(path: &Path) -> rustix::io::Result<()> {
    mount("tmpfs", path, "tmpfs", MountFlags::empty(), None)
}
