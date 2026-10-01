use std::path::{Path, PathBuf};

use rustix::{
    mount::{MountFlags, MountPropagationFlags, mount, mount_bind, mount_change, mount_remount},
    thread::{UnshareFlags, unshare_unsafe},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PathOverride {
    /// Whether the path mounted to the privileged namespace should NOT be mounted RDONLY.
    pub inner_writable: bool,
    /// Whether the path mounted to the privileged namespace should NOT be mounted NOEXEC.
    pub inner_executable: bool,
    /// Whether the path mounted to the root namespace should NOT be mounted RDONLY.
    pub outer_writable: bool,
    /// Whether the path mounted to the root namespace should NOT be mounted NOEXEC.
    pub outer_executable: bool,
    /// Whether the path mounted to the root namespace should have read permissions for non-root users
    pub outer_readable: bool,
    /// Whether the path mounted to the root namespace should NOT be hidden by wabbit-ebpf.
    pub outer_visible: bool,
    /// The path to modify in the root namespace.
    pub path: PathBuf,
    /// The path to mount to the privileged namespace.
    pub inner_path: Option<PathBuf>,
    /// The layer in the mount stack at which this mount should be applied
    pub priority: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootFSConfig {
    pub executable: bool,
    pub writable: bool,
    #[serde(default)]
    pub overrides: Vec<PathOverride>,
}

impl Default for RootFSConfig {
    fn default() -> Self {
        Self {
            executable: true,
            writable: true,
            overrides: Vec::new(),
        }
    }
}

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
    remount("/", config.writable, config.executable, true)?;

    let mut overrides: Vec<&PathOverride> = config.overrides.iter().collect();
    overrides.sort_by_key(|override_| override_.priority);
    for override_ in overrides {
        let (writable, executable) = if inner {
            (override_.inner_writable, override_.inner_executable)
        } else {
            (override_.outer_writable, override_.outer_executable)
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
