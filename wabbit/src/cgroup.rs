//! this module provides utilities for interacting with, taking over, and joining cgroups.
use std::{os::fd::OwnedFd, path::PathBuf};

use rustix::{
    fs::{Mode, OFlags},
    io::Errno,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

fn mkopen_dir(path: PathBuf) -> Result<OwnedFd, Errno> {
    rustix::fs::open(
        path,
        OFlags::DIRECTORY | OFlags::CREATE,
        Mode::RUSR | Mode::WUSR,
    )
}

fn mk_rt_cgroup(name: &str) -> Result<OwnedFd, Errno> {
    mkopen_dir(PathBuf::from(CGROUP_ROOT).join(name))
}

struct Cgroup {
    name: String,
    fd: OwnedFd,
    is_leaf: bool,
}

impl Cgroup {
    /// get the child cgroups of this cgroup
    fn get_children(&self) -> &[Cgroup] {
        todo!("walking cgroup children")
    }

    /// get the tasks in this cgroup
    fn get_tasks(&self) -> &[OwnedFd] {
        todo!("listing cgroup tasks")
    }

    /// create a cgroup out of thin air
    fn new(name: &str, allow_children: bool, owner: Cgroup) -> Result<Self, Errno> {
        todo!("creating a cgroup")
    }

    /// assemble a wabbit cgroup struct from an existing cgroup.
    fn assemble(fd: OwnedFd, allow_children: bool) -> Self {
        todo!("assembling a cgroup from a file descriptor")
    }
}
