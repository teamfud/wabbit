#![allow(non_camel_case_types)]

use core::mem::size_of;

pub const AUTH_VERSION: u32 = 1;

pub const ACTION_SETNS: u64 = 1 << 0;
pub const ACTION_UNSHARE: u64 = 1 << 1;
pub const ACTION_MOUNT: u64 = 1 << 2;
pub const ACTION_EXEC: u64 = 1 << 3;
pub const ACTION_CREDENTIALS: u64 = 1 << 4;
pub const ACTION_TAG_CONTROL: u64 = 1 << 5;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CgroupKey {
    pub cgroup_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Authorization {
    pub version: u32,
    pub size: u32,
    pub generation: u64,
    pub action_mask: u64,
    pub namespace_id: u64,
    pub flags: u64,
}

const _: () = assert!(size_of::<CgroupKey>() == 8);
const _: () = assert!(size_of::<Authorization>() == 40);
