#![allow(non_camel_case_types)]

use core::mem::size_of;

pub const AUTH_VERSION: u32 = 1;

pub const ACTION_SETNS: u64 = 1 << 0;
pub const ACTION_UNSHARE: u64 = 1 << 1;
pub const ACTION_MOUNT: u64 = 1 << 2;
pub const ACTION_EXEC: u64 = 1 << 3;
pub const ACTION_CREDENTIALS: u64 = 1 << 4;
pub const ACTION_TAG_CONTROL: u64 = 1 << 5;

/// Use the `bpf(2)` syscall in the restricted form system-management
/// daemons need — the "systemd class".
///
/// Grant this only to cgroups whose bpf(2) use is orchestrated by PID 1
/// (init.scope and, if it turns out to genuinely need it,
/// systemd-udevd.service): systemd loads and attaches every unit's cgroup
/// device-control and egress-firewall programs itself, so services never
/// need the bit.
///
/// What the class permits, and what each permit relies on:
///
/// * `BPF_PROG_LOAD`, but only for cgroup-family program types
///   (`CGROUP_DEVICE`, `CGROUP_SKB`, `CGROUP_SOCK_ADDR`, `SOCKET_FILTER`,
///   `SOCK_OPS`, `CGROUP_SOCK`): enough for `DeviceAllow=`, per-unit
///   firewalls and IP accounting. LSM, kprobe, raw-tracepoint and tracing
///   program types are never granted below full wabbit trust — hostile
///   LSM programs would shadow enforcement and tracing programs give an
///   arbitrary-kernel-read primitive.
/// * `BPF_MAP_CREATE` and the `BPF_MAP_*_ELEM` commands: safe because a
///   process can only ever hold fds to maps it created or inherited —
///   the fd-by-ID lookup commands (`BPF_MAP_GET_FD_BY_ID`,
///   `BPF_PROG_GET_FD_BY_ID`) are never granted below full trust, and the
///   bpffs path gate already blocks opening wabbit's pins. Without a fd,
///   wabbit's maps — including the trusted-PID map — are unreachable.
/// * `BPF_PROG_ATTACH`/`BPF_LINK_CREATE` with cgroup-family attach types,
///   plus `BPF_BTF_LOAD`. LSM link creation stays wabbit-only.
///
/// The bit is only as strong as the cgroup walls around it: the
/// cgroup-migration protections must deny moving processes into a cgroup
/// holding this bit, or a rooted attacker joins init.scope by writing to
/// `cgroup.procs` and the class is decorative. For maps that stop needing
/// writes, `BPF_MAP_FREEZE` (kernel 5.2+, every target) is belt-and-braces:
/// a frozen map stays read-only from userspace forever, even against a
/// stolen fd.
pub const ACTION_BPF_ATTACH: u64 = 1 << 6;

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
