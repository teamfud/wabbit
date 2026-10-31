//! The classed `bpf(2)` gate.
//!
//! `security_bpf(int cmd, union bpf_attr *attr, unsigned int size)` runs
//! for every `bpf(2)` syscall — before the command executes, whatever the
//! command. The gate is *classed* (see `ACTION_BPF_ATTACH` and
//! `ACTION_BPF_FULL` in `wabbit-common`, the design documented there):
//!
//! * **trusted** (wabbit's PID or cgroup): everything allowed. wabbit must
//!   never be gated by its own protections — it loads these programs.
//! * **the full class** ([`ACTION_BPF_FULL`] on the cgroup): every
//!   command, every program type, every attach type — unfiltered. The
//!   policy signer who grants it is choosing that the cgroup can reach
//!   anything `bpf(2)` reaches, wabbit's own maps included (the
//!   fd-by-ID lookups); the bpffs *open* gate still holds, because
//!   `file_open` is a separate hook and pins are path-shaped.
//! * **the systemd class** ([`ACTION_BPF_ATTACH`] on the cgroup): the
//!   restricted command set a system-management daemon needs — map creates
//!   and element operations (a process can only ever hold fds to maps it
//!   created or inherited), program loads for the cgroup family, program
//!   attaches and link creates with cgroup-family attach types, and BTF
//!   loads. The dangerous things never relax below the full class: the
//!   fd-by-ID lookups (`BPF_MAP_GET_FD_BY_ID`, `BPF_PROG_GET_FD_BY_ID`) are
//!   the only route to wabbit's maps that bypasses bpffs, and LSM and
//!   tracing program types would shadow enforcement or read kernel memory.
//! * **everyone else**: denied, `EPERM`.
//!
//! `cmd` (argument 0) and `attr` (argument 1) are stable across every
//! target kernel's hook layout — verified against the 5.14 and 6.8
//! sources — so the gate reads them directly. The phony *retval* argument
//! is deliberately unread: mainline grew a fourth `bool kernel` parameter
//! after 6.8, which shifts it, and the cost of not reading it is only that
//! a denial replaces an earlier LSM's errno with `EPERM` (the denial
//! itself is identical). Not reading the retval loads everywhere.
//!
//! The union's front matter the gate probes is UAPI-stable: `prog_type`
//! sits at offset 0 of the load command's struct (every kernel since the
//! union gained `expected_attach_type`), and `attach_type` at offset 8 of
//! both the attach and link-create structs.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use wabbit_common::authorization::{ACTION_BPF_ATTACH, ACTION_BPF_FULL};

use crate::lsm::trust::{self, EPERM};

/// `enum bpf_cmd` values, from `uapi/linux/bpf.h`. The enum is
/// append-only UAPI; every value below predates the oldest target kernel
/// (`BPF_LINK_CREATE` is 5.7).
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_BTF_LOAD: u32 = 18;
const BPF_MAP_LOOKUP_AND_DELETE_ELEM: u32 = 21;
const BPF_LINK_CREATE: u32 = 28;

/// Offsets into `union bpf_attr`'s per-command structs (UAPI-stable front
/// matter, see the module docs).
const ATTR_PROG_TYPE: usize = 0;
const ATTR_ATTACH_TYPE: usize = 8;

/// The `enum bpf_prog_type` values of the cgroup family — exactly the set
/// `ACTION_BPF_ATTACH`'s documentation names. `BPF_PROG_TYPE_LSM`,
/// `TRACING`, kprobe, raw-tracepoint and tracepoint types are *not* here:
/// an LSM program would shadow enforcement, a tracing program is an
/// arbitrary-kernel-read primitive, and both stay out of the systemd class
/// (`ACTION_BPF_FULL` grants them by definition — "unfiltered").
const CLASS_PROG_TYPES: &[u32] = &[
    1,  // SOCKET_FILTER
    8,  // CGROUP_SKB
    9,  // CGROUP_SOCK
    13, // SOCK_OPS
    15, // CGROUP_DEVICE
    18, // CGROUP_SOCK_ADDR
    25, // CGROUP_SOCKOPT
];

/// The `enum bpf_attach_type` values of the cgroup family (every
/// `BPF_CGROUP_*` value: ingress/egress, sock create, sock ops, device,
/// bind/connect/post-bind for v4 and v6, udp sendmsg/recvmsg, sysctl,
/// getsockopt/setsockopt, getpeername/getsockname, sock release). The
/// `BPF_TRACE_*`, `BPF_MODIFY_RETURN`, `BPF_LSM_*` and sockmap values are
/// *not* here — LSM link creation stays out of the systemd class
/// (`ACTION_BPF_FULL` grants it).
#[inline(always)]
fn is_class_attach_type(attach_type: u32) -> bool {
    matches!(
        attach_type,
        0..=3        // INET_INGRESS, INET_EGRESS, INET_SOCK_CREATE, CGROUP_SOCK_OPS
            | 6      // CGROUP_DEVICE
            | 8..=15 // INET4/6_BIND, INET4/6_CONNECT, INET4/6_POST_BIND, UDP4/6_SENDMSG
            | 18..=22 // CGROUP_SYSCTL, UDP4/6_RECVMSG, GETSOCKOPT, SETSOCKOPT
            | 29..=32 // INET4/6_GETPEERNAME, INET4/6_GETSOCKNAME
            | 34     // INET_SOCK_RELEASE
    )
}

/// A `u32` field out of the `bpf(2)` attribute union, or `None` if the
/// kernel memory cannot be probed (the gate then fails closed).
#[inline(always)]
fn attr_u32(attr: *mut u8, offset: usize) -> Option<u32> {
    unsafe { bpf_probe_read_kernel(attr.wrapping_add(offset) as *const u32) }.ok()
}

/// The classed `bpf(2)` gate (see the module docs).
///
/// Deliberately reads `cmd` and `attr` but never the phony trailing
/// retval: see the module docs for why that loads on every target kernel.
#[lsm(hook = "bpf")]
pub fn bpf_gate(ctx: LsmContext) -> i32 {
    if trust::trusted() {
        return 0;
    }
    let cmd = ctx.arg::<u32>(0);
    let attr = ctx.arg::<*mut u8>(1);
    // The full class first: ACTION_BPF_FULL permits every command,
    // unfiltered — the class check below is the systemd class's.
    let allowed = trust::current_authorized(ACTION_BPF_FULL) || class_allows(cmd, attr);
    trust::verdict(trust::HOOK_BPF, if allowed { 0 } else { EPERM })
}

/// Does the current cgroup's [`ACTION_BPF_ATTACH`] class permit `cmd`?
/// (The `ACTION_BPF_FULL` class permits every command and never reaches
/// here — the gate checks it first.)
#[inline(always)]
fn class_allows(cmd: u32, attr: *mut u8) -> bool {
    if !trust::current_authorized(ACTION_BPF_ATTACH) {
        return false;
    }
    match cmd {
        // Map creation and element operations — safe because a process
        // can only ever hold fds to maps it created or inherited: without
        // the fd-by-ID lookups (never granted in the class) and the bpffs
        // pins (walled by the `file_open` gate), wabbit's own maps are
        // unreachable from here.
        BPF_MAP_CREATE
        | BPF_MAP_LOOKUP_ELEM
        | BPF_MAP_UPDATE_ELEM
        | BPF_MAP_DELETE_ELEM
        | BPF_MAP_GET_NEXT_KEY
        | BPF_MAP_LOOKUP_AND_DELETE_ELEM => true,
        // A BTF object is loadable but carries no executable program.
        BPF_BTF_LOAD => true,
        // Program loads, restricted to the cgroup family — an LSM or
        // tracing program must never load below full trust.
        BPF_PROG_LOAD => attr_u32(attr, ATTR_PROG_TYPE)
            .map(|prog_type| CLASS_PROG_TYPES.contains(&prog_type))
            .unwrap_or(false),
        // Attaches and links, restricted to cgroup-family attach types.
        BPF_PROG_ATTACH | BPF_PROG_DETACH | BPF_LINK_CREATE => attr_u32(attr, ATTR_ATTACH_TYPE)
            .map(is_class_attach_type)
            .unwrap_or(false),
        // Everything else — pins, fd-by-ID lookups, freezes, raw
        // tracepoints, iteration, stats — is `ACTION_BPF_FULL` only
        // (full trust permits it too, before this function is reached).
        _ => false,
    }
}
