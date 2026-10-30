//! Trust and authorization primitives, shared by every gate.
//!
//! Three identities a gate can act on, in order of how much they carry:
//!
//! * a **trusted PID** (`TRUSTED_PIDS`) — wabbit's own process. The
//!   boot-time model: inherited from wabbit-initrd's grant, lost on fork,
//!   spoofable by PID reuse. Gates check it first because wabbit itself
//!   must never be gated by its own protections.
//! * a **trusted cgroup** (`TRUSTED_CGROUPS`) — wabbit's own cgroup.
//!   Membership is inherited at fork and survives the whole process tree;
//!   the cgroup-migration protections are what keep an attacker from
//!   joining it, so this is the real boundary.
//! * an **authorization** (`AUTHORIZATIONS`) — a per-cgroup action mask.
//!   The systemd class ([`ACTION_BPF_ATTACH`]), module loading
//!   ([`ACTION_KMODS`]), cgroupfs writes ([`ACTION_CGROUPFS_WRITE`]),
//!   firewall changes ([`ACTION_FIREWALL`]) — each gate consults its own
//!   bit, and nothing else.
//!
//! Every gate also consults [`ENFORCING`]: while it reads `0` the gate
//! traces its decision into [`DECISIONS`] and allows, which is the
//! observing self-test phase of the startup diagram ("i am active but not
//! enforcing"); the flip to `1` is what turns the denials on.

use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid};
#[rustfmt::skip]
pub use wabbit_common::authorization::{
    CODE_ALLOWED, CODE_WOULD_DENY, CgroupKey, DEFAULT_CGROUP_ID, ENFORCE, HOOK_BPF, HOOK_BIND,
    HOOK_FILE_OPEN, HOOK_KMOD, HOOK_SB_MOUNT, HOOK_SETSOCKOPT, HOOK_SOCKET_CREATE,
    HOOK_TASK_KILL, OBSERVE, decision_key,
};
use wabbit_common::authorization::Authorization;

use crate::maps::{
    AUTHORIZATIONS, DECISIONS, ENFORCING, PROTECTED_PATHS, TRUSTED_CGROUPS, TRUSTED_PIDS,
};

/// Deny, as every gate in this crate does: `EPERM`.
pub const EPERM: i32 = -1;

/// Record that this gate reached a decision point. A `BPF_ANY` insert
/// marks the code as hit — never counted, see [`DECISIONS`].
#[inline(always)]
pub fn trace(hook: u32, code: u32) {
    let _ = DECISIONS.insert(decision_key(hook, code), 1, 0);
}

/// Is the enforcing mode armed? Read per decision — the flip is racy by
/// design (observability first, atomicity of the mode itself is never
/// load-bearing: a decision made mid-flip is either logged or enforced).
#[inline(always)]
pub fn enforcing() -> bool {
    ENFORCING.get(0).copied().unwrap_or(0) != 0
}

/// The current task's pid (not the tgid's: the task that made the call).
#[inline(always)]
pub fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// Is the current task's PID trusted (wabbit itself)?
#[inline(always)]
pub fn pid_trusted() -> bool {
    unsafe { TRUSTED_PIDS.get(&current_pid()) }.is_some()
}

/// The current task's cgroup key, as `bpf_get_current_cgroup_id` reports
/// it. The value is the kernfs id of the cgroupfs directory — the same id
/// `stat(2)` reports as `st_ino` — so the userspace keying a trusted
/// cgroup and this lookup agree without any shared constant.
#[inline(always)]
pub fn current_cgroup() -> CgroupKey {
    CgroupKey {
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
    }
}

/// Is `cgroup` a trusted cgroup?
#[inline(always)]
pub fn cgroup_trusted(cgroup: &CgroupKey) -> bool {
    unsafe { TRUSTED_CGROUPS.get(cgroup) }.is_some()
}

/// Full trust: a trusted PID (wabbit itself) or a trusted cgroup. Gates
/// allow these before consulting anything else — wabbit must never be
/// gated by its own protections, and the `file_open` cgroupfs wall exempts
/// the trusted so the loader can still administer the hierarchy.
#[inline(always)]
pub fn trusted() -> bool {
    pid_trusted() || cgroup_trusted(&current_cgroup())
}

/// The entry that governs `cgroup`: its own, or — for a cgroup with no
/// entry — the policy's default (keyed [`DEFAULT_CGROUP_ID`]), along
/// with the id its `PATH_RULES` are keyed under. `None` when neither
/// exists: the unlisted floor (no bits, no rules).
#[inline(always)]
pub fn governing(cgroup: &CgroupKey) -> Option<(u64, &'static Authorization)> {
    if let Some(authorization) = unsafe { AUTHORIZATIONS.get(cgroup) } {
        return Some((cgroup.cgroup_id, authorization));
    }
    let default = CgroupKey {
        cgroup_id: DEFAULT_CGROUP_ID,
    };
    unsafe { AUTHORIZATIONS.get(&default) }.map(|authorization| (DEFAULT_CGROUP_ID, authorization))
}

/// Does `cgroup` hold the authorization `action` — through its own entry,
/// or the default's when it has none?
#[inline(always)]
pub fn authorized(cgroup: &CgroupKey, action: u64) -> bool {
    match governing(cgroup) {
        Some((_, authorization)) => authorization.action_mask & action != 0,
        None => false,
    }
}

/// Does the *current* cgroup hold the authorization `action`?
#[inline(always)]
pub fn current_authorized(action: u64) -> bool {
    authorized(&current_cgroup(), action)
}

/// Does the current cgroup hold `action`, or have no `Authorization`
/// entry at all? The signals gate's **default-allow** posture: an
/// unlisted cgroup may signal (the whole unlisted world of a boot —
/// initramfs units, session scopes — must never lose `kill(2)` to a
/// boundary nobody drew), while a *listed* cgroup gets exactly its
/// bits — the operator names the cgroup, the operator chose its
/// actions. The policy's default entry is deliberately *not* consulted:
/// an unlisted cgroup stays unlisted here.
#[inline(always)]
pub fn current_authorized_or_unlisted(action: u64) -> bool {
    match unsafe { AUTHORIZATIONS.get(&current_cgroup()) } {
        Some(authorization) => authorization.action_mask & action != 0,
        None => true,
    }
}

/// Is `path` (already hashed by the caller, with
/// `wabbit_common::authorization::path_hash`) a protected cgroupfs path?
/// See [`PROTECTED_PATHS`] for the key convention.
#[inline(always)]
pub fn protected(path: u64) -> bool {
    unsafe { PROTECTED_PATHS.get(&path) }.is_some()
}

/// Close a gate's decision: trace it, then apply the mode.
///
/// Every gate ends in this call. The trace records what the rules decided
/// — allow ([`CODE_ALLOWED`]) or deny ([`CODE_WOULD_DENY`]) — regardless
/// of mode, so the observing self-test phase and the enforcing re-test see
/// the same decision stream; in observing mode a deny is traced and then
/// *not applied* ("i'm active but not enforcing"). Trusted callers
/// short-circuit before their gate's rules and never reach this.
#[inline(always)]
pub fn verdict(hook: u32, decision: i32) -> i32 {
    if decision == 0 {
        trace(hook, CODE_ALLOWED);
    } else {
        trace(hook, CODE_WOULD_DENY);
    }
    if !enforcing() && decision != 0 {
        return 0;
    }
    decision
}
