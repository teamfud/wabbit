//! The mount gate — `security_sb_mount`, the `mount(2)` LSM hook.
//!
//! What it denies for untrusted cgroups:
//!
//! * **mounts over the module trees** — an attacker must not shadow
//!   `/lib/modules` with their own tree and rehearse a path the
//!   module-load gate would reject. Never lifted by an action bit.
//! * **mounts over bpffs** — the pins again; shadowing `/sys/fs/bpf`
//!   with a writable fs would hand an attacker an editable view of the
//!   protection's own store. Never lifted by an action bit.
//! * **mounts over the cgroupfs root** — a fresh hierarchy mounted over
//!   `/sys/fs/cgroup` hides the real one from every later open. (It
//!   cannot forge cgroup *identity* — `bpf_get_current_cgroup_id`
//!   reports kernfs ids of the real hierarchy regardless of mounts — but
//!   the visibility lie is worth denying.) Lifted by [`ACTION_MOUNT`].
//! * **mounts over protected cgroup paths** — mounting over
//!   `/sys/fs/cgroup/wabbit` itself, or any authorized child. Lifted by
//!   [`ACTION_MOUNT`].
//!
//! Everything else is allowed: a booted system mounts constantly
//! (automounts, fstab late mounts, container runtimes), and a blanket
//! mount-deny for every untrusted cgroup would break more than it
//! protects. [`ACTION_MOUNT`] is the reference model's blanket grant —
//! wabbit keeps it for the paths that matter.
//!
//! `sb_mount` is sleepable on every kernel in the target matrix, so the
//! one path-resolving shape needs no loadability variants. The
//! unmount-side companions (`move_mount`, `umount`) are documented
//! residuals: neither hook is in any matrix kernel's sleepable set, so no
//! path-resolving protection can exist there.

use aya_ebpf::{bindings, macros::lsm, programs::LsmContext};
use wabbit_common::authorization::ACTION_MOUNT;

use crate::lsm::{
    paths,
    trust::{self, EPERM},
};

/// A `sb_mount`-local decision code, so a failed self-test can tell "the
/// gate fired and resolved a path" (code 0/1) from "the gate fired but
/// `bpf_d_path` failed" (this code) from "the hook never ran" (no key at
/// all). See `trust::verdict` for the code layout.
const SB_MOUNT_UNRESOLVED: u32 = 2;

/// The mount gate (see the module docs).
///
/// Deliberately reads no phony retval, unlike the other gates:
/// `security_sb_mount` takes five real arguments (dev_name, path, type,
/// flags, data), so the trampoline's retval slot is the sixth register —
/// never written by the call, and the first lab runs measured it as
/// garbage rather than zero, which made the gate silently return that
/// garbage on every invocation ("attached but never decided"). The
/// `bpf` gate in bnuuy carries the same trade's documentation: where an
/// earlier LSM already denied the call, this gate's verdict replaces
/// its errno — a denial stays a denial; on an allow it may re-allow what
/// a prior LSM denied, which is the documented cost of not reading an
/// argument that cannot be read soundly.
#[lsm(hook = "sb_mount", sleepable)]
pub fn sb_mount(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, sb_mount, const char *dev_name,
    //          const struct path *path, const char *type,
    //          unsigned long flags, void *data)
    if trust::trusted() {
        // Trusted callers short-circuit without a verdict, so the trace is
        // the only record they leave — without it, a hook-4 absence could
        // still mean "silently allowed as trusted" instead of "never ran".
        trust::trace(trust::HOOK_SB_MOUNT, 5);
        return 0;
    }

    let mut buffer = [0u8; paths::PATH_BUFFER_SIZE];
    let target = ctx.arg::<*mut bindings::path>(1);
    let Some(resolved) = (unsafe { paths::resolve(target, &mut buffer) }) else {
        // The resolution failure is a decision point in its own right: it
        // distinguishes "the gate ran but could not read the target" from
        // "the gate never ran" in the DECISIONS dump (see
        // SB_MOUNT_UNRESOLVED). Fail-open per the house rule.
        trust::trace(trust::HOOK_SB_MOUNT, SB_MOUNT_UNRESOLVED);
        return 0;
    };
    // The gate ran and resolved a path: trace code 3, unconditionally, so
    // a failed self-test can prove the trampoline invoked the program at
    // all — no other code can appear without this one having run.
    trust::trace(trust::HOOK_SB_MOUNT, 3);

    // Never-lifted walls: the module trees and the pins.
    if paths::is_modules_path(resolved) {
        return trust::verdict(trust::HOOK_SB_MOUNT, EPERM);
    }
    if paths::is_bpffs_path(resolved) {
        return trust::verdict(trust::HOOK_SB_MOUNT, EPERM);
    }

    // The cgroupfs: the root and the protected paths, lifted by ACTION_MOUNT.
    if paths::is_cgroupfs_root(resolved) || paths::under_protected_cgroup(resolved) {
        let allowed = trust::current_authorized(ACTION_MOUNT);
        return trust::verdict(trust::HOOK_SB_MOUNT, if allowed { 0 } else { EPERM });
    }

    0
}
