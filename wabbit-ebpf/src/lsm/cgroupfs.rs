//! The cgroupfs gate — `security_file_open`, the wall around the
//! authorization model.
//!
//! What it denies, in order:
//!
//! 1. **untrusted opens of bpffs files** — reads included. wabbit's pins
//!    live under `/sys/fs/bpf`; with the fd-by-ID lookups never granted
//!    below full trust (the `bpf(2)` gate), closing the pins is what
//!    makes wabbit's maps — including the trust maps — unreachable.
//! 2. **opens the cgroup's path rules deny for the open's operation
//!    class** — the per-cgroup, per-operation (read/write/exec) profile
//!    (see [`paths::path_rule_denies`] and [`paths::PathOp`]): a rule
//!    can block writes and exec under a prefix while reads stay open,
//!    resolution is longest-deciding-prefix-wins per class, and an
//!    operation no rule decides follows the cgroup default.
//! 3. **writable opens under the module trees** — the plant-a-`.ko`
//!    gate, parity with bnuuy's boot gate, lifted by [`ACTION_KMODS`].
//! 4. **writable opens under protected cgroupfs paths** — the
//!    load-bearing one. `cgroup.procs`, `cgroup.freeze`, `cgroup.kill`:
//!    a rooted attacker must not be able to migrate into a trusted or
//!    authorized cgroup, or freeze or kill one, by writing its files —
//!    or the whole class model is decorative (see
//!    [`ACTION_BPF_ATTACH`]'s documentation). Lifted by
//!    [`ACTION_CGROUPFS_WRITE`] for outsiders, and by nothing for the
//!    yard's own insiders: a caller whose cgroup *is* the protected
//!    cgroup it writes below manages its own subtree (systemd's unit
//!    children re-attach from inside the unit cgroup PID 1 already moved
//!    them into; its daemons move their workers into sub-cgroups under
//!    it), and an insider of one yard is still an outsider of every
//!    other.
//!
//! `security_file_open(struct file *file)` runs after `f_mode` is set, so
//! a writable open is visible through it — a denied `open(2)` instead of a
//! deferred failure at first `write(2)`. The same holds for the execve
//! marker: `do_open_execat` hands `do_filp_open` the open flags
//! `O_RDONLY | O_LARGEFILE | __FMODE_EXEC` (0x20), which `alloc_empty_file`
//! → `init_file` copies into `f_flags` before the hook runs — while
//! `OPEN_FMODE` (which fills `f_mode`) maps only `O_ACCMODE`, and
//! `VALID_OPEN_FLAGS` excludes 0x20, so `f_flags & 0x20` is a marker no
//! userspace `open(2)` can counterfeit. Reading `f_mode`, `f_flags`, and
//! `f_path` means reaching into `struct file`, which was reordered
//! mid-series (`see [`paths::file_layout`]`), so the gate exists as
//! `_modern` and `_legacy` program variants and the (later) loader tries
//! them in order: the verifier validates `bpf_d_path`'s argument against
//! the running kernel's BTF, so the variant with the wrong offsets fails
//! to load loudly and the kernel itself picks the right one.
//!
//! `file_open` is sleepable on every kernel in the target matrix — the
//! one path-resolving hook that needs no variant of *loadability*.

use aya_ebpf::{bindings, helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use wabbit_common::authorization::{ACTION_CGROUPFS_WRITE, ACTION_KMODS};

use crate::lsm::{
    paths,
    trust::{self, EPERM},
};

/// `FMODE_WRITE`, the `f_mode` bit of a writable open.
const FMODE_WRITE: u32 = 1 << 1;

/// `__FMODE_EXEC` (0x20), the execve marker `do_open_execat` carries in
/// the open flags — `f_flags`, never `f_mode` (`OPEN_FMODE` cannot put
/// it there) and never a userspace-settable bit (`VALID_OPEN_FLAGS`
/// excludes it). An `f_flags` read that fails cannot tell exec from
/// read; the open falls to the read class — fail-open, the house rule
/// for a protection whose failure mode must never be a wedged system.
const FMODE_EXEC: u32 = 0x20;

/// The gate body, parameterized by the `struct file` layout (see the
/// module docs). Every decision is closed by [`trust::verdict`], which
/// applies the observing/enforcing mode.
#[inline(always)]
fn file_open_body(
    ctx: &LsmContext,
    path_offset: usize,
    mode_offset: usize,
    flags_offset: usize,
) -> i32 {
    // LSM_HOOK(int, 0, file_open, struct file *file)
    // The phony retval (index 1) is read exactly once, first — see
    // kmod.rs for the verifier bug that motivates the shape.
    let retval = ctx.arg::<i32>(1);
    if retval != 0 {
        return retval;
    }
    if trust::trusted() {
        return 0;
    }

    let file = ctx.arg::<*mut bindings::file>(0);
    let mode = unsafe {
        bpf_probe_read_kernel((file as *const u8).wrapping_add(mode_offset) as *const u32)
    };
    let flags = unsafe {
        bpf_probe_read_kernel((file as *const u8).wrapping_add(flags_offset) as *const u32)
    };
    // One buffer shared by every path check in this hook (see `paths`).
    let mut buffer = [0u8; paths::PATH_BUFFER_SIZE];

    let Some(resolved) =
        (unsafe { paths::resolve(paths::file_path_ptr(file, path_offset), &mut buffer) })
    else {
        // No path, no verdict — and no denial: an unresolvable open is not
        // one of the protected classes, and fail-open is the house rule for
        // a protection whose failure mode must never be a wedged system.
        return 0;
    };

    // The pins: any untrusted open of bpffs is denied, reads included.
    if paths::is_bpffs_path(resolved) {
        return trust::verdict(trust::HOOK_FILE_OPEN, EPERM);
    }

    // The cgroup's path rules (per-cgroup, per-operation profiles; see
    // `paths::path_rule_denies`). The open's operation class — exec
    // first (the kernel's own marker), then writability, then read —
    // picks the verdict: a rule can deny writes and exec under a
    // prefix while reads of it stay open. An unreadable `f_mode` or
    // `f_flags` cannot tell the classes apart, and the open falls to
    // read — the same fail-open as an unresolvable path.
    let op = if flags.map_or(false, |flags| flags & FMODE_EXEC != 0) {
        paths::PathOp::Exec
    } else if mode.map_or(false, |mode| mode & FMODE_WRITE != 0) {
        paths::PathOp::Write
    } else {
        paths::PathOp::Read
    };
    if paths::path_rule_denies(resolved, op) {
        return trust::verdict(trust::HOOK_FILE_OPEN, EPERM);
    }

    let Ok(mode) = mode else {
        // `f_mode` unreadable: the gate cannot tell writability, and a
        // read-only open is harmless by definition. Allow.
        return 0;
    };
    if mode & FMODE_WRITE == 0 {
        return 0;
    }

    // The module trees: planting into the real tree.
    if paths::is_modules_path(resolved) {
        let allowed = trust::current_authorized(ACTION_KMODS);
        return trust::verdict(trust::HOOK_FILE_OPEN, if allowed { 0 } else { EPERM });
    }

    // The protected cgroupfs paths: the cgroup.procs/freeze/kill wall.
    // An outsider needs `ACTION_CGROUPFS_WRITE` (PID 1's unit management
    // runs from init.scope, which holds it). The yard itself does not:
    // its own processes — the unit's children and daemons, already
    // attached into the unit cgroup by PID 1 — open `cgroup.procs` in
    // their *own* subtree (their own re-attach, their worker sub-cgroups)
    // as housekeeping, and denying that kills the unit at EXIT_CGROUP
    // (systemd's children migrate from inside the unit's cgroup; its
    // daemons run in worker sub-cgroups under it), which in turn makes
    // systemd delete and recreate the cgroup with a fresh kernfs id on
    // every retry. [`trust::inside_yard`] decides which case this open
    // is; an insider of one yard is still an outsider of every other.
    if let Some(yard) = paths::under_protected_yard(resolved) {
        let allowed =
            trust::current_authorized(ACTION_CGROUPFS_WRITE) || trust::inside_yard(yard);
        return trust::verdict(trust::HOOK_FILE_OPEN, if allowed { 0 } else { EPERM });
    }

    trust::verdict(trust::HOOK_FILE_OPEN, 0)
}

/// The cgroupfs gate, for kernels with the modern `struct file` layout
/// (6.8: `f_mode@20`, `f_flags@72`, `f_path@152`). Tried first by the
/// loader.
#[lsm(hook = "file_open", sleepable)]
pub fn file_open_modern(ctx: LsmContext) -> i32 {
    file_open_body(
        &ctx,
        paths::file_layout::MODERN_PATH,
        paths::file_layout::MODERN_MODE,
        paths::file_layout::MODERN_FLAGS,
    )
}

/// The cgroupfs gate, for kernels with the legacy `struct file` layout
/// (5.14–6.1: `f_mode@68`, `f_flags@64`, `f_path@16`). Tried second by
/// the loader.
#[lsm(hook = "file_open", sleepable)]
pub fn file_open_legacy(ctx: LsmContext) -> i32 {
    file_open_body(
        &ctx,
        paths::file_layout::LEGACY_PATH,
        paths::file_layout::LEGACY_MODE,
        paths::file_layout::LEGACY_FLAGS,
    )
}
