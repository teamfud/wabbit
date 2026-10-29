//! The cgroupfs gate — `security_file_open`, the wall around the
//! authorization model.
//!
//! What it denies, in order:
//!
//! 1. **untrusted opens of bpffs files** — reads included. wabbit's pins
//!    live under `/sys/fs/bpf`; with the fd-by-ID lookups never granted
//!    below full trust (the `bpf(2)` gate), closing the pins is what
//!    makes wabbit's maps — including the trust maps — unreachable.
//! 2. **opens under a denied path rule** — the cgroup's own per-cgroup
//!    allow/deny path profile (see [`paths::path_rule_denies`]): a
//!    policy-defined path, denied for reads and writes alike, with
//!    longest-prefix-wins resolution.
//! 3. **writable opens under the module trees** — the plant-a-`.ko`
//!    gate, parity with bnuuy's boot gate, lifted by [`ACTION_KMODS`].
//! 4. **writable opens under protected cgroupfs paths** — the
//!    load-bearing one. `cgroup.procs`, `cgroup.freeze`, `cgroup.kill`:
//!    a rooted attacker must not be able to migrate into a trusted or
//!    authorized cgroup, or freeze or kill one, by writing its files —
//!    or the whole class model is decorative (see
//!    [`ACTION_BPF_ATTACH`]'s documentation). Lifted by
//!    [`ACTION_CGROUPFS_WRITE`].
//!
//! `security_file_open(struct file *file)` runs after `f_mode` is set, so
//! a writable open is visible through it — a denied `open(2)` instead of a
//! deferred failure at first `write(2)`. Reading `f_mode` and `f_path`
//! means reaching into `struct file`, which was reordered mid-series (`see
//! [`paths::file_layout`]`), so the gate exists as `_modern` and `_legacy`
//! program variants and the (later) loader tries them in order: the
//! verifier validates `bpf_d_path`'s argument against the running kernel's
//! BTF, so the variant with the wrong offsets fails to load loudly and the
//! kernel itself picks the right one.
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

/// The gate body, parameterized by the `struct file` layout (see the
/// module docs). Every decision is closed by [`trust::verdict`], which
/// applies the observing/enforcing mode.
#[inline(always)]
fn file_open_body(ctx: &LsmContext, path_offset: usize, mode_offset: usize) -> i32 {
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

    // The cgroup's own path rules (per-cgroup allow/deny profiles; see
    // `paths::path_rule_denies`). Before the writability early-returns:
    // a path rule denies *opens*, so a denied path is denied for reads
    // and writes alike.
    if paths::path_rule_denies(resolved) {
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
    if paths::under_protected_cgroup(resolved) {
        let allowed = trust::current_authorized(ACTION_CGROUPFS_WRITE);
        return trust::verdict(trust::HOOK_FILE_OPEN, if allowed { 0 } else { EPERM });
    }

    trust::verdict(trust::HOOK_FILE_OPEN, 0)
}

/// The cgroupfs gate, for kernels with the modern `struct file` layout
/// (6.8: `f_mode@20`, `f_path@152`). Tried first by the loader.
#[lsm(hook = "file_open", sleepable)]
pub fn file_open_modern(ctx: LsmContext) -> i32 {
    file_open_body(
        &ctx,
        paths::file_layout::MODERN_PATH,
        paths::file_layout::MODERN_MODE,
    )
}

/// The cgroupfs gate, for kernels with the legacy `struct file` layout
/// (5.14–6.1: `f_mode@68`, `f_path@16`). Tried second by the loader.
#[lsm(hook = "file_open", sleepable)]
pub fn file_open_legacy(ctx: LsmContext) -> i32 {
    file_open_body(
        &ctx,
        paths::file_layout::LEGACY_PATH,
        paths::file_layout::LEGACY_MODE,
    )
}
