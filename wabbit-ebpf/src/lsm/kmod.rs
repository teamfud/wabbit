//! The kernel-module load gate.
//!
//! `finit_module(2)` and `init_module(2)` both reach the loader through
//! `kernel_read_file_from_fd`, which consults
//! `security_kernel_read_file(file, id, contents)` *before* the module
//! loader reads a byte: denying there costs the caller an `EPERM` and
//! nothing else. `id == READING_MODULE` is the module case; the same hook
//! fires for firmware and kexec images, which pass through untouched.
//!
//! Unlike bnuuy's boot gate this resolves **no path** — on purpose. A
//! `bpf_d_path` allowlist needs the *sleepable* `kernel_read_file` hook,
//! and that exists only on bookworm (6.1) and later plus RHEL's backports
//! (rocky): vanilla 5.15 — jammy — is not in the sleepable set. The plain
//! hook exists on every kernel in the matrix, so the identity-keyed gate
//! loads on all four distros where the path-based variant would not. The
//! trade is documented in `ACTION_KMODS`: in-tree loads are not
//! distinguished here — a cgroup either holds the bit or it may not load
//! modules at all. Post-boot, module loads are package-manager business,
//! and the cgroups those run in are wabbit's to authorize explicitly.

use aya_ebpf::{macros::lsm, programs::LsmContext};
use wabbit_common::authorization::ACTION_KMODS;

use crate::lsm::trust::{self, EPERM};

/// `READING_MODULE`, from `enum kernel_read_file_id`: 2 on every target
/// kernel (the enum has carried a leading `READING_UNKNOWN` entry since
/// before 5.14 — verified against the matrix).
const READING_MODULE: i32 = 2;

/// Deny module loads for every cgroup without [`ACTION_KMODS`].
#[lsm(hook = "kernel_read_file")]
pub fn kmod_gate(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, kernel_read_file, struct file *file,
    //          enum kernel_read_file_id id, bool contents)
    // The phony retval (index 3, behind the three real arguments) is read
    // exactly once, before anything else — re-reading it after a loop of
    // comparisons trips the 6.8 verifier's register-invariant check.
    let retval = ctx.arg::<i32>(3);
    if retval != 0 {
        return retval;
    }
    let id = ctx.arg::<i32>(1);
    if id != READING_MODULE {
        return 0;
    }
    if trust::trusted() {
        return 0;
    }
    let allowed = trust::current_authorized(ACTION_KMODS);
    trust::verdict(trust::HOOK_KMOD, if allowed { 0 } else { EPERM })
}
