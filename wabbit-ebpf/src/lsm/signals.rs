//! The signal gate — `task_kill`, the sketch's
//! `allow_signaling_other_cgroups` made honest.
//!
//! What the sketch wanted — "may this cgroup signal *that* cgroup" —
//! needs the *target's* cgroup id, and reading it means walking
//! `task_struct` → `css_set` → `cgroup`: the exact class of deep,
//! `__randomize_layout`-unstable struct walks this design forbids (the
//! fork-watcher's distro-patched tracepoint record is the measured
//! lesson: wrong offsets there fail *silently*). So the implemented
//! semantic is the one the identity alone can afford:
//!
//! * **self-signals always pass** — `raise(3)`, `kill(getpid())`, a
//!   thread exiting itself: the target `task_struct` *is* the current
//!   one;
//! * **`SIGCONT` always passes** — it is the thaw channel: every rescue
//!   path (the handoff resume, the `FrozenWorld` drop backstop, the
//!   watchdog's sweep) is a SIGCONT broadcast from whatever cgroup the
//!   rescue happens to run in, and the failure-safety contract — a
//!   frozen world never outlives a failed wabbit-initrd — outranks any
//!   signaling containment. A resumeable process is an operator
//!   convenience, not a boundary: stopping is not jailing.
//! * **every other signal** — same cgroup, other cgroup, wabbit's own
//!   processes, PID 1 — requires [`ACTION_SIGNAL_OTHERS`] **on cgroups
//!   the policy lists**. The posture is default-allow: a cgroup with no
//!   `Authorization` entry may signal (the unlisted world of a boot —
//!   initramfs units, session scopes — never loses `kill(2)` to a
//!   boundary nobody drew); a listed cgroup gets exactly its bits, so
//!   the operator who names a cgroup chooses whether it may signal
//!   (class runs are listed by construction — their containment is the
//!   point).
//!
//! The self-exemption is the one comparison the design can make without
//! touching `task_struct` memory: **pointer identity, as scalars**. The
//! eBPF verifier prohibits pointer comparisons in every form (PTR vs
//! PTR *and* PTR vs scalar — `is_pointer_value` on either side,
//! verified against the 5.14 and 6.8 verifier sources), so the gate
//! never compares the pointer types at all: it `bpf_probe_read_kernel`s
//! the raw argument bits out of the program's own BTF context (a
//! laundered scalar copy — the same read every `arg::<primitive>` in
//! this crate does under aya's `btf_arg`), and compares them against
//! `bpf_get_current_task()`'s return — an integer by the helper's own
//! prototype (`bpf_get_current_task_btf` is the pointer-typed variant,
//! deliberately not used). Scalar against scalar: no dereference of
//! either side, no layout dependence, loadable on every target kernel.
//!
//! Deny-by-default here is real containment — the processes that never
//! needed `kill(2)` lose it entirely — but it is also why the bit must
//! be granted where process management is legitimate: PID 1's unit
//! management, udev's worker pool, a shell's job control. The starter
//! policy carries the boot-critical grants.
//!
//! # Residuals
//!
//! * **same-cgroup signaling is not distinguished** — a cgroup holding
//!   the bit may signal anything, including outside itself and
//!   including wabbit's own processes (before this gate, that was every
//!   process's residual; now it is the *authorized* processes' — the
//!   signer's trade, the same shape as every other bit here).
//! * **kernel-internal kills** — `kernel_send_sig*` paths bypass the
//!   LSM hook by design (the OOM killer, module loaders' cleanup); no
//!   userspace gate could or should stand in their way.

use aya_ebpf::{
    EbpfContext as _,
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use wabbit_common::authorization::ACTION_SIGNAL_OTHERS;

use crate::lsm::trust::{self, EPERM};

/// Deny signaling any task other than the caller's own (see the module
/// docs).
///
/// `SIGCONT` (19), from `uapi/linux/signal.h`: the thaw channel, always
/// exempt (see the module docs).
const SIGCONT: i32 = 19;

/// `security_task_kill(p, info, sig, cred)` — the target task is arg 0,
/// and only its *identity* is consulted: the raw argument bits against
/// `bpf_get_current_task()`, both scalars, no `task_struct` field is
/// ever read. Phony retval at index 4, read once, first.
#[lsm(hook = "task_kill")]
pub fn signal_gate(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, task_kill, struct task_struct *p,
    //          struct kernel_siginfo *info, int sig,
    //          const struct cred *cred) — the phony retval is index 4.
    //
    // The phony retval is read once, first, and *compared* before any
    // other context read — the verifier shape (see kmod.rs), and it is
    // load-bearing in both directions, measured on the matrix:
    //
    // * comparing `sig` *before* the retval breaks the slot patching on
    //   RHEL 9's 5.14 verifier — the exemption silently never fired and
    //   the initrd stayed frozen;
    // * but the slot itself is leftover caller register state, and on a
    //   *stacked* LSM list (rocky's stock
    //   `lockdown,capability,yama,selinux,bpf`) it holds the previous
    //   hook's leftovers — nonzero, target-dependent — so consulting it
    //   before the unconditional passes denies the boot's own thaw.
    //
    // So: the two reads and the two comparisons come first, in the
    // house order (retval, compare, sig, compare), and the stale
    // upstream verdict is only consulted *after* the two callers no
    // gate may ever refuse: SIGCONT (the thaw channel) and the
    // trusted.
    let retval = ctx.arg::<i32>(4);
    let denied_upstream = retval != 0;
    if ctx.arg::<i32>(2) == SIGCONT {
        // The thaw channel outranks everything: every rescue path —
        // the handoff resume, the drop backstop, the watchdog — is a
        // SIGCONT sweep, from whatever cgroup the rescue lands in, and
        // a frozen world must never outlive a failed boot.
        return 0;
    }
    if trust::trusted() {
        return 0;
    }
    if denied_upstream {
        return retval;
    }
    // The target's raw bits, laundered into a scalar: `arg::<*mut _>`
    // would keep the register's PTR_TO_BTF_ID provenance (the type the
    // verifier assigns by position, whatever the program claims), and a
    // pointer on either side of a comparison is a load-time rejection —
    // so this reads the context's own argument slot, exactly as aya's
    // `btf_arg` does for primitives, through `bpf_probe_read_kernel`.
    // `LsmContext::as_ptr` is the BTF context's argument array; arg 0
    // is its first slot.
    let slot = ctx.as_ptr() as *const u64;
    let Ok(target) = (unsafe { bpf_probe_read_kernel::<u64>(slot.cast()) }) else {
        // The one read cannot fail for the program's own context — but
        // a hypothetical failure must not wedge the machine's ability
        // to raise(3): fail-open, the house rule.
        return 0;
    };
    if target == unsafe { bpf_get_current_task() } {
        // The one target every cgroup may always reach: itself.
        return 0;
    }
    // The default-allow posture: an *unlisted* cgroup may signal any
    // task (the operator never drew a boundary around it), while a
    // listed one gets exactly its bits — the starter policy's grants
    // stay meaningful, and a listed cgroup without `signal` is the
    // containment the operator asked for.
    let allowed = trust::current_authorized_or_unlisted(ACTION_SIGNAL_OTHERS);
    trust::verdict(trust::HOOK_TASK_KILL, if allowed { 0 } else { EPERM })
}
