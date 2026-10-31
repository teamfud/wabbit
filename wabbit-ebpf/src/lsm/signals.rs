//! The signal gate — `task_kill`, the sketch's
//! `allow_signaling_other_cgroups` made honest, plus the self-guard that
//! keeps wabbit itself from being killed by outside processes.
//!
//! What the sketch wanted — "may this cgroup signal *that* cgroup" —
//! needs the *target's* cgroup id, and reading it means walking
//! `task_struct` → `css_set` → `cgroup`: deep struct walks this design
//! forbids *as compile-time guesses* (the fork-watcher's distro-patched
//! tracepoint record is the measured lesson: a wrong hardcoded offset
//! fails *silently* and reads garbage). So the implemented semantics are
//! the ones identity alone can afford:
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
//! * **every other signal** — same cgroup, other cgroup, PID 1's
//!   targets, wabbit's own processes — requires
//!   [`ACTION_SIGNAL_OTHERS`] **on cgroups the policy lists**. The
//!   posture is default-allow: a cgroup with no `Authorization` entry
//!   may signal (the unlisted world of a boot — initramfs units, session
//!   scopes — never loses `kill(2)` to a boundary nobody drew); a listed
//!   cgroup gets exactly its bits, so the operator who names a cgroup
//!   chooses whether it may signal (class runs are listed by
//!   construction — their containment is the point).
//!
//! # The self-guard
//!
//! The posture above is the signer's trade and governs the *machine's*
//! signaling. One target is not the signer's to trade away: **wabbit
//! itself**. An enforcement process killed by an outside process is
//! every protection on the box gone at once — the walls stand exactly as
//! long as the process that owns their links — so the gate carries a
//! self-guard that outranks the posture: **every signal aimed at
//! wabbit's own tgid is denied for every caller** — bit or no bit,
//! listed or unlisted — with exactly the exceptions the shutdown
//! contract needs:
//!
//! * the *trusted* (wabbit's own PID and cgroup — it can always signal
//!   itself, and its own threads),
//! * **`SIGCONT`** (above),
//! * **PID 1** — the system, not an outside process: its one directed
//!   use of `kill(2)` toward wabbit is the shutdown sweep (systemd
//!   re-executes into `systemd-shutdown`, which SIGTERMs and then
//!   SIGKILLs everything left), and "unless the system is shutting
//!   down" must hold on every policy, not only ones that remembered
//!   `init.scope`'s bit. A boundary that wants to contain PID 1's
//!   signaling has nothing real to contain: whoever runs PID 1 already
//!   owns the box;
//! * the **shutdown relaxation** ([`SELF_GUARD`]'s flag): when the
//!   userspace's watch observes the system going down — PID 1 exiting,
//!   the shutdown re-exec, or a SIGTERM only an exempt sender could
//!   have delivered — the guard decides nothing, so a SysV-style sweep
//!   (`killall5`, from a non-PID-1 sender) works too.
//!
//! `SIGINT` is **not** among them: the operator's stop channel is the
//! *signed `stop` IPC command* (`wabbit_common::ipc_command`'s
//! [`KIND_STOP`](wabbit_common::ipc_command::KIND_STOP)) — an
//! authenticated request minted by the deployment's key, bound to this
//! boot, burned on acceptance — strictly stronger than a signal any
//! process on the box could once send. The park-exit it triggers is the
//! same designed lifecycle Ctrl-C was; what changed is who may ask.
//!
//! Naming the target is the one thing the gate needs that its
//! identities could not give it: `->tgid`, read out of the target
//! `task_struct` at the offset the **userspace parsed from the running
//! kernel's own BTF** at load (`wabbit/src/btf.rs`). That is ground
//! truth, not a hardcoded offset — the exact shape of the fork-watcher's
//! format-file selection, and the answer to the silent-garbage lesson
//! that keeps this crate off `task_struct` in the first place: a distro
//! that reorders the struct moves the offset in the same BTF the loader
//! parses. The read itself is a scalar probe at a variable offset
//! (both operands scalars, [`bpf_probe_read_kernel`]'s source argument
//! is `ARG_ANYTHING`), never a struct walk, and a failed read
//! fail-opens — the house rule; the self-test's enforcing step is what
//! makes a silently unarmed guard loud.
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
//!   the bit may signal anything except wabbit itself (the self-guard
//!   outranks the bit) — the signer's trade, the same shape as every
//!   other bit here.
//! * **kernel-internal kills** — `kernel_send_sig*` paths bypass the
//!   LSM hook by design (the OOM killer, module loaders' cleanup); no
//!   userspace gate could or should stand in their way.
//! * **a nested pid namespace disarms the guard silently** — the gate
//!   reads the target's tgid in the initial namespace, and a wabbit
//!   launched inside a pid namespace would record a namespace-local
//!   `getpid(2)`. The launches this design defines (initrd, init) never
//!   do that, and the self-test's enforcing step turns a mismatch into
//!   a loud boot failure.

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
/// `SIGCONT` (18), from `uapi/linux/signal.h`: the thaw channel, always
/// exempt (see the module docs).
///
/// The number is load-bearing and was once wrong (`19` — `SIGSTOP`): the
/// exemption then let `SIGSTOP` through at wabbit and denied the real
/// `SIGCONT` at it, so a frozen wabbit could never be thawed from
/// userspace — the exact inversion of the thaw channel, measured in the
/// lab on noble (a second run's sweep stopped the first run's parked
/// wabbit and could not resume it, `EPERM`). The `signal-cont` self-test
/// step pins it per boot: a wrong number fails that step loudly.
const SIGCONT: i32 = 18;

/// PID 1: the system's own process. The self-guard exempts it — see the
/// module docs.
const INIT_TGID: u32 = 1;

/// Read the target's tgid — the one `task_struct` field the gate
/// consults — at the offset the userspace parsed out of the running
/// kernel's own BTF (see the module docs: ground truth, never a
/// compile-time guess). A scalar probe at a variable offset, never a
/// struct walk; `None` means unarmed or unreadable, and both fail open.
#[inline(always)]
fn target_tgid(target: u64) -> Option<u32> {
    let offset = trust::self_guard_tgid_offset();
    if offset == 0 {
        // Unarmed: the loader could not parse the offset, and probing at
        // a guess would read silent garbage. Fail open; the self-test's
        // enforcing step (skipped only with an explicit warning) is what
        // keeps this from going quietly.
        return None;
    }
    unsafe { bpf_probe_read_kernel::<u32>((target + offset as u64) as *const u32).ok() }
}

/// `security_task_kill(p, info, sig, cred)` — the target task is arg 0,
/// and only its *identity* and (for the self-guard) its `->tgid` are
/// consulted: the raw argument bits against `bpf_get_current_task()`,
/// both scalars, one BTF-derived field through a scalar probe. Phony
/// retval at index 4, read once, first.
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
    // upstream verdict is only consulted *after* the callers no
    // gate may ever refuse: SIGCONT (the thaw channel) and the
    // trusted.
    let retval = ctx.arg::<i32>(4);
    let denied_upstream = retval != 0;
    // The one `sig` read, in the house order — after the retval, never
    // before it.
    let sig = ctx.arg::<i32>(2);
    if sig == SIGCONT {
        // The thaw channel outranks everything: every rescue path —
        // the handoff resume, the drop backstop, the watchdog — is a
        // SIGCONT sweep, from whatever cgroup the rescue lands in, and
        // a frozen world must never outlive a failed boot.
        return 0;
    }
    if trust::trusted() {
        return 0;
    }
    if trust::current_tgid() == INIT_TGID {
        // PID 1 is the system, not an outside process: exempt before
        // anything of the gate's own (the shutdown sweep has to work on
        // every policy — see the module docs), and before the stale
        // upstream verdict too (PID 1's own unit management must never
        // depend on this gate).
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
    // The self-guard: wabbit itself is not signalable by outside
    // processes while the system is up. It outranks the posture — a
    // `signal` bit, listed or unlisted, buys no path to the process
    // that owns every wall — and it yields only to its own exceptions,
    // already passed above: SIGCONT, the trusted, PID 1, and the
    // shutdown relaxation. `SIGINT` among the rest: the operator's stop
    // channel is the signed `stop` IPC command, not a signal any
    // process on the box can send (see the module docs).
    if !trust::self_guard_relaxed() && target_tgid(target) == Some(trust::self_guard_tgid()) {
        // A match requires an armed guard (an unarmed one reads `None`,
        // and a real tgid is never `0`), so an unpopulated map can only
        // ever fail open — never deny a signal it cannot prove is aimed
        // at wabbit.
        return trust::verdict(trust::HOOK_SIGNAL_WABBIT, EPERM);
    }
    // The default-allow posture: an *unlisted* cgroup may signal any
    // task (the operator never drew a boundary around it), while a
    // listed one gets exactly its bits — the starter policy's grants
    // stay meaningful, and a listed cgroup without `signal` is the
    // containment the operator asked for.
    let allowed = trust::current_authorized_or_unlisted(ACTION_SIGNAL_OTHERS);
    trust::verdict(trust::HOOK_TASK_KILL, if allowed { 0 } else { EPERM })
}
