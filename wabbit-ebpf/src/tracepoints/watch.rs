//! Tracepoints: kernel-side observability for the steady-state gates.
//!
//! The fork watchers record every child PID from inside the kernel,
//! independent of any `/proc` view — the later trust-learning reads the
//! map (a fork from a trusted task is news), and the self-test suite uses
//! it as the backstop that proves the watchers attached.
//!
//! `sched_process_fork`'s record layout is **distro-patched and silently
//! so**: tracepoint context reads are not validated against BTF, so a
//! program with the wrong `child_pid` offset loads fine and records
//! comm bytes as PIDs. RHEL's lazy-preempt backport pads the trace-entry
//! header (`common_preempt_lazy_count`), pushing `child_pid` from 44 to
//! 48. Both offsets therefore exist as compiled variants — the
//! (later) loader parses the running kernel's own format file and
//! attaches the matching one, and both if the parsed offset matches
//! neither.
//!
//! `module_load` records every task that successfully loaded a module.
//! With the `kernel_read_file` gate denying unauthorized loads, an entry
//! here means an *authorized* load happened; the self-test suite asserts
//! the map stays empty through its deny tests.

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};

use crate::maps::{FORK_EVENTS, MODULE_LOADS};

/// The vanilla `sched_process_fork` record: 16-byte comm arrays inline,
/// `child_pid` at offset 44.
const CHILD_PID_VANILLA: usize = 44;

/// RHEL's lazy-preempt `sched_process_fork` record: the
/// `common_preempt_lazy_count` header pad pushes `child_pid` to 48.
const CHILD_PID_PREEMPT_LAZY: usize = 48;

/// Record every fork, for the vanilla record layout.
#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn fork_watcher_vanilla(ctx: TracePointContext) -> i32 {
    record_fork(ctx, CHILD_PID_VANILLA)
}

/// Record every fork, for the RHEL lazy-preempt record layout.
#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn fork_watcher_preempt_lazy(ctx: TracePointContext) -> i32 {
    record_fork(ctx, CHILD_PID_PREEMPT_LAZY)
}

#[inline(always)]
fn record_fork(ctx: TracePointContext, child_pid_offset: usize) -> i32 {
    if let Ok(child_pid) = unsafe { ctx.read_at::<i32>(child_pid_offset) } {
        if child_pid > 0 {
            let _ = FORK_EVENTS.insert(child_pid as u32, 0, 0);
        }
    }
    0
}

/// Record the PID of every task that has successfully loaded a module.
/// Nothing is read from the context: the event itself is the signal.
#[tracepoint(name = "module_load", category = "module")]
pub fn module_load_logger(_ctx: TracePointContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = MODULE_LOADS.insert(pid, 0, 0);
    0
}
