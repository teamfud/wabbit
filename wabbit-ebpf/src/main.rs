#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::debug;

pub mod lsm;
pub mod maps;
pub mod tracepoints;

/// The load-path scaffold: one program the userspace can attach, proving
/// the object loads and its logger reaches userspace. It logs at debug,
/// not info — attached to `sys_enter` it fires on *every* syscall, and
/// at info a single 30-second lab window floods the log with every
/// syscall on every cpu.
///
/// The category is `raw_syscalls`: that is where the kernel exposes
/// `sys_enter` (`/sys/kernel/tracing/events/raw_syscalls/sys_enter`),
/// and aya's attach resolves the event id from the category path — the
/// scaffold's `sys` category never existed.
#[tracepoint(name = "sys_enter", category = "raw_syscalls")]
pub fn sys_enter_trace(ctx: TracePointContext) -> u32 {
    match try_sys_enter_trace(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_trace(ctx: TracePointContext) -> Result<u32, u32> {
    debug!(&ctx, "tracepoint sys_enter called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
