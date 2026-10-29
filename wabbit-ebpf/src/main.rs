#![no_std]
#![no_main]

use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use aya_log_ebpf::info;

pub mod lsm;
pub mod maps;
pub mod tracepoints;

#[btf_tracepoint(function = "sys_enter")]
pub fn sys_enter_trace(ctx: BtfTracePointContext) -> u32 {
    match try_sys_enter_trace(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_trace(ctx: BtfTracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter called");
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
