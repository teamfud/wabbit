use aya_ebpf::{
    btf_maps::{Array, ProgramArray},
    helpers::bpf_get_current_pid_tgid,
    macros::{btf_map, btf_tracepoint},
    programs::tp_btf::BtfTracePointContext,
};

/// map to store pids to hide
#[btf_map]
pub static HIDDEN_PIDS: Array<u32, { u8::MAX as usize }> = Array::new();

#[allow(
    arithmetic_overflow,
    reason = "we have to truncate the pid_tgid to get the pid and tgid"
)]
/// handle getdents entry
#[btf_tracepoint(function = "syscalls/sys_enter_getdents64")]
pub fn handle_getdents64_enter(ctx: BtfTracePointContext) {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;
}

/// handle getdents exit
#[btf_tracepoint(function = "syscalls/sys_exit_getdents64")]
pub fn handle_getdents64_exit(ctx: BtfTracePointContext) {}
