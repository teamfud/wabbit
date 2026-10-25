#![no_std]
#![no_main]
// The hooks here resolve paths with `bpf_d_path`, which LSM programs may
// only call from *sleepable* hooks — the kernel's `sleepable_lsm_hooks`
// set. That set admits `file_open`, `kernel_read_file`, `sb_mount`, and the
// `path_unlink`/`mkdir`/`rmdir`/`symlink`/`link`/`rename` family, but not
// `file_permission`, `move_mount`, or `path_mknod`: those hooks cannot
// resolve a path at all, so their protections do not exist here.
// `file_open` carries the module-tree write gate (open-time `f_mode`) and
// the untrusted-bpffs open gate; `sb_mount` carries the mount-target gate.
// The residual gaps — writing through an fd opened before wabbit started,
// and `move_mount`/`fchownat`-style mount shuffling — are documented in
// AGENTS.md.

use aya_ebpf::{
    btf_maps::HashMap,
    helpers::{TASK_COMM_LEN, bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{btf_map, lsm, tracepoint},
    programs::{LsmContext, TracePointContext},
};

/// The child PID of every fork, recorded from the kernel side by
/// `fork_watcher`. Independent of any `/proc` view.
#[btf_map]
pub static FORK_EVENTS: HashMap<u32, u8, 1024> = HashMap::new();

/// The PID of every task that has successfully loaded a module.
#[btf_map]
pub static MODULE_LOADS: HashMap<u32, u8, 64> = HashMap::new();

/// Which decisions the hooks reached: a `BPF_ANY` insert marks a code as
/// hit, not counted. eBPF programs cannot print; this is how the `file_open`
/// hook speaks to the verification suite, which dumps the map into the sign
/// when a writable-open-under-the-module-tree test fails. A read-modify-
/// write counter here tripped the 6.8 verifier's register-invariant check;
/// hit/miss is what the diagnosis needs anyway.
///
/// ```text
///  1 = hook called
///  2 = early return on a previous LSM's denial
///  3 = untrusted open of a bpffs file (denied)
///  4 = f_mode could not be read
///  5 = open is not writable (no FMODE_WRITE)
///  6 = open is writable, module-tree check follows
///  7 = module-tree file (denied)
///  8 = writable, but not under the module trees
/// 90 = a d_path resolution failed (global, any hook)
/// ```
#[btf_map]
pub static FILE_OPEN_TRACE: HashMap<u32, u32, 32> = HashMap::new();

#[inline(always)]
fn traced(code: u32) {
    let _ = FILE_OPEN_TRACE.insert(code, 1, 0);
}

#[btf_map]
pub static TRUSTED_BPF_PIDS: HashMap<u32, u8, 1024> = HashMap::new();

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The module trees, in every spelling `d_path` can produce for them. On
/// merged-/usr systems (Ubuntu, modern Debian and Fedora) `/lib` is a
/// symlink to `usr/lib`, and the path walk resolves it before the file
/// exists — so a module image opened through `/lib/modules/...` has the
/// canonical path `/usr/lib/modules/...`. Both must be allowed, or every
/// writable open and module load on those distros is denied as out-of-tree.
/// In the initrd, `/sysroot/lib/modules` and `/sysroot/usr/lib/modules`
/// cover the real root's trees before the switch.
const MODULES_PATHS: &[&[u8]] = &[
    b"/lib/modules",
    b"/usr/lib/modules",
    b"/sysroot/lib/modules",
    b"/sysroot/usr/lib/modules",
];
const BPFFS_PATHS: &[&[u8]] = &[b"/sys/fs/bpf"];
const PATH_BUFFER_SIZE: usize = 256;

/// The `id` argument of the `kernel_read_file` LSM hook, from `enum
/// kernel_read_file_id`. Every kernel in the target matrix (5.14 through
/// 6.8, verified against the vanilla headers) numbers `READING_MODULE` as 2,
/// after the leading `READING_UNKNOWN` entry.
const READING_MODULE: i32 = 2;

const FMODE_WRITE: u32 = 1 << 1;

/// `struct file` layouts, for the hooks that must reach into a `file` the
/// kernel handed them. The struct was reordered mid-series — the read-mostly
/// `f_path` moved from the head to the tail — so each layout gets its own
/// program variant, and `wabbit-initrd` tries them until one loads. That
/// works because the verifier validates `bpf_d_path`'s argument against the
/// running kernel's BTF: the variant with the wrong offsets fails to load,
/// loudly, instead of reading the wrong fields. A kernel with a third
/// layout fails both variants and is reported by name.
///
/// Offsets verified against the vanilla headers, x86-64, distro release
/// configurations (no lockdep or mutex debugging):
///
/// ```text
/// legacy (v5.14): f_u(16) f_path@16 f_inode f_op f_lock f_write_hint
///                 f_count f_flags f_mode@68 ...
/// modern (v6.8):  f_u(16) f_lock@16 f_mode@20 f_count f_pos_lock(32)
///                 f_pos f_flags f_owner(32) f_cred f_ra(32) f_path@152 ...
/// ```
mod file_layout {
    pub const LEGACY_PATH: usize = 16;
    pub const LEGACY_MODE: usize = 68;
    pub const MODERN_PATH: usize = 152;
    pub const MODERN_MODE: usize = 20;
}

/// Resolve `path` with `bpf_d_path` into `buffer` and return the length
/// written, or `None` if the path could not be resolved. One buffer per
/// program, shared by every path check: two 256-byte buffers in separate
/// frames overflowed the 512-byte eBPF stack limit once the module-tree
/// list grew past a size where the compiler stopped merging frames.
#[inline(always)]
fn resolve_path<'a>(
    path: *mut aya_ebpf::bindings::path,
    buffer: &'a mut [u8; PATH_BUFFER_SIZE],
) -> Option<&'a [u8]> {
    let length = unsafe { bpf_d_path(path, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if length < 0 {
        traced(90);
        return None;
    }
    // `get`, never panicking slices: an indexing panic path gets outlined
    // into `.text.unlikely.` with a relocation against a section symbol,
    // which nothing resolves — the program loads as `call -1` and the
    // kernel rejects it with "last insn is not an exit or jmp".
    buffer.get(..length as usize)
}

/// Does `resolved` name `base` itself, or something directly inside it?
/// Panic-free for the same reason as [`resolve_path`].
#[inline(always)]
fn names_or_contains(resolved: &[u8], base: &[u8]) -> bool {
    match resolved.get(..base.len()) {
        Some(prefix) if prefix == base => {
            resolved.len() == base.len() || resolved.get(base.len()) == Some(&b'/')
        }
        _ => false,
    }
}

#[inline(always)]
fn is_modules_path(
    path: *mut aya_ebpf::bindings::path,
    buffer: &mut [u8; PATH_BUFFER_SIZE],
) -> bool {
    match resolve_path(path, buffer) {
        None => false,
        Some(resolved) => MODULES_PATHS
            .iter()
            .any(|modules_path| names_or_contains(resolved, modules_path)),
    }
}

#[inline(always)]
fn is_path_under(
    path: *mut aya_ebpf::bindings::path,
    paths: &[&[u8]],
    buffer: &mut [u8; PATH_BUFFER_SIZE],
) -> bool {
    match resolve_path(path, buffer) {
        None => false,
        Some(resolved) => paths.iter().any(|base| names_or_contains(resolved, base)),
    }
}

#[inline(always)]
fn current_pid_trusted() -> bool {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    unsafe { TRUSTED_BPF_PIDS.get(&pid) }.is_some()
}

/// `&file->f_path` without dereferencing it. `bpf_d_path` requires the
/// trusted provenance of the pointer the hook itself was handed: copying
/// `f_path` to the stack erases it, and the verifier rejects the program.
/// Pure pointer arithmetic keeps the register a `PTR_TO_BTF_ID`, and the
/// verifier then checks the offset against the running kernel's BTF.
#[inline(always)]
fn file_path_ptr(
    file: *mut aya_ebpf::bindings::file,
    path_offset: usize,
) -> *mut aya_ebpf::bindings::path {
    (file as *mut u8).wrapping_add(path_offset).cast()
}

#[inline(always)]
fn is_modules_file(
    file: *mut aya_ebpf::bindings::file,
    path_offset: usize,
    buffer: &mut [u8; PATH_BUFFER_SIZE],
) -> bool {
    is_modules_path(file_path_ptr(file, path_offset), buffer)
}

#[inline(always)]
fn is_bpffs_file(
    file: *mut aya_ebpf::bindings::file,
    path_offset: usize,
    buffer: &mut [u8; PATH_BUFFER_SIZE],
) -> bool {
    is_path_under(file_path_ptr(file, path_offset), BPFFS_PATHS, buffer)
}

#[inline(always)]
fn deny_if_modules_path(ctx: &LsmContext, path_arg: usize, retval: i32) -> i32 {
    if retval != 0 {
        return retval;
    }

    let mut buffer = [0u8; PATH_BUFFER_SIZE];
    let path = ctx.arg::<*mut aya_ebpf::bindings::path>(path_arg);
    if is_modules_path(path, &mut buffer) {
        return -1;
    }

    0
}

#[inline(always)]
fn deny_if_untrusted_bpffs_path(ctx: &LsmContext, path_arg: usize, retval: i32) -> i32 {
    if retval != 0 {
        return retval;
    }

    let mut buffer = [0u8; PATH_BUFFER_SIZE];
    if !current_pid_trusted()
        && is_path_under(
            ctx.arg::<*mut aya_ebpf::bindings::path>(path_arg),
            BPFFS_PATHS,
            &mut buffer,
        )
    {
        return -1;
    }

    0
}

/// Deny `bpf(2)` for every PID outside `TRUSTED_BPF_PIDS`.
///
/// Deliberately context-free. `security_bpf`'s argument count varies across
/// kernels — mainline has a fourth `bool kernel` parameter that Ubuntu
/// 24.04's 6.8 and older kernels lack — and reading the trailing phony
/// `retval` argument bakes in one layout: Ubuntu 24.04's verifier rejects a
/// mainline-layout program outright ("func 'bpf_lsm_bpf' doesn't have 5-th
/// argument"). Touching no argument at all loads everywhere. The cost:
/// where an earlier LSM already denied the call, our `-1` replaces its
/// errno; the denial itself is identical.
#[lsm(hook = "bpf")]
pub fn bpf(_ctx: LsmContext) -> i32 {
    if current_pid_trusted() { 0 } else { -1 }
}

/// Deny loading kernel modules from outside the module trees.
///
/// `finit_module(2)` reads its image through `kernel_read_file_from_fd`,
/// which consults this hook with `id == READING_MODULE` before the module
/// loader looks at a single byte: denying here costs the caller an `EPERM`
/// and nothing else. Only images whose path lies in one of
/// [`MODULES_PATHS`] may proceed. Everything else is out-of-tree and denied,
/// including `init_module(2)` memory images, for which `bpf_d_path` fails
/// and the path check fails closed.
#[inline(always)]
fn kernel_read_file_body(ctx: &LsmContext, path_offset: usize) -> i32 {
    // LSM_HOOK(int, 0, kernel_read_file, struct file *file,
    //          enum kernel_read_file_id id, bool contents)
    let retval = ctx.arg::<i32>(3);
    if retval != 0 {
        return retval;
    }

    let id = ctx.arg::<i32>(1);
    if id != READING_MODULE {
        return 0;
    }

    let file = ctx.arg::<*mut aya_ebpf::bindings::file>(0);
    let mut buffer = [0u8; PATH_BUFFER_SIZE];
    if is_modules_file(file, path_offset, &mut buffer) {
        0
    } else {
        -1
    }
}

#[lsm(hook = "kernel_read_file", sleepable)]
pub fn kernel_read_file_modern(ctx: LsmContext) -> i32 {
    kernel_read_file_body(&ctx, file_layout::MODERN_PATH)
}

#[lsm(hook = "kernel_read_file", sleepable)]
pub fn kernel_read_file_legacy(ctx: LsmContext) -> i32 {
    kernel_read_file_body(&ctx, file_layout::LEGACY_PATH)
}

/// Record every fork from the kernel side.
///
/// `sched_process_fork` fires inside the kernel for every new task, before
/// anything about it is visible in `/proc` — and regardless of how `/proc`
/// is mounted. The BPF-visible offsets are exactly the tracepoint format
/// file's, and on every kernel of the target matrix the comm fields are
/// 16-byte inline arrays (mainline converts them to dynamic `__string`
/// words only after 6.8):
///
/// ```text
/// offset  8: parent_comm[16]
/// offset 24: parent_pid
/// offset 28: child_comm[16]
/// offset 44: child_pid                       ← vanilla layout
/// ```
///
/// The `common_*` header itself is distro-patched: RHEL 9's kernel adds
/// `common_preempt_lazy_count` (the lazy-preempt backport) at offset 8,
/// pushing every later field up 4 bytes — `child_pid` at 48:
///
/// ```text
/// offset 12: parent_comm[16]
/// offset 28: parent_pid
/// offset 32: child_comm[16]
/// offset 48: child_pid                       ← RHEL lazy-preempt layout
/// ```
///
/// Tracepoint programs cannot pick this up from a load failure — the ctx
/// read is not validated against anything, so the wrong offset loads fine
/// and silently records comm bytes as PIDs (100 = "d", the tail of
/// "wabbit-initrd", on Rocky 9). wabbit-initrd therefore parses the
/// running kernel's format file and attaches the matching variant — and
/// attaches both when the parsed offset is neither known value, leaving
/// the map with some junk keys but no blind spot. The freeze's
/// verification is the backstop: it checks the worker's own PID against
/// the map.
#[tracepoint(name = "sched_process_fork", category = "sched")]
fn fork_watcher_vanilla(ctx: TracePointContext) -> i32 {
    record_fork(ctx, 44)
}

/// The RHEL lazy-preempt variant of [`fork_watcher_vanilla`]; see its
/// documentation for the layout divergence.
#[tracepoint(name = "sched_process_fork", category = "sched")]
fn fork_watcher_preempt_lazy(ctx: TracePointContext) -> i32 {
    record_fork(ctx, 48)
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

/// Record the PID of every task that successfully loads a module.
///
/// Nothing is read from the context: the event itself is the signal. With
/// `kernel_read_file` denying out-of-tree loads, an entry here means an
/// in-tree load happened; the verification tests assert the map stays empty.
#[tracepoint(name = "module_load", category = "module")]
fn module_load_logger(_ctx: TracePointContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = MODULE_LOADS.insert(pid, 0, 0);
    0
}

/// The module-loading syscall gate.
///
/// On kernels whose `sleepable_lsm_hooks` set does not admit
/// `kernel_read_file` (vanilla 5.14/5.15), no `bpf_d_path` allowlist can
/// gate module loads — but those kernels' syscall wrappers are
/// error-injectable, and a `BPF_MODIFY_RETURN` program returning a
/// non-zero error at one skips the syscall before the module loader runs
/// at all. This is that program, deny-by-default: trusted PIDs pass (the
/// same `TRUSTED_BPF_PIDS` map the `bpf` hook consults), and so do the
/// initrd's module loaders by `comm`, because a real initrd legitimately
/// loads storage and crypto drivers mid-boot and a syscall-entry gate
/// has no path knowledge to tell those apart. `comm` is spoofable, but
/// only by code already running inside the initrd — a boundary whose
/// loss means wabbit-initrd itself could simply have been removed.
///
/// The section is named `fentry/` only so object parsers recognize it.
/// aya cannot host `BPF_MODIFY_RETURN` programs (its own source marks
/// them "not supported yet in Aya"), so wabbit-initrd loads these
/// rustc-compiled instructions itself through `BPF_PROG_LOAD` and
/// attaches them to the four module-loading syscalls with
/// `BPF_RAW_TRACEPOINT_OPEN`. The trampoline hands this function the
/// target's arguments; they are deliberately unread — the gate decides
/// on the caller's identity alone.
#[unsafe(link_section = "fentry/module_syscall_gate")]
#[unsafe(no_mangle)]
pub extern "C" fn module_syscall_gate() -> i64 {
    module_syscall_gate_body()
}

#[inline(always)]
fn module_syscall_gate_body() -> i64 {
    if current_pid_trusted() {
        return 0;
    }
    match current_comm() {
        Some(comm) if names_module_loader(&comm) => 0,
        // The helper cannot fail in this context, but deny is the safe
        // default if it ever does.
        _ => -1,
    }
}

/// The task `comm` of the current context, or `None` on helper failure.
///
/// The buffer is deliberately left uninitialized: the helper writes all
/// `TASK_COMM_LEN` bytes on success, and a zero-initialized buffer makes
/// the compiler outline the zeroing into a `memset` call. aya relocates
/// such calls for its own loads, but wabbit-initrd loads the gate raw
/// (aya cannot host `BPF_MODIFY_RETURN` programs), so the gate must stay
/// free of outlined calls — the same `#[inline(always)]` discipline the
/// rest of bnuuy keeps, for the same reason.
#[inline(always)]
fn current_comm() -> Option<[u8; TASK_COMM_LEN]> {
    let mut comm = core::mem::MaybeUninit::<[u8; TASK_COMM_LEN]>::uninit();
    // SAFETY: the pointer is a valid 16-byte stack slot, and the size
    // matches the helper's write.
    let ret = unsafe {
        aya_ebpf::helpers::generated::bpf_get_current_comm(
            comm.as_mut_ptr().cast(),
            TASK_COMM_LEN as u32,
        )
    };
    if ret == 0 {
        // SAFETY: the helper wrote every byte on success.
        Some(unsafe { comm.assume_init() })
    } else {
        None
    }
}

/// Does `comm` name one of the initrd's module loaders? `modprobe` is the
/// name every initrd invokes (and it stays the invoked name even when the
/// binary behind it is kmod); `kmod` and `insmod` cover the remaining
/// spellings. The task `comm` is always NUL-padded, so requiring a zero
/// byte after the name pins the exact length.
#[inline(always)]
fn names_module_loader(comm: &[u8; TASK_COMM_LEN]) -> bool {
    const LOADERS: &[&[u8]] = &[b"modprobe", b"kmod", b"insmod"];
    LOADERS.iter().any(|loader| {
        comm.get(..loader.len()) == Some(*loader) && comm.get(loader.len()) == Some(&0)
    })
}
// blue linden NOTE: DO NOT TRUST THIS AS A SECURITY GATE. THIS ISN'T SECURE, BUT JAMMY KERNEL IS FUCKING STUPID.

/// Deny untrusted access to bpffs files, and writable opens of module-tree
/// files.
///
/// `security_file_open` runs after `f_mode` is set, so a writable open is
/// visible through it — this is what makes the diagram's "test write perms
/// of /l/m → EPERM" a single denied `open(2)` rather than a deferred
/// failure at the first `write(2)`.
#[inline(always)]
fn file_open_body(ctx: &LsmContext, path_offset: usize, mode_offset: usize) -> i32 {
    // LSM_HOOK(int, 0, file_open, struct file *file)
    traced(1);
    let file = ctx.arg::<*mut aya_ebpf::bindings::file>(0);
    let retval = ctx.arg::<i32>(1);
    if retval != 0 {
        traced(2);
        return retval;
    }

    // One buffer shared by every path check in this hook: two 256-byte
    // buffers in separate frames overflow the 512-byte eBPF stack limit.
    let mut buffer = [0u8; PATH_BUFFER_SIZE];

    if !current_pid_trusted() && is_bpffs_file(file, path_offset, &mut buffer) {
        traced(3);
        return -1;
    }

    let mode = unsafe {
        bpf_probe_read_kernel((file as *const u8).wrapping_add(mode_offset) as *const u32)
    };

    let Ok(mode) = mode else {
        traced(4);
        return 0;
    };

    if mode & FMODE_WRITE == 0 {
        traced(5);
        return 0;
    }

    traced(6);
    if is_modules_file(file, path_offset, &mut buffer) {
        traced(7);
        return -1;
    }

    traced(8);
    0
}

#[lsm(hook = "file_open", sleepable)]
pub fn file_open_modern(ctx: LsmContext) -> i32 {
    file_open_body(&ctx, file_layout::MODERN_PATH, file_layout::MODERN_MODE)
}

#[lsm(hook = "file_open", sleepable)]
pub fn file_open_legacy(ctx: LsmContext) -> i32 {
    file_open_body(&ctx, file_layout::LEGACY_PATH, file_layout::LEGACY_MODE)
}

/// Deny mounting over the module trees, and untrusted mounts over bpffs.
///
/// `sb_mount` is the `mount(2)` LSM hook: its `path` argument (index 1) is
/// the mountpoint about to be covered. The `move_mount` hook would be the
/// natural companion, but it is not in the kernel's `sleepable_lsm_hooks`
/// set — and LSM programs may only call `bpf_d_path` from sleepable hooks —
/// so it cannot resolve a path at all; the same constraint retires the
/// `file_permission` and `path_mknod` protections (see the module docs).
#[lsm(hook = "sb_mount", sleepable)]
pub fn sb_mount(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, sb_mount, const char *dev_name,
    //          const struct path *path, const char *type,
    //          unsigned long flags, void *data)
    // The phony retval is read once, before any path resolution: re-reading
    // it after the string-comparison loops trips the 6.8 verifier's
    // register-invariant check on the truncation (REG INVARIANTS VIOLATION,
    // then an unprovable R0 at exit). One early read is the shape every
    // hook that loads on 6.8 already uses.
    let retval = ctx.arg::<i32>(5);
    let result = deny_if_modules_path(&ctx, 1, retval);
    if result != 0 {
        return result;
    }
    deny_if_untrusted_bpffs_path(&ctx, 1, retval)
}

#[lsm(hook = "path_unlink", sleepable)]
pub fn path_unlink(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, path_unlink, const struct path *dir,
    //          struct dentry *dentry)
    let retval = ctx.arg::<i32>(2);
    deny_if_untrusted_bpffs_path(&ctx, 0, retval)
}

#[lsm(hook = "path_mkdir", sleepable)]
pub fn path_mkdir(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, path_mkdir, const struct path *dir,
    //          struct dentry *dentry, umode_t mode)
    let retval = ctx.arg::<i32>(3);
    let result = deny_if_modules_path(&ctx, 0, retval);
    if result != 0 {
        return result;
    }
    deny_if_untrusted_bpffs_path(&ctx, 0, retval)
}

#[lsm(hook = "path_rmdir", sleepable)]
pub fn path_rmdir(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, path_rmdir, const struct path *dir,
    //          struct dentry *dentry)
    let retval = ctx.arg::<i32>(2);
    deny_if_untrusted_bpffs_path(&ctx, 0, retval)
}

#[lsm(hook = "path_symlink", sleepable)]
pub fn path_symlink(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, path_symlink, const struct path *dir,
    //          struct dentry *dentry, const char *old_name)
    let retval = ctx.arg::<i32>(3);
    let result = deny_if_modules_path(&ctx, 0, retval);
    if result != 0 {
        return result;
    }
    deny_if_untrusted_bpffs_path(&ctx, 0, retval)
}

#[lsm(hook = "path_link", sleepable)]
pub fn path_link(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, path_link, struct dentry *old_dentry,
    //          const struct path *new_dir, struct dentry *new_dentry)
    let retval = ctx.arg::<i32>(3);
    let result = deny_if_modules_path(&ctx, 1, retval);
    if result != 0 {
        return result;
    }
    deny_if_untrusted_bpffs_path(&ctx, 1, retval)
}

#[lsm(hook = "path_rename", sleepable)]
pub fn path_rename(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, path_rename, const struct path *old_dir,
    //          struct dentry *old_dentry, const struct path *new_dir,
    //          struct dentry *new_dentry[, unsigned int flags])
    // The trailing `flags` argument only exists on newer kernels — Rocky
    // 9's 5.14 predates it — so the phony `retval` shifts between layouts
    // and reading it bakes in one of them. Reading only the stable
    // arguments (`new_dir`, index 2) loads everywhere; as with the `bpf`
    // hook, the prior-LSM errno pass-through is traded away: an earlier
    // LSM's denial becomes our -1, still a denial.
    let new_dir = ctx.arg::<*mut aya_ebpf::bindings::path>(2);
    let mut buffer = [0u8; PATH_BUFFER_SIZE];
    if is_modules_path(new_dir, &mut buffer) {
        return -1;
    }
    if !current_pid_trusted() && is_path_under(new_dir, BPFFS_PATHS, &mut buffer) {
        return -1;
    }
    0
}
