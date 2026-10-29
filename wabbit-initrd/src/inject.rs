//! Syscall-level gates for the module-loading family, through error
//! injection.
//!
//! On kernels whose `sleepable_lsm_hooks` set does not admit
//! `kernel_read_file` (vanilla 5.14/5.15), no `bpf_d_path` protection —
//! and so no path-based allowlist — can exist for module loads. What the
//! kernel *does* offer there is error injection: the syscall wrappers for
//! the whole module-loading family are annotated injectable (verified
//! empirically on Ubuntu 22.04's 5.15: `__x64_sys_finit_module`,
//! `__x64_sys_init_module`, `__x64_sys_delete_module`,
//! `__x64_sys_kexec_load` all appear in
//! `/sys/kernel/debug/error_injection/list`, and
//! `CONFIG_BPF_KPROBE_OVERRIDE` is set), and a `BPF_MODIFY_RETURN`
//! program attached to such a wrapper that returns a non-zero error skips
//! the function entirely — the syscall returns the error before a single
//! instruction of the module loader runs.
//!
//! The program itself is authored in bnuuy as Rust —
//! `module_syscall_gate` — and compiled to eBPF by the same toolchain as
//! every other bnuuy program. This module only performs the loading that
//! aya cannot: its own source marks `BPF_MODIFY_RETURN` "not supported yet
//! in Aya". The instructions are parsed out of the embedded object, the
//! trust-map fd is patched into the program's map reference, and the
//! program is submitted through `BPF_PROG_LOAD` (tracing/modify-return)
//! and attached with `BPF_RAW_TRACEPOINT_OPEN` — the pre-link attach
//! path, because 5.15's `BPF_LINK_CREATE` carries no tracing case.
//!
//! The gate has no path knowledge (that is exactly what the sleepable set
//! takes away), so it is armed only on kernels that lack the LSM gate,
//! and its allowance besides trusted PIDs is `comm`-based (see the
//! program's documentation in bnuuy). Failure safety: each gate's link is
//! an fd held by this process, exactly like every bnuuy LSM link — when
//! wabbit-initrd dies, by any cause, the kernel closes the fds and the
//! gates detach. They are deliberately *not* pinned: pins are inert data,
//! but a pinned link would keep denying after the freezer is gone.

use std::{
    collections::HashSet,
    ffi::{CString, c_long},
    mem::offset_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::Path,
};

use anyhow::{Context, Result, bail};
use aya::Btf;
use aya_obj::{
    btf::BtfKind,
    generated::bpf_insn,
    maps::Map,
    obj::{Function, Object},
};
use log::{info, warn};
use wabbit_common::brand::SIGN_NAME;

/// The syscall family the gate covers: loading modules by fd, loading by
/// buffer, unloading (an attacker dropping a security-relevant module is
/// also tampering), and kexec (replacing the running kernel outright).
const GATED_SYSCALLS: &[&str] = &["finit_module", "init_module", "delete_module", "kexec_load"];

/// The gate program's name in the bnuuy object (its section is named
/// `fentry/…` only so object parsers recognize it; see bnuuy's
/// documentation of the program).
const GATE_NAME: &str = "module_syscall_gate";

/// The bnuuy map the gate consults — the same trust map the `bpf` hook
/// reads, pinned where wabbit-initrd put it.
const TRUST_MAP_NAME: &str = "TRUSTED_BPF_PIDS";

// Kernel UAPI values, from `include/uapi/linux/bpf.h` (the same numbers
// aya's generated bindings carry). Declared here because the loaders are
// hand-rolled; the unit tests pin the attr layouts against the UAPI so a
// wrong copy fails on the host, not in a VM.
const BPF_PROG_LOAD: c_long = 5;
const BPF_OBJ_GET: c_long = 7;
const BPF_RAW_TRACEPOINT_OPEN: c_long = 17;
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_MODIFY_RETURN: u32 = 26;
const BPF_PSEUDO_MAP_FD: u8 = 1;

/// The `bpf_func_id` helpers the gate may call — `bpf_map_lookup_elem`,
/// `bpf_get_current_pid_tgid`, `bpf_get_current_comm`. Any other `call` in
/// the gate's instructions means an outlined function sneaked in
/// (bnuuy's `#[inline(always)]` discipline exists precisely to prevent
/// that), and loading it would produce an unresolved call the kernel
/// rejects as an empty program.
const GATE_HELPERS: &[i32] = &[1, 14, 16];

/// The `BPF_PROG_LOAD` attribute tail this loader fills, in the kernel
/// UAPI's field order (pinned by unit test against the layout aya's
/// generated bindings carry).
#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_btf_obj_fd: u32,
}

/// The `BPF_OBJ_GET` attribute (shared shape with `BPF_OBJ_PIN` in the
/// UAPI), same discipline.
#[repr(C)]
#[derive(Default)]
struct ObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// The `BPF_RAW_TRACEPOINT_OPEN` attribute. With `name` unset this is the
/// pre-`bpf_link` attach path for tracing programs — the one 5.15
/// kernels accept (their `BPF_LINK_CREATE` carries no tracing case and
/// answers `EINVAL`), delegating to the trampoline attach against the
/// program's load-time `attach_btf_id`. This is the same call aya uses to
/// attach Fentry programs, proven on these kernels.
#[repr(C)]
#[derive(Default)]
struct RawTracepointOpenAttr {
    name: u64,
    prog_fd: u32,
}

fn bpf(cmd: c_long, attr: &[u8]) -> Result<c_long> {
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_ptr(), attr.len()) };
    if ret < 0 {
        bail!("bpf({cmd}): {}", std::io::Error::last_os_error());
    }
    Ok(ret)
}

/// Take a pinned object's fd through `BPF_OBJ_GET` — the only open that
/// yields a fd whose file operations satisfy the kernel's map-reference
/// resolution (a VFS open of a bpffs pin is a different file, and the
/// verifier rejects it with "fd N is not pointing to valid bpf_map").
fn obj_get(path: &Path) -> Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("encoding {} as a C path", path.display()))?;
    let attr = ObjGetAttr {
        pathname: path.as_ptr() as u64,
        ..ObjGetAttr::default()
    };
    let attr_bytes = unsafe {
        std::slice::from_raw_parts(
            (&attr as *const ObjGetAttr).cast::<u8>(),
            std::mem::size_of::<ObjGetAttr>(),
        )
    };
    let fd = bpf(BPF_OBJ_GET, attr_bytes)
        .with_context(|| format!("BPF_OBJ_GET({})", path.to_string_lossy()))?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Pull the gate's rustc-compiled instructions out of the embedded bnuuy
/// object, relocated against the pinned trust map.
///
/// The relocation is aya's own public machinery — the same call its
/// loader performs for every program it loads. The trust map gets the
/// pinned fd; the object's other maps get an invalid one, because only
/// the gate's instructions are read afterwards. The fd's owner (the
/// caller of [`gate_instructions_with_trust_fd`]) must keep it open
/// through the subsequent program loads.
fn gate_instructions_with_trust_fd(trust_fd: RawFd) -> Result<Vec<bpf_insn>> {
    let mut object = Object::parse(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/early"
    )))
    .context(format!(
        "parsing the {SIGN_NAME} object for the syscall gate"
    ))?;

    let map_defs: Vec<(String, Map)> = object
        .maps
        .iter()
        .map(|(name, map)| (name.clone(), map.clone()))
        .collect();
    let text_sections: HashSet<usize> = object
        .functions
        .keys()
        .map(|(section_index, _)| *section_index)
        .collect();
    let maps = map_defs.iter().map(|(name, map)| {
        let fd = if name == TRUST_MAP_NAME { trust_fd } else { -1 };
        (name.as_str(), fd, map)
    });
    object.relocate_maps(maps, &text_sections).context(format!(
        "relocating the {SIGN_NAME} object's map references"
    ))?;

    let program = object
        .programs
        .get(GATE_NAME)
        .with_context(|| format!("finding the {GATE_NAME} program in the {SIGN_NAME} object"))?;
    let function: &Function = object
        .functions
        .get(&program.function_key())
        .with_context(|| format!("finding the {GATE_NAME} function's instructions"))?;
    let insns = function.instructions.clone();
    if insns.is_empty() {
        bail!("the {GATE_NAME} program has no instructions");
    }

    // The relocation must have flagged the map reference (the wide
    // `ldimm64` carrying `BPF_PSEUDO_MAP_FD`) and patched the pinned fd
    // into it — exactly one, pointing at the trust map.
    let map_refs = insns
        .iter()
        .filter(|insn| insn.code == 0x18 && insn.src_reg() == BPF_PSEUDO_MAP_FD)
        .count();
    if map_refs != 1
        || insns.iter().any(|insn| {
            insn.code == 0x18 && insn.src_reg() == BPF_PSEUDO_MAP_FD && insn.imm != trust_fd
        })
    {
        bail!(
            "the {GATE_NAME} program carries {map_refs} trust-map references; \
             exactly one, patched with the pinned fd, was expected"
        );
    }

    // Guard the outlining discipline: every call must be a known helper.
    // An outlined function's call is unresolved without aya's call
    // relocation (deliberately not performed here) and would load as an
    // empty program the kernel rejects.
    for insn in &insns {
        if insn.code == 0x85 && !GATE_HELPERS.contains(&insn.imm) {
            bail!(
                "the {GATE_NAME} program calls a non-helper (imm {}); \
                 its helper chain must stay #[inline(always)]",
                insn.imm
            );
        }
    }
    Ok(insns)
}

/// Load and attach the gate to `__x64_sys_{syscall}`, returning the prog
/// and link fds. The verifier log is captured and included in any
/// failure, because a rejection here is undiagnosable without it.
fn gate_for(btf: &Btf, syscall: &str, insns: &[bpf_insn]) -> Result<(OwnedFd, OwnedFd)> {
    let symbol = format!("__x64_sys_{syscall}");
    let btf_id = btf
        .id_by_type_name_kind(&symbol, BtfKind::Func)
        .with_context(|| format!("finding {symbol} in the kernel BTF"))?;

    // `BPF_OBJ_NAME_LEN` is 16 *including* the terminating NUL, and the
    // kernel rejects a name that does not fit — so the cosmetic diagnostic
    // name truncates to 15 bytes.
    let mut name = [0u8; 16];
    let gate_name = format!("wb_{syscall}");
    let gate_name = &gate_name.as_bytes()[..gate_name.len().min(15)];
    name[..gate_name.len()].copy_from_slice(gate_name);
    let license = b"GPL\0";

    let mut verifier_log = vec![0u8; 65536];
    let mut attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_TRACING,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: verifier_log.len() as u32,
        log_buf: verifier_log.as_mut_ptr() as u64,
        prog_name: name,
        expected_attach_type: BPF_MODIFY_RETURN,
        attach_btf_id: btf_id,
        ..ProgLoadAttr::default()
    };
    let attr_bytes = unsafe {
        std::slice::from_raw_parts(
            (&attr as *const ProgLoadAttr).cast::<u8>(),
            // Exactly the field bytes: the struct's alignment padding past
            // 116 is never passed to the kernel (and its contents are not
            // guaranteed zero).
            offset_of!(ProgLoadAttr, attach_btf_obj_fd) + std::mem::size_of::<u32>(),
        )
    };
    let prog_fd = bpf(BPF_PROG_LOAD, attr_bytes).with_context(|| {
        let log_end = verifier_log.iter().position(|b| *b == 0).unwrap_or(0);
        format!(
            "loading the {syscall} gate (verifier: {})",
            String::from_utf8_lossy(&verifier_log[..log_end])
        )
    })?;
    let prog_fd = unsafe { OwnedFd::from_raw_fd(prog_fd as RawFd) };

    // `name` unset: attach the tracing program to the function it was
    // loaded against (the attach_btf_id above).
    let attach_attr = RawTracepointOpenAttr {
        name: 0,
        prog_fd: prog_fd.as_raw_fd() as u32,
    };
    let attach_attr_bytes = unsafe {
        std::slice::from_raw_parts(
            (&attach_attr as *const RawTracepointOpenAttr).cast::<u8>(),
            offset_of!(RawTracepointOpenAttr, prog_fd) + std::mem::size_of::<u32>(),
        )
    };
    let link_fd = bpf(BPF_RAW_TRACEPOINT_OPEN, attach_attr_bytes)
        .with_context(|| format!("attaching the {syscall} gate to {symbol}"))?;
    let link_fd = unsafe { OwnedFd::from_raw_fd(link_fd as RawFd) };
    Ok((prog_fd, link_fd))
}

/// The armed gates. The fds — programs and links alike — are held for as
/// long as this value lives, and closing them detaches the gates.
pub struct Gates {
    _progs: Vec<OwnedFd>,
    links: Vec<OwnedFd>,
}

impl Gates {
    pub fn none() -> Self {
        Gates {
            _progs: Vec::new(),
            links: Vec::new(),
        }
    }

    pub fn armed(&self) -> bool {
        !self.links.is_empty()
    }
}

impl Drop for Gates {
    fn drop(&mut self) {
        if !self.links.is_empty() {
            info!("detaching the syscall-level module gates");
        }
    }
}

/// Arm the syscall-level gates for the whole module-loading family. Armed
/// only by callers that lack the LSM module-load gate; every other kernel
/// keeps its (stronger, path-aware) `kernel_read_file` gate instead.
pub fn arm(btf: &Btf, trusted_map_pin: &Path) -> Result<Gates> {
    // The pinned map's fd is baked into the gate's instructions, so it
    // must outlive the loads below — each BPF_PROG_LOAD takes its own
    // reference, but only while the syscall runs.
    let trust_map = obj_get(trusted_map_pin)?;
    let insns = gate_instructions_with_trust_fd(trust_map.as_raw_fd())?;

    let mut progs = Vec::new();
    let mut links = Vec::new();
    let mut gated = Vec::new();
    for syscall in GATED_SYSCALLS {
        match gate_for(btf, syscall, &insns) {
            Ok((prog, link)) => {
                progs.push(prog);
                links.push(link);
                gated.push(*syscall);
            }
            Err(error) => {
                warn!("the {syscall} gate does not arm on this kernel: {error:#}");
            }
        }
    }
    if links.is_empty() {
        bail!("no syscall-level module gate could be armed");
    }
    info!("syscall-level module gates armed: {gated:?}");
    Ok(Gates {
        _progs: progs,
        links,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prog_load_attr_matches_the_uapi_layout() {
        assert_eq!(offset_of!(ProgLoadAttr, prog_type), 0);
        assert_eq!(offset_of!(ProgLoadAttr, insn_cnt), 4);
        assert_eq!(offset_of!(ProgLoadAttr, insns), 8);
        assert_eq!(offset_of!(ProgLoadAttr, license), 16);
        assert_eq!(offset_of!(ProgLoadAttr, log_level), 24);
        assert_eq!(offset_of!(ProgLoadAttr, log_buf), 32);
        assert_eq!(offset_of!(ProgLoadAttr, prog_flags), 44);
        assert_eq!(offset_of!(ProgLoadAttr, prog_name), 48);
        assert_eq!(offset_of!(ProgLoadAttr, expected_attach_type), 68);
        assert_eq!(offset_of!(ProgLoadAttr, attach_btf_id), 108);
        assert_eq!(offset_of!(ProgLoadAttr, attach_btf_obj_fd), 112);
        // 8-byte alignment pads the struct to 120; the syscall only ever
        // sees the first 116 field bytes (see gate_for).
        assert_eq!(std::mem::size_of::<ProgLoadAttr>(), 120);
    }

    #[test]
    fn obj_get_attr_matches_the_uapi_layout() {
        assert_eq!(offset_of!(ObjGetAttr, pathname), 0);
        assert_eq!(offset_of!(ObjGetAttr, bpf_fd), 8);
        assert_eq!(offset_of!(ObjGetAttr, file_flags), 12);
        assert_eq!(std::mem::size_of::<ObjGetAttr>(), 16);
    }

    #[test]
    fn raw_tracepoint_open_attr_matches_the_uapi_layout() {
        assert_eq!(offset_of!(RawTracepointOpenAttr, name), 0);
        assert_eq!(offset_of!(RawTracepointOpenAttr, prog_fd), 8);
        assert_eq!(std::mem::size_of::<RawTracepointOpenAttr>(), 16);
    }

    /// The gate really is in the object, relocates against the trust map
    /// through aya's own machinery, and calls nothing but its three known
    /// helpers — checked against the actual compiled bnuuy object, on the
    /// host, before any VM is involved.
    #[test]
    fn the_gate_relocates_and_calls_only_known_helpers() {
        let insns = gate_instructions_with_trust_fd(42)
            .expect("the gate relocates against a fake trust-map fd");

        assert!(!insns.is_empty(), "the gate has instructions");

        let map_refs: Vec<&bpf_insn> = insns
            .iter()
            .filter(|insn| insn.code == 0x18 && insn.src_reg() == BPF_PSEUDO_MAP_FD)
            .collect();
        assert_eq!(map_refs.len(), 1, "exactly one trust-map reference");
        assert_eq!(
            map_refs[0].imm, 42,
            "the relocation patched the trust-map fd into the reference"
        );

        for insn in &insns {
            if insn.code == 0x85 {
                assert!(
                    GATE_HELPERS.contains(&insn.imm),
                    "only known helpers may be called, found imm {}",
                    insn.imm
                );
            }
        }
    }
}
