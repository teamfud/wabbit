//! Path resolution for the sleepable gates.
//!
//! The disciplines here are load-bearing, each learned from a verifier that
//! rejected the alternative (see AGENTS.md):
//!
//! * **one 256-byte `d_path` buffer per hook**, passed `&mut` down the
//!   helper chain — two buffers in separate frames overflow the 512-byte
//!   eBPF stack limit once the code is too complex for the compiler to
//!   merge frames;
//! * **`#[inline(always)]` on the whole chain** — helpers that cross the
//!   compiler's inline-cost threshold get outlined into `.text`, and
//!   bpf-linker leaves their cross-section calls unresolved: the program
//!   loads as an empty stub the kernel rejects;
//! * **panic-free indexing (`get`, never slicing)** — a panicking slice
//!   index has its panic path outlined into `.text.unlikely.` with a
//!   relocation against a section symbol nothing resolves, which silently
//!   guts the program at load time;
//! * **`bpf_d_path` needs trusted provenance** — `&file->f_path` is pure
//!   pointer arithmetic (never dereferenced, never copied to the stack),
//!   so the register stays a `PTR_TO_BTF_ID` and the verifier checks the
//!   offset against the running kernel's BTF.

use aya_ebpf::{bindings, helpers::bpf_d_path};
use wabbit_common::authorization::{
    FLAG_PATH_RULES_DEFAULT_DENY, PATH_RULE_ALLOW, PATH_RULE_DENY, PathRuleKey,
};

use crate::{
    lsm::trust,
    maps::{AUTHORIZATIONS, PATH_RULES},
};

/// One buffer per hook (see the module docs).
pub const PATH_BUFFER_SIZE: usize = 256;

/// The module trees, in every spelling `d_path` can produce for them. On
/// merged-/usr distros `/lib` is a symlink to `usr/lib` and the path walk
/// resolves it, so a module image opened through `/lib/modules/...` has
/// the canonical path `/usr/lib/modules/...`; both spellings must match or
/// every distro but the unmerged ones is denied wholesale. The `/sysroot`
/// spellings cover the pre-switch window.
const MODULES_PATHS: &[&[u8]] = &[
    b"/lib/modules",
    b"/usr/lib/modules",
    b"/sysroot/lib/modules",
    b"/sysroot/usr/lib/modules",
];

/// The bpffs root, where wabbit's pins live.
const BPFFS_PATHS: &[&[u8]] = &[b"/sys/fs/bpf"];

/// The cgroupfs root. The gates key protected cgroups by hash of the
/// canonical path *below this root* — no trailing `/`.
pub const CGROUPFS_ROOT: &[u8] = b"/sys/fs/cgroup";

/// `struct file` layouts, for the hooks that must reach into a `file` the
/// kernel handed them. The struct was reordered mid-series — the
/// read-mostly `f_path` moved from the head to the tail — so each layout
/// gets its own program variant, and the loader tries them until one
/// loads. That works because the verifier validates `bpf_d_path`'s
/// argument against the running kernel's BTF: the variant with the wrong
/// offsets fails to load loudly, instead of reading the wrong fields.
///
/// Offsets verified against the vanilla headers, x86-64, distro release
/// configurations (no lockdep or mutex debugging):
///
/// ```text
/// legacy (v5.14–6.1): f_u(16) f_path@16 f_inode f_op f_lock f_write_hint
///                     f_count f_flags f_mode@68 ...
/// modern (v6.8):      f_u(16) f_lock@16 f_mode@20 f_count f_pos_lock(32)
///                     f_pos f_flags f_owner(32) f_cred f_ra(32) f_path@152 ...
/// ```
pub mod file_layout {
    pub const LEGACY_PATH: usize = 16;
    pub const LEGACY_MODE: usize = 68;
    pub const MODERN_PATH: usize = 152;
    pub const MODERN_MODE: usize = 20;
}

/// Resolve `path` with `bpf_d_path` into `buffer`, returning the resolved
/// bytes, or `None` when the path could not be resolved.
///
/// `bpf_d_path` returns the length **including** the trailing NUL (`len =
/// buf + sz - p`, and d_path right-aligns its NUL-terminated string in the
/// buffer) — the first lab runs measured 22 for the 21-byte
/// `/sys/fs/cgroup/wabbit`, and the extra NUL broke every *final*
/// whole-path hash while prefix boundaries kept matching (which is exactly
/// why bnuuy never tripped: its matches are always prefix-plus-`/`
/// continuations). Strip the NUL here, once, so every consumer —
/// `names_or_contains` equality, the protected-path walk, the rule walk —
/// hashes the same bytes the userspace key convention does.
/// # Safety
/// This function dereferences raw pointers.
#[inline(always)]
pub unsafe fn resolve(
    path: *mut bindings::path,
    buffer: &mut [u8; PATH_BUFFER_SIZE],
) -> Option<&[u8]> {
    let length = unsafe { bpf_d_path(path, buffer.as_mut_ptr().cast(), PATH_BUFFER_SIZE as u32) };
    if length < 0 {
        return None;
    }
    let mut length = length as usize;
    // `get`, never a panicking slice (see the module docs).
    if length > 0 && buffer.get(length - 1) == Some(&0) {
        length -= 1;
    }
    buffer.get(..length)
}

/// Byte-wise equality. `==` on slices lowers to a `memcmp` call LLVM
/// outlines into `.text`; bnuuy's matrix-proven object carries `memset`
/// alone, and this keeps the guard in the same call class — the hand loop
/// emits no call at all.
#[inline(always)]
fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    // `get`, never indexing (see the module docs).
    while index < left.len() {
        if left.get(index) != right.get(index) {
            return false;
        }
        index += 1;
    }
    true
}

/// Does `resolved` name `base` itself, or something directly inside it?
#[inline(always)]
pub fn names_or_contains(resolved: &[u8], base: &[u8]) -> bool {
    match resolved.get(..base.len()) {
        Some(prefix) if bytes_equal(prefix, base) => {
            resolved.len() == base.len() || resolved.get(base.len()) == Some(&b'/')
        }
        _ => false,
    }
}

/// Is `resolved` `base` itself or below any of `bases`?
#[inline(always)]
pub fn under_any(resolved: &[u8], bases: &[&[u8]]) -> bool {
    bases.iter().any(|base| names_or_contains(resolved, base))
}

/// `&file->f_path` without dereferencing it: `file + offset`, so the
/// register keeps its `PTR_TO_BTF_ID` provenance and the verifier can
/// check the offset against the running kernel's BTF (see the module
/// docs). `bpf_d_path` rejects a stack-copied path.
#[inline(always)]
pub fn file_path_ptr(file: *mut bindings::file, path_offset: usize) -> *mut bindings::path {
    (file as *mut u8).wrapping_add(path_offset).cast()
}

/// Is the resolved path a module-tree path?
#[inline(always)]
pub fn is_modules_path(resolved: &[u8]) -> bool {
    under_any(resolved, MODULES_PATHS)
}

/// Is the resolved path a bpffs path (one of wabbit's pins)?
#[inline(always)]
pub fn is_bpffs_path(resolved: &[u8]) -> bool {
    under_any(resolved, BPFFS_PATHS)
}

/// Is the resolved path a cgroupfs path (below [`CGROUPFS_ROOT`])?
#[inline(always)]
pub fn is_cgroupfs_path(resolved: &[u8]) -> bool {
    names_or_contains(resolved, CGROUPFS_ROOT)
}

/// The FNV-1a 64 offset basis and prime, mirrored from
/// [`wabbit_common::authorization::path_hash`]. The eBPF side cannot call
/// the shared `const fn` inside a loop without paying a full re-hash per
/// prefix (which detonated the verifier's complexity limit on the first
/// lab run: "BPF program is too large. Processed 1000001 insns"), so the
/// walk below maintains the hash *incrementally* — after consuming byte
/// `i`, the running hash equals `path_hash(&resolved[..i + 1])` — and the
/// known-vector asserts on the shared `const fn` pin the two together.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0000_0100_0000_01b3;
pub use wabbit_common::authorization::PATH_WALK_CAP;

/// One FNV-1a step.
#[inline(always)]
const fn fnv_step(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(FNV_PRIME)
}

/// Does `resolved` fall under a *protected* cgroupfs path?
///
/// One forward pass: the walk consumes each byte, maintaining the FNV-1a
/// hash of the prefix consumed so far, and at every `/` boundary — where
/// the running hash equals [`path_hash`] of the complete prefix ending
/// right before the separator — checks it against
/// [`trust::protected`]. The whole path is checked after the loop: a
/// mount *target* is a complete path with no trailing `/`. The cgroupfs
/// root's own boundaries (at or before [`CGROUPFS_ROOT`]) are skipped —
/// the root is never a protected path, or every cgroupfs write would be
/// walled off. A hash collision can only add a protected path, never
/// remove one.
#[inline(always)]
pub fn under_protected_cgroup(resolved: &[u8]) -> bool {
    if !is_cgroupfs_path(resolved) {
        return false;
    }
    // The cap is a constant, so the verifier sees a bounded loop (see
    // [`PATH_WALK_CAP`]).
    let len = resolved.len().min(PATH_WALK_CAP);
    let mut hash = FNV_OFFSET_BASIS;
    let mut index = 0;
    // `get`, never indexing (see the module docs).
    while index < len {
        let Some(&byte) = resolved.get(index) else {
            break;
        };
        if byte == b'/' && index > 0 {
            // The running hash is `path_hash(&resolved[..index])`.
            if trust::protected(hash) {
                return true;
            }
        }
        hash = fnv_step(hash, byte);
        index += 1;
    }
    // The whole path — the final boundary, the mount-target case.
    trust::protected(hash)
}

/// Is `resolved` exactly the cgroupfs root? (`sb_mount` targeting it mounts
/// a fresh hierarchy over the real one.)
#[inline(always)]
pub fn is_cgroupfs_root(resolved: &[u8]) -> bool {
    names_or_contains(resolved, CGROUPFS_ROOT) && resolved.len() == CGROUPFS_ROOT.len()
}

/// Does the current cgroup's path rules deny opening `resolved`?
///
/// The rules (see [`PATH_RULES`] and
/// `wabbit_common::authorization::FLAG_PATH_RULES_DEFAULT_DENY`) resolve
/// **longest-prefix-wins**: of every prefix carrying a rule, the longest
/// one decides. This is one forward pass — the same incremental FNV-1a
/// walk as [`under_protected_cgroup`], with the running hash equal to
/// `path_hash` of the prefix consumed so far at every `/` boundary, and
/// the whole path at the end — that remembers the verdict of the deepest
/// rule seen: walking shortest to longest and keeping the last match is
/// the same decision as checking the longest first. No rule matched, and
/// the cgroup's default decides: allow, unless its `Authorization` carries
/// the default-deny flag, in which case only a prefix explicitly carrying
/// [`PATH_RULE_ALLOW`] opens. A cgroup with no `Authorization` entry has no
/// rules and is default-allow.
///
/// The per-prefix re-hash this replaces cost a full nested hash loop per
/// boundary, which detonated the verifier's complexity limit on the first
/// lab run ("BPF program is too large. Processed 1000001 insns"). A hash
/// collision can only make a rule match a different path — over-deny or
/// over-allow on that path, never a widening of someone else's rules.
/// Trusted callers never reach this: `file_open` short-circuits them.
#[inline(always)]
pub fn path_rule_denies(resolved: &[u8]) -> bool {
    let cgroup = trust::current_cgroup();
    // The cgroup's default: allow, unless its Authorization says otherwise.
    let Some(authorization) = (unsafe { AUTHORIZATIONS.get(&cgroup) }) else {
        return false;
    };
    let default_deny = authorization.flags & FLAG_PATH_RULES_DEFAULT_DENY != 0;

    // One forward pass, remembering the deepest matching rule's verdict.
    // The cap is a constant, so the verifier sees a bounded loop (see
    // [`PATH_WALK_CAP`]).
    let len = resolved.len().min(PATH_WALK_CAP);
    let mut deepest: Option<bool> = None;
    let mut hash = FNV_OFFSET_BASIS;
    let mut index = 0;
    // `get`, never indexing (see the module docs).
    while index < len {
        let Some(&byte) = resolved.get(index) else {
            break;
        };
        if byte == b'/' && index > 0 {
            // The running hash is `path_hash(&resolved[..index])`.
            deepest = rule_verdict(cgroup.cgroup_id, hash, default_deny).or(deepest);
        }
        hash = fnv_step(hash, byte);
        index += 1;
    }
    // The whole path — the final and deepest boundary.
    deepest = rule_verdict(cgroup.cgroup_id, hash, default_deny).or(deepest);

    deepest.unwrap_or(default_deny)
}

/// One prefix's rule verdict, if it carries one: `false` is "opens", `true`
/// is "denied". In a default-deny profile only an explicit
/// [`PATH_RULE_ALLOW`] opens; in a default-allow profile a
/// [`PATH_RULE_DENY`] denies.
#[inline(always)]
fn rule_verdict(cgroup_id: u64, prefix_hash: u64, default_deny: bool) -> Option<bool> {
    let key = PathRuleKey {
        cgroup_id,
        path_hash: prefix_hash,
    };
    let rule = unsafe { PATH_RULES.get(&key) }?;
    Some(if default_deny {
        rule & PATH_RULE_ALLOW == 0
    } else {
        rule & PATH_RULE_DENY != 0
    })
}
