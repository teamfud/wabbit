//! The steady-state maps: what the `wabbit` eBPF programs consult, and
//! what the (later) map-loading and init steps will populate.
//!
//! Nothing here is created with a value: every map starts empty, and the
//! userspace loader fills them before the programs enforce. That ordering
//! is the security model — `TRUSTED_*` and `AUTHORIZATIONS` are written
//! first, `ENFORCING` is flipped last — and it is why every gate reads
//! `ENFORCING` rather than trusting its own presence.
//!
//! # The keys
//!
//! `CgroupKey { cgroup_id }` keys on the kernfs id of the cgroupfs
//! directory, which is the same id `bpf_get_current_cgroup_id` reports for
//! a task inside it: the userspace learns a cgroup's id from the cgroup
//! itself (`stat(2)` on the directory reports it as `st_ino`), so both
//! sides agree without any shared constant.
//!
//! `PROTECTED_PATHS` keys on [`path_hash`] of the canonical cgroupfs path
//! — no trailing `/`, e.g. `/sys/fs/cgroup/wabbit` — hashed with the
//! shared FNV-1a in `wabbit-common`, so the userspace and the eBPF
//! programs compute the same key. A collision can only ever add a
//! protected path, never remove one: it over-protects, it does not open a
//! hole.

use aya_ebpf::{
    btf_maps::{Array, HashMap},
    macros::btf_map,
};
use wabbit_common::authorization::{Authorization, CgroupKey, PathRuleKey};

/// Per-cgroup authorization classes, keyed by the cgroup's id. Written by
/// the userspace when an authorized child cgroup is created (the signed
/// IPC request), consulted by every gate.
#[btf_map]
pub static AUTHORIZATIONS: HashMap<CgroupKey, Authorization, 1024> = HashMap::new();

/// Full-trust cgroups: wabbit's own. Trusted is everything — no gate
/// applies. The loader seeds wabbit's cgroup here before flipping
/// [`ENFORCING`]; the userspace adds anything else that must never be
/// gated.
#[btf_map]
pub static TRUSTED_CGROUPS: HashMap<CgroupKey, u32, 256> = HashMap::new();

/// Full-trust PIDs: wabbit's own process (and, later, whatever its
/// trust-learning discovers). A PID trust is the boot-time model — it
/// dies with the process and is spoofable by PID reuse, so the cgroup
/// maps are the real boundary; this exists for the window where wabbit
/// has not written its cgroup yet, and for the loaders themselves, which
/// run before anything else is populated.
#[btf_map]
pub static TRUSTED_PIDS: HashMap<u32, u32, 1024> = HashMap::new();

/// The protected cgroupfs paths — wabbit's own cgroup and every cgroup
/// holding an authorization bit — keyed by [`path_hash`] of the canonical
/// path (see the module docs). The `file_open` and `sb_mount` gates deny
/// writable opens and mounts under these for everyone outside them: that
/// is the wall around `cgroup.procs` migration that the whole class model
/// leans on.
#[btf_map]
pub static PROTECTED_PATHS: HashMap<u64, u32, 1024> = HashMap::new();

/// Per-cgroup path rules: the allow/deny path profiles
/// (`wabbit-common/src/cgroup_types.rs`'s `PathProfile`, simplified — see
/// [`wabbit_common::authorization::PATH_RULE_ALLOW`]). Keyed by
/// [`PathRuleKey`] (the cgroup and the hashed canonical path prefix), the
/// rule covers the prefix itself and everything below it, resolution is
/// longest-prefix-wins (see [`crate::lsm::paths::path_rule_denies`]), and
/// a cgroup with no [`Authorization`] entry has no rules at all (the
/// default allow). A cgroup's *default* — deny-list or allow-list — is the
/// [`wabbit_common::authorization::FLAG_PATH_RULES_DEFAULT_DENY`] flag on
/// its `Authorization`.
#[btf_map]
pub static PATH_RULES: HashMap<PathRuleKey, u32, 4096> = HashMap::new();

/// The mode switch: index 0 is `0` = observe (trace, do not deny — the
/// self-test phase of the startup diagram) and `1` = enforce. The
/// userspace loads every program, runs its self-tests against the
/// observing gates, then flips this and repeats the deny tests.
#[btf_map]
pub static ENFORCING: Array<u32, 1> = Array::new();

/// Which decision points the gates reached, so the self-test suite can
/// assert what it observed. A `BPF_ANY` insert marks a code as hit, not
/// counted — a read-modify-write counter here trips the 6.8 verifier's
/// register-invariant check, and hit/miss is what a self-test needs
/// anyway. Key: `hook << 16 | code`, value `1`.
#[btf_map]
pub static DECISIONS: HashMap<u32, u32, 64> = HashMap::new();

/// The child PID of every fork, recorded from the kernel side by the fork
/// watcher tracepoints. Independent of any `/proc` view. The later
/// trust-learning reads this: a fork from a trusted task is news (its
/// child inherits the walls of its cgroup, but not a PID-trust), and the
/// self-test suite uses it as the backstop for the fork-watcher offset
/// variants.
#[btf_map]
pub static FORK_EVENTS: HashMap<u32, u8, 1024> = HashMap::new();

/// The PID of every task that has successfully loaded a module. With the
/// `kernel_read_file` gate denying unauthorized loads, an entry here means
/// an *authorized* load happened; the self-test suite asserts the map
/// stays empty through its deny tests.
#[btf_map]
pub static MODULE_LOADS: HashMap<u32, u8, 64> = HashMap::new();
