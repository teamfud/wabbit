#![allow(non_camel_case_types)]

use core::mem::size_of;

pub const AUTH_VERSION: u32 = 1;

pub const ACTION_SETNS: u64 = 1 << 0;
pub const ACTION_UNSHARE: u64 = 1 << 1;
pub const ACTION_MOUNT: u64 = 1 << 2;
pub const ACTION_EXEC: u64 = 1 << 3;
pub const ACTION_CREDENTIALS: u64 = 1 << 4;
pub const ACTION_TAG_CONTROL: u64 = 1 << 5;

/// Use the `bpf(2)` syscall in the restricted form system-management
/// daemons need — the "systemd class".
///
/// Grant this only to cgroups whose bpf(2) use is orchestrated by PID 1
/// (init.scope and, if it turns out to genuinely need it,
/// systemd-udevd.service): systemd loads and attaches every unit's cgroup
/// device-control and egress-firewall programs itself, so services never
/// need the bit.
///
/// What the class permits, and what each permit relies on:
///
/// * `BPF_PROG_LOAD`, but only for cgroup-family program types
///   (`CGROUP_DEVICE`, `CGROUP_SKB`, `CGROUP_SOCK_ADDR`, `SOCKET_FILTER`,
///   `SOCK_OPS`, `CGROUP_SOCK`): enough for `DeviceAllow=`, per-unit
///   firewalls and IP accounting. LSM, kprobe, raw-tracepoint and tracing
///   program types are never granted below full wabbit trust — hostile
///   LSM programs would shadow enforcement and tracing programs give an
///   arbitrary-kernel-read primitive.
/// * `BPF_MAP_CREATE` and the `BPF_MAP_*_ELEM` commands: safe because a
///   process can only ever hold fds to maps it created or inherited —
///   the fd-by-ID lookup commands (`BPF_MAP_GET_FD_BY_ID`,
///   `BPF_PROG_GET_FD_BY_ID`) are never granted below full trust, and the
///   bpffs path gate already blocks opening wabbit's pins. Without a fd,
///   wabbit's maps — including the trusted-PID map — are unreachable.
/// * `BPF_PROG_ATTACH`/`BPF_LINK_CREATE` with cgroup-family attach types,
///   plus `BPF_BTF_LOAD`. LSM link creation stays wabbit-only.
///
/// The bit is only as strong as the cgroup walls around it: the
/// cgroup-migration protections must deny moving processes into a cgroup
/// holding this bit, or a rooted attacker joins init.scope by writing to
/// `cgroup.procs` and the class is decorative. For maps that stop needing
/// writes, `BPF_MAP_FREEZE` (kernel 5.2+, every target) is belt-and-braces:
/// a frozen map stays read-only from userspace forever, even against a
/// stolen fd.
pub const ACTION_BPF_ATTACH: u64 = 1 << 6;

/// Allow loading kernel modules (`finit_module(2)`/`init_module(2)`, gated
/// at `kernel_read_file` where `id == READING_MODULE`).
///
/// wabbit-initrd's own gate is path-based and deny-by-default for everyone
/// but the initrd's trusted PIDs, because its armed window is the boot and
/// only initrd code can execute then. The steady-state gate is
/// identity-based instead: every kernel in the target matrix hosts the
/// `kernel_read_file` LSM hook, but only some host it *sleepable* (which a
/// `bpf_d_path` allowlist needs), so the steady-state gate deliberately
/// resolves no path and loads everywhere: a cgroup without this bit may not
/// load modules at all, in-tree or not, and one with it may. That is
/// stricter than the boot gate (in-tree loads by anyone) — post-boot,
/// module loads should be nothing but package managers, and those run in
/// cgroups wabbit gets to authorize explicitly.
pub const ACTION_KMODS: u64 = 1 << 7;

/// Allow writing cgroupfs files under *protected* cgroups from the
/// outside.
///
/// `PROTECTED_PATHS` keys the cgroupfs paths whose integrity wabbit depends
/// on (its own cgroup, and every cgroup holding an authorization bit — the
/// walls around [`ACTION_BPF_ATTACH`] and this bit itself). The
/// `file_open` gate denies writable opens of files under those paths for
/// every cgroup outside them, which is what stops a rooted attacker from
/// migrating into a trusted cgroup through `cgroup.procs`, or from
/// freezing/killing a cgroup through `cgroup.freeze`/`cgroup.kill`. This
/// bit lifts that denial. A cgroup *inside* a protected path does not need
/// it: the gate only stops movement *into* a protected cgroup from
/// elsewhere.
pub const ACTION_CGROUPFS_WRITE: u64 = 1 << 8;

/// Allow modifying firewall rules.
///
/// What wabbit can gate on every target kernel is *both* rule paths:
///
/// * the **nfnetlink path** — `socket(AF_NETLINK, SOCK_RAW,
///   NETLINK_NETFILTER)`, the channel nftables and everything speaking it
///   uses (`nft`, `iptables-nft`/`ip6tables-nft` — the distro defaults —
///   firewalld, ipset, conntrack-tools). Gated at `socket_create` by the
///   `netfilter_netlink_gate` eBPF program, which keys on
///   `(family, protocol) == (AF_NETLINK, NETLINK_NETFILTER)`.
/// * the **legacy xtables path** — `setsockopt(fd, IPPROTO_IP|IPPROTO_IPV6,
///   IPT_SO_SET_REPLACE|IPT_SO_SET_ADD_COUNTERS)`. Gated at
///   `socket_setsockopt` by the `firewall_gate` eBPF program.
///
/// Grant the bit to the cgroups allowed to reconfigure the firewall (the
/// blue team's tooling), not to services. An *inherited* socket fd — one
/// handed across a cgroup boundary before the gate armed — keeps its
/// access; that residual is documented with the gate.
pub const ACTION_FIREWALL: u64 = 1 << 9;

/// How deep the eBPF prefix walks may go: 64 bytes.
///
/// A walk over a runtime-known length makes the verifier explore the whole
/// `(index × length)` pair space — quadratic, and at a 256-byte buffer the
/// first lab run measured 51,069 total states and the 1,000,000-insn
/// complexity limit ("BPF program is too large"). A constant cap bounds
/// the pair space to `cap²/2` ≈ 2k states, verified in bnuuy-like time.
///
/// This is a **loader contract**, not a silent truncation: the generator
/// (`wabbit-policy build`) rejects a `PATH_RULES` prefix longer than this,
/// and the loader rejects a policy entry that would exceed it. A path
/// *resolved* longer still resolves correctly — only its prefixes past
/// the cap go unchecked, and since every rule key is ≤ 64 bytes, no rule
/// can match past it either.
pub const PATH_WALK_CAP: usize = 64;

/// One path rule: the cgroup it applies to, and the hashed path prefix it
/// covers. The rule covers the prefix itself and everything below it.
///
/// The cgroup is the *exact* one keyed — children do not inherit (a cgroup
/// walk would need the ancestor walks this design forbids); the userspace
/// writes a rule per cgroup, and it knows the tree because it creates the
/// authorized children.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PathRuleKey {
    /// The cgroup whose processes the rule applies to.
    pub cgroup_id: u64,
    /// [`path_hash`] of the canonical path prefix — no trailing `/` —
    /// covering the prefix itself and everything below it.
    pub path_hash: u64,
}

/// A [`PATH_RULES`] value: a path rule's verdict bits. The simplified
/// path-rule model — the reference `PathAction` set (`Enoent`, `Sigkill`,
/// `Sigill`, `Sigseggv`) needs retval rewriting an LSM program cannot do,
/// so a rule is allow or deny and nothing else.
pub const PATH_RULE_ALLOW: u32 = 1 << 0;
pub const PATH_RULE_DENY: u32 = 1 << 1;

/// An [`Authorization`] flag: the cgroup's path rules are an *allow-list* —
/// every open under a path with no matching rule is denied, and only the
/// prefixes carrying [`PATH_RULE_ALLOW`] open. Without it the rules are a
/// *deny-list*: nothing is denied except the prefixes carrying
/// [`PATH_RULE_DENY`].
///
/// Resolution is longest-prefix-wins: the rule on the longest matching
/// path prefix decides, and a path matching no rule follows the default.
/// (In a deny-list profile an `ALLOW` bit is redundant; in an allow-list
/// profile a `DENY` bit is — the bit that would matter is the one the
/// default already supplies.)
pub const FLAG_PATH_RULES_DEFAULT_DENY: u64 = 1 << 0;

/// Decision-trace hook ids: the high half of a `DECISIONS` map key. Shared
/// by the eBPF gates (the writers) and the userspace self-test (the
/// reader), so both sides compute the same keys without one importing the
/// other.
pub const HOOK_BPF: u32 = 1;
pub const HOOK_KMOD: u32 = 2;
pub const HOOK_FILE_OPEN: u32 = 3;
pub const HOOK_SB_MOUNT: u32 = 4;
pub const HOOK_SETSOCKOPT: u32 = 5;
pub const HOOK_SOCKET_CREATE: u32 = 6;

/// Decision codes: the low half of a `DECISIONS` key. Every gate traces
/// what its rules decided — allow or would-deny — regardless of mode, so
/// the observing self-test can assert what it *would* have denied.
pub const CODE_ALLOWED: u32 = 0;
pub const CODE_WOULD_DENY: u32 = 1;

/// The `DECISIONS` key of one `(hook, code)` pair.
pub const fn decision_key(hook: u32, code: u32) -> u32 {
    (hook << 16) | code
}

/// The `ENFORCING` mode-switch values: the gates observe (`OBSERVE`) —
/// trace and allow — until the userspace self-test flips them to
/// `ENFORCE`.
pub const OBSERVE: u32 = 0;
pub const ENFORCE: u32 = 1;

/// FNV-1a 64 — the hash shared by the userspace and the eBPF programs for
/// path-keyed maps. Not cryptographic: it exists so `PROTECTED_PATHS` can
/// key on a fixed-size integer instead of a path string, with both sides
/// computing the same key. The eBPF side hashes the same bytes userspace
/// does (a canonical path, no trailing `/`, e.g. `/sys/fs/cgroup/wabbit`),
/// so a collision can only ever over-protect.
pub const fn path_hash(bytes: &[u8]) -> u64 {
    /// The FNV-1a 64 offset basis.
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    /// The FNV-1a 64 prime.
    const FNV_PRIME: u64 = 0x0000_0000_0100_0000_01b3 & 0xffff_ffff_ffff_ffff;
    let mut hash = OFFSET_BASIS;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        index += 1;
    }
    hash
}

const _: () = {
    // Known vectors, so a silent change of the hash breaks the build. The
    // last one is the key convention of `PROTECTED_PATHS`: the canonical
    // path, no trailing `/`.
    assert!(path_hash(b"") == 0xcbf2_9ce4_8422_2325);
    assert!(path_hash(b"a") == 0xaf63_dc4c_8601_ec8c);
    assert!(path_hash(b"wabbit") == 0xa881_58bb_0a03_ea60);
    assert!(path_hash(b"/sys/fs/cgroup/wabbit") == 0x24e5_6f43_9fde_b3f0);
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CgroupKey {
    pub cgroup_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Authorization {
    pub version: u32,
    pub size: u32,
    pub generation: u64,
    pub action_mask: u64,
    pub namespace_id: u64,
    pub flags: u64,
}

const _: () = assert!(size_of::<CgroupKey>() == 8);
const _: () = assert!(size_of::<Authorization>() == 40);
const _: () = assert!(size_of::<PathRuleKey>() == 16);

// The userspace (aya) side keys its maps with these types, and aya's
// `Pod` is an unsafe trait the kernel-side layouts must claim explicitly.
// All three are `#[repr(C)]` structs of integers and nothing else, so the
// claim is sound.
#[cfg(feature = "user")]
const _: () = {
    use aya::Pod;
    unsafe impl Pod for CgroupKey {}
    unsafe impl Pod for Authorization {}
    unsafe impl Pod for PathRuleKey {}
};
