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

/// Allow raw packet capture: creating an `AF_PACKET` socket (tcpdump's
/// own channel — every packet on the wire, including other processes'
/// traffic) or a raw IP socket (`socket(AF_INET|AF_INET6, SOCK_RAW, …)`,
/// hand-crafted IP packets and sniffing). Gated at `socket_create` by the
/// `raw_capture_gate` eBPF program, which keys on the family and the
/// `SOCK_RAW` type — plain scalar arguments, so the gate loads on every
/// target kernel. Kernel-internal creation (`kern == 1`) is exempt.
pub const ACTION_RAW_CAPTURE: u64 = 1 << 10;

/// Allow `bind(2)` on network sockets (`AF_INET`/`AF_INET6`): acquiring a
/// listening or connected local endpoint. Gated at `socket_bind` by the
/// `bind_gate` eBPF program, which reads the sockaddr's family through
/// `bpf_probe_read_kernel` (the first member of `struct sockaddr`, a
/// stable uapi layout) and consults this bit. Every other family —
/// netlink binds (udev's uevents, rtnl), netfilter's own netlink, and
/// `AF_UNIX` above all — passes untouched: local IPC is the machine's
/// connective tissue and is deliberately ungated.
pub const ACTION_BIND_NET: u64 = 1 << 11;

/// Use the `bpf(2)` syscall **unfiltered**: every command, every program
/// type, every attach type — what the [`ACTION_BPF_ATTACH`] "systemd
/// class" deliberately is not.
///
/// The restricted class exists because `bpf(2)` below full trust is
/// sharp at both ends: the fd-by-ID lookup commands
/// (`BPF_MAP_GET_FD_BY_ID`, `BPF_PROG_GET_FD_BY_ID`) are the one route to
/// wabbit's maps that bypasses bpffs — an LSM program loaded from a
/// lesser cgroup would shadow enforcement, a tracing program is an
/// arbitrary-kernel-read primitive, and `BPF_PROG_LOAD` of either type
/// is the same `bpf(2)` the class already grants. This bit grants
/// exactly that: a cgroup holding it can do anything with `bpf(2)`
/// short of nothing. It is deliberately **not** an upgrade path the
/// default entry may carry (see [`DEFAULT_ALLOWED_ACTIONS`]) — handed to
/// every unlisted cgroup it hands the whole machine the keys.
///
/// **The bit lifts the `bpf(2)` gate alone.** The bpffs open gate
/// (`file_open`, `cgroupfs.rs`) still denies this cgroup's opens of
/// wabbit's pins — reads included — because pins are path-shaped and
/// the fd-by-ID lookups are the sanctioned route; the pins' parent
/// directory's permissions are the operator's to set. A cgroup holding
/// this bit can therefore reach wabbit's maps by ID if it goes looking —
/// that is what "unfiltered" means, and the policy signer who grants it
/// is choosing that.
///
/// Grant it where a tool genuinely needs the full syscall (an
/// observability agent loading its own tracing programs, a bpffs
/// power-user) and nowhere else: the walls around the cgroup holding it
/// must hold, or the machine is anyone's — see [`ACTION_BPF_ATTACH`]'s
/// closing paragraph, which applies double here.
pub const ACTION_BPF_FULL: u64 = 1 << 12;

/// The reserved [`CgroupKey`] id of the policy's **default** entry: the
/// `Authorization` (and the `PATH_RULES`) a cgroup with no entry of its
/// own falls back to. kernfs ids start at 1 — the cgroupfs root's — so
/// no real cgroup can collide with it.
///
/// The fallback is for *unlisted* cgroups only: a listed cgroup gets
/// exactly its own entry, never the default's bits or rules on top. The
/// `task_kill` gate ignores the default entirely — unlisted cgroups keep
/// their default-allow signal posture, the failure-safety contract (see
/// [`ACTION_SIGNAL_OTHERS`]).
pub const DEFAULT_CGROUP_ID: u64 = 0;

/// The action bits a default entry may carry. Everything else is
/// rejected by the generator and the loader: the wall-lifting bits
/// (`mount`, `cgroupfs-write`, `bpf-attach`) handed to every unlisted
/// cgroup would dissolve the walls the whole class model leans on, and
/// `signal` is never consulted from the default (see
/// [`DEFAULT_CGROUP_ID`]) — a grant that silently means nothing is
/// rejected by name instead.
pub const DEFAULT_ALLOWED_ACTIONS: u64 =
    ACTION_KMODS | ACTION_FIREWALL | ACTION_RAW_CAPTURE | ACTION_BIND_NET;

/// `NET_POSTURE` index: how far the `bind_gate` reaches — one of the
/// `BIND_GATE_*` values. The policy's `network` section sets it; an
/// unpopulated map reads `0`, the strictest posture.
pub const NET_POSTURE_BIND: u32 = 0;
/// `NET_POSTURE` index: how far the `raw_capture_gate` reaches — one of
/// the `RAW_CAPTURE_GATE_*` values.
pub const NET_POSTURE_RAW_CAPTURE: u32 = 1;

/// `SELF_GUARD` index: wabbit's own tgid — the one process the
/// self-guard protects from outside signals (see the `signal_gate`
/// docs). The loader writes it at startup; `0` means unarmed and the
/// eBPF side never matches it (a real tgid is never `0`).
pub const SELF_GUARD_TGID: u32 = 0;
/// `SELF_GUARD` index: the byte offset of `tgid` in `struct task_struct`,
/// parsed at load out of the *running* kernel's own BTF
/// (`wabbit/src/btf.rs`) — never a compile-time guess, because
/// `task_struct` is exactly the struct distros patch and a wrong offset
/// reads silent garbage (the fork-record lesson). `0` means unarmed: the
/// gate fail-opens rather than probing at a guessed offset.
pub const SELF_GUARD_TGID_OFFSET: u32 = 1;
/// `SELF_GUARD` index: the shutdown relaxation. The userspace sets it
/// when its shutdown watch observes the system going down (PID 1
/// exiting, the shutdown re-exec, or the SIGTERM only an exempt sender
/// could have delivered) — from then on the self-guard decides nothing,
/// which is the "unless the system is shutting down" of the protection.
pub const SELF_GUARD_SHUTDOWN: u32 = 2;

/// Every `AF_INET`/`AF_INET6` `bind(2)` needs [`ACTION_BIND_NET`] — the
/// ephemeral port-0 binds clients make included.
pub const BIND_GATE_ALL: u32 = 0;
/// Only a bind that names a specific port needs [`ACTION_BIND_NET`]: a
/// port-0 bind (the kernel picks an ephemeral port — the client shape)
/// passes, so outbound connectivity is never gated, only claiming a port.
pub const BIND_GATE_PORTS: u32 = 1;
/// The bind gate decides nothing: every bind passes.
pub const BIND_GATE_OFF: u32 = 2;

/// `AF_PACKET` sockets and `SOCK_RAW` at the IP families both need
/// [`ACTION_RAW_CAPTURE`].
pub const RAW_CAPTURE_GATE_ALL: u32 = 0;
/// The ICMP exception: raw `IPPROTO_ICMP` sockets at `AF_INET` and raw
/// `IPPROTO_ICMPV6` sockets at `AF_INET6` pass (`ping`, `traceroute -I`,
/// and the ICMP-error receive side of classic `traceroute`); `AF_PACKET`
/// and every other raw IP protocol still need [`ACTION_RAW_CAPTURE`] —
/// a raw `IPPROTO_TCP`/`IPPROTO_UDP` socket receives copies of every
/// inbound packet of its protocol, which is sniffing by another name.
pub const RAW_CAPTURE_GATE_ICMP: u32 = 1;
/// The raw-capture gate decides nothing: every socket passes.
pub const RAW_CAPTURE_GATE_OFF: u32 = 2;

/// Allow signaling any task other than the caller's own: `kill(2)`,
/// `tgkill(2)`, `tkill(2)`, `pidfd_send_signal(2)` — gated at
/// `task_kill` by the `signal_gate` eBPF program.
///
/// **Self-signals are always exempt** (`raise(3)`, `kill(getpid())`,
/// a thread's own exits): the one identity check the design can afford
/// is target-`task_struct` == current, compared as raw scalar bits (the
/// verifier prohibits pointer comparisons, and the target's *cgroup*
/// would need the deep `task_struct` walks this design forbids — which
/// also means the bit cannot distinguish same-cgroup from cross-cgroup
/// targets). **`SIGCONT` is always exempt too**: it is the thaw channel
/// every rescue path broadcasts (the handoff resume, the drop backstop,
/// the watchdog), from whatever cgroup the rescue runs in, and the
/// failure-safety contract — a frozen world never outlives a failed
/// boot — outranks signaling containment. A cgroup without the bit can
/// still raise itself. **The posture is default-allow for unlisted
/// cgroups**: a cgroup with no `Authorization` entry may signal any
/// task (the unlisted world of a boot — initramfs units, session
/// scopes — never loses `kill(2)` to a boundary nobody drew), while a
/// listed cgroup gets exactly its bits — the operator who names a
/// cgroup chooses whether it may signal. Grant it where a listed
/// cgroup does process management legitimately (PID 1's unit
/// management, udev's worker pool, a shell's job control); omit it
/// where cross-task signaling is the thing to contain.
///
/// **The bit never reaches wabbit itself**: the `signal_gate` carries a
/// *self-guard* — signals toward wabbit's own tgid are denied for every
/// caller (bit or no bit, listed or unlisted) unless the system is
/// shutting down (see `HOOK_SIGNAL_WABBIT` and the `SELF_GUARD_*`
/// indexes). The bit governs the rest of the machine's signaling; the
/// guard is not the signer's to trade away.
pub const ACTION_SIGNAL_OTHERS: u64 = 1 << 13;

/// The per-cgroup **path rules decide nothing** for this cgroup: the
/// `file_open` gate's path-rule resolution is skipped entirely — opens
/// under it are governed by the *other* `file_open` protections alone.
///
/// This is the **trusted-user** grant. A policy that walls machine
/// configuration off with path rules (`[default]` denies for `/etc`,
/// an entry's allow-list) still needs a way for a *trusted* principal
/// to edit those very paths — the operator's shell, an admin session,
/// a deployment tool. Spelling an `allow` rule for every denied
/// prefix per operator cgroup is lockstep bookkeeping against the
/// default section; this bit is the one-line form: grant it to the
/// operator's cgroup (a listed login or service scope) or an operator
/// `[[class]]` (a classed run), and path rules stop applying to that
/// cgroup's opens — read, write, and exec classes alike, its own
/// rules and the `[default]` entry's alike.
///
/// What it does **not** lift — the boundary that keeps it honest:
///
/// * **bpffs opens** (wabbit's pins, reads included) — pins are not
///   path rules;
/// * **the module-tree write gate** (`ACTION_KMODS`) — planting a
///   `.ko` is not editing a configuration file;
/// * **the migration wall** (`cgroup.procs`/`freeze`/`kill` under
///   protected paths, `ACTION_CGROUPFS_WRITE`) — the wall around every
///   other bit, this one included;
/// * every other gate (`bpf`, mounts, firewall, sockets, signals).
///
/// And it is a **wall-lifting bit** in the `[default]`'s sense: handed
/// to every unlisted cgroup it dissolves the per-cgroup file profile
/// machine-wide, so `wabbit-policy build` refuses it there by name.
/// The signer who grants it to a *listed* cgroup is choosing that that
/// cgroup's opens are governed by the structural walls alone — that is
/// what "trusted" means here, and the signature is what says so.
pub const ACTION_PATH_BYPASS: u64 = 1 << 14;

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

/// A [`PATH_RULES`] value: a path rule's verdict, per operation class.
///
/// The simplified path-rule model — the reference `PathAction` set
/// (`Enoent`, `Sigkill`, `Sigill`, `Sigseggv`) needs retval rewriting an
/// LSM program cannot do — so a rule's verdict is per-operation allow or
/// deny and nothing else. The three operation classes an open can carry
/// at `file_open`:
///
/// * **read** — any open of the path at all;
/// * **write** — a writable open (`f_mode & FMODE_WRITE`);
/// * **exec** — an execve open (`f_flags & __FMODE_EXEC`, 0x20, which
///   `do_open_execat` sets in the open flags; `OPEN_FMODE` never copies
///   it into `f_mode`, and `VALID_OPEN_FLAGS` excludes it, so a
///   userspace `open(2)` cannot counterfeit the marker).
///
/// One allow and one deny bit per class. A value with neither bit of a
/// class set does not decide that class: resolution falls through to the
/// next rule that does, and past every rule to the cgroup default
/// ([`FLAG_PATH_RULES_DEFAULT_DENY`]). The wire encoding
/// (`wabbit-policy`'s `PathRuleVerdict`, six bits of a `u8`) maps onto
/// these bits one to one, so the loader translates a rule verbatim.
pub const PATH_RULE_READ_ALLOW: u32 = 1 << 0;
pub const PATH_RULE_READ_DENY: u32 = 1 << 1;
pub const PATH_RULE_WRITE_ALLOW: u32 = 1 << 2;
pub const PATH_RULE_WRITE_DENY: u32 = 1 << 3;
pub const PATH_RULE_EXEC_ALLOW: u32 = 1 << 4;
pub const PATH_RULE_EXEC_DENY: u32 = 1 << 5;

/// An [`Authorization`] flag: the cgroup's path rules are an *allow-list* —
/// for every operation class, an open under a path no matching rule
/// *decides* is denied, and only a rule carrying that class's `*_ALLOW`
/// bit opens. Without it the rules are a *deny-list*: nothing is denied
/// except what a rule carrying a `*_DENY` bit denies.
///
/// Resolution is per operation class, longest-deciding-prefix-wins: the
/// deepest rule that *speaks for* the open's class (read, write, or exec)
/// decides it, a rule that leaves the class unspecified falls through to
/// the next shallower rule, and a class no rule decides follows this
/// default. (In a deny-list profile an `ALLOW` bit is redundant; in an
/// allow-list profile a `DENY` bit is — the bit that would matter is the
/// one the default already supplies.)
pub const FLAG_PATH_RULES_DEFAULT_DENY: u64 = 1 << 0;

/// An [`Authorization`] flag: this cgroup is **protected** — the
/// migration wall applies to it.
///
/// The loader adds the cgroup's canonical path to `PROTECTED_PATHS`,
/// which the `file_open` and `sb_mount` gates consult: for every cgroup
/// *outside* the protected path, writable opens of files under it
/// (`cgroup.procs`, `cgroup.freeze`, `cgroup.kill` — the migration and
/// kill paths) and mounts over it are denied, so nothing can move a
/// process into a protected cgroup, freeze it, or kill it through the
/// cgroupfs. Every cgroup holding an action bit is protected
/// automatically — the walls around those bits are load-bearing — so
/// this flag's purpose is to extend the same wall to cgroups that hold
/// no bits at all (the sketch's `protect`: a cgroup the blue team wants
/// migration-proofed for its own sake).
pub const FLAG_PROTECT: u64 = 1 << 1;

/// An [`Authorization`] flag: **opt this cgroup out of the migration
/// wall** its action bits would otherwise give it.
///
/// Bit-holding cgroups are walled automatically — but the wall has one
/// legitimate exception, and it is signed-policy business: **PID 1
/// bootstraps into `init.scope` from outside every wall** (it starts in
/// the root cgroup and migrates itself before anything is authorized),
/// so an `init.scope` carrying boot-time grants could never receive
/// them walled. The signer who sets this flag accepts the trade: a
/// process able to write `cgroup.procs` from outside may join this
/// cgroup. It is contradictory with [`FLAG_PROTECT`] and rejected
/// together with it.
pub const FLAG_UNPROTECTED: u64 = 1 << 2;

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
pub const HOOK_BIND: u32 = 7;
pub const HOOK_TASK_KILL: u32 = 8;
/// The self-guard's decision point: a signal was aimed at wabbit's own
/// tgid and denied (or, in the observing phase, traced as a would-deny).
/// Distinct from [`HOOK_TASK_KILL`] so the self-test can assert the
/// protection fired *as itself*, not as the listed-cgroup posture.
pub const HOOK_SIGNAL_WABBIT: u32 = 9;

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

/// One **protected cgroup** — a *yard* — as `PROTECTED_PATHS`' value: the
/// cgroup's kernfs id and its level in the unified hierarchy (the root is
/// level 0). The eBPF wall compares the id with the *opening caller's*
/// ancestors (`bpf_get_current_ancestor_cgroup_id`) to tell the yard's own
/// insiders — a task at or below the yard, managing its own subtree —
/// from the outsiders the wall exists for.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Yard {
    pub cgroup_id: u64,
    pub level: u32,
    pub _reserved: u32,
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
const _: () = assert!(size_of::<Yard>() == 16);
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
    unsafe impl Pod for Yard {}
};
