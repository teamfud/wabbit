//! The steady-state LSM gates — `wabbit`'s own eBPF, distinct from bnuuy's
//! boot-window hooks.
//!
//! # Compatibility, per hook and distro
//!
//! The loadability facts below are the target matrix (rocky 9 = RHEL
//! 5.14, jammy = vanilla 5.15, bookworm = 6.1, noble = 6.8), verified
//! against the kernel sources and against bnuuy's lab runs:
//!
//! | Gate | Hook | Sleepable everywhere? | Notes |
//! | --- | --- | --- | --- |
//! | [`bpf_gate`] | `bpf` | needs no sleepable set (no `d_path`) | args 0–1 stable through 6.8; the phony retval shifts on mainline and is unread |
//! | [`kmod_gate`] | `kernel_read_file` | needs no sleepable set (no `d_path`) | `id == READING_MODULE == 2` on every target |
//! | [`cgroupfs`] | `file_open` | yes — in every matrix kernel's sleepable set | `struct file` was reordered: `_modern`/`_legacy` variants, kernel BTF picks |
//! | [`mount`] | `sb_mount` | yes — in every matrix kernel's sleepable set | `path` is arg 1, retval arg 5, stable through 6.8 |
//! | [`firewall`] | `socket_setsockopt`, `socket_create` | needs no sleepable set (no `d_path`) | both hooks stable 5.14→6.8; legacy xtables `setsockopt` and the nftables nfnetlink socket — the two rule paths |
//! | [`net`] | `socket_create`, `socket_bind` | needs no sleepable set (no `d_path`) | both hooks stable 5.14→6.8; `socket_create`'s scalar arguments key raw capture (`AF_PACKET`, `SOCK_RAW`), `socket_bind` reads only the sockaddr's uapi `sa_family` |
//! | [`signals`] | `task_kill` | needs no sleepable set (no `d_path`) | arg 0's *identity* plus one BTF-derived field: raw ctx-slot bits vs `bpf_get_current_task()` (an integer helper), both scalars — the verifier prohibits pointer comparisons — and, for the self-guard, `->tgid` read through a scalar probe at the offset the userspace parsed from the running kernel's own BTF (ground truth, never a compile-time guess). Self-signals and `SIGCONT` (the thaw channel every rescue broadcasts) always exempt; the self-guard denies every signal aimed at wabbit itself unless the system is shutting down |
//!
//! The distinction matters: a path-resolving gate (`bpf_d_path`) can only
//! load where its hook is in the kernel's `sleepable_lsm_hooks` set, and
//! that set varies per *distro* (RHEL's backports exceed vanilla 5.15).
//! Every gate here that resolves a path (`file_open`, `sb_mount`) sits on
//! a hook sleepable in the whole matrix; every gate on a hook that is not
//! sleepable somewhere (`kernel_read_file` is not, on vanilla 5.15)
//! resolves no path at all, so it loads everywhere. That is the design
//! rule that keeps this crate distro-version-free.
//!
//! # Enforcement and the mode switch
//!
//! Every gate closes with [`trust::verdict`], which consults
//! [`crate::maps::ENFORCING`]: the loader loads everything observing
//! (`ENFORCING == 0` — decisions traced into [`crate::maps::DECISIONS`],
//! nothing denied), runs its self-tests, then flips the map to enforce.
//! Trusted callers (wabbit's own PID and cgroup) pass before any gate's
//! rules run — wabbit must never be gated by its own protections.
//!
//! # Residuals, honestly listed
//!
//! * **inherited firewall/bpf sockets** — an fd handed across a cgroup
//!   boundary before the gate armed keeps its access; the `socket_create`
//!   and `bpf` gates the *creation*, not the inherited use (the exact
//!   class of residual a stale-fd gate carries; `socket_connect`/
//!   `sendmsg`/`bind` variants would need `struct sock` walks, which
//!   this design forbids — see [`firewall`]'s docs).
//! * **`move_mount`/`umount2`** — not in any matrix kernel's sleepable
//!   set, so no path-resolving protection can exist; mount *shuffling*
//!   past the `sb_mount` gate is documented (bnuuy carries the same
//!   residual).
//! * **writes through an fd opened before wabbit started** — `file_open`
//!   gates the open, not the write; bnuuy's residual, inherited. The path
//!   rules carry the same shape: a rule denies the *open*, and an fd
//!   opened before the rule was written keeps its access.
//! * **path rules apply to the exact cgroup keyed** — a child does not
//!   inherit its parent's rules (an ancestor walk would need the struct
//!   walks this design forbids), so the userspace writes a rule per
//!   cgroup; it knows the tree because it creates the authorized
//!   children.
//! * **signals (`kill(2)`) toward wabbit's processes** — the
//!   [`signals`] gate denies every cross-task signal without
//!   [`crate::maps::AUTHORIZATIONS`]' `signal` bit (self-signals
//!   exempt), and its **self-guard** denies every signal aimed at
//!   wabbit itself — the bit buys no path to the process that owns
//!   every wall — unless the system is shutting down (PID 1 always
//!   exempt; `SIGINT` is *not* exempt — the operator's stop channel is
//!   the signed `stop` IPC command, an authenticated request instead
//!   of a signal any process could send; see [`signals`]' docs). The
//!   *cgroup* distinction the sketch wanted (same- vs cross-cgroup
//!   targets) remains out of reach: the target's cgroup cannot be read
//!   without deep `task_struct` walks (the class of *compile-time*
//!   offsets this crate refuses — the self-guard's `->tgid` is read at
//!   an offset parsed from the running kernel's own BTF, ground
//!   truth); the cgroupfs walls (`cgroup.procs`, `cgroup.freeze`,
//!   `cgroup.kill`) still cover the cgroup-level kill path.
//! * **`file_permission`** — not sleepable anywhere in the matrix; a
//!   write-by-write gate cannot resolve a path, and the open-time
//!   `f_mode` gate covers the writable-open case.

pub mod bpf_gate;
pub mod cgroupfs;
pub mod firewall;
pub mod kmod;
pub mod mount;
pub mod net;
pub mod paths;
pub mod signals;
pub mod trust;
