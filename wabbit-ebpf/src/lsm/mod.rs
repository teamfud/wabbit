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
//! * **signals (`kill(2)`) to wabbit's processes** — the target task's
//!   cgroup cannot be read without deep `task_struct` walks (the exact
//!   class of unstable offsets this crate refuses); the cgroupfs walls
//!   (`cgroup.procs`, `cgroup.freeze`, `cgroup.kill`) cover the
//!   cgroup-level kill path, direct PID signals are residual.
//! * **`file_permission`** — not sleepable anywhere in the matrix; a
//!   write-by-write gate cannot resolve a path, and the open-time
//!   `f_mode` gate covers the writable-open case.

pub mod bpf_gate;
pub mod cgroupfs;
pub mod firewall;
pub mod kmod;
pub mod mount;
pub mod paths;
pub mod trust;
