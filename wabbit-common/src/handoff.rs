//! The handoff protocol between `wabbit-initrd` and `wabbit`, over the
//! socketpair `wabbit-initrd` creates and dups to [`SOCKET_FD`]
//! (`docs/startup.mermaid`):
//!
//! ```text
//! winit   → "trusted"  the bpf(2) trust grant has landed (wabbit's first
//!                      bpf(2) call would race it; it waits for this)
//! wabbit  → "ready"   the guard is enforcing and self-tested
//! winit   → "die"    the pre-shutdown self-test passed; go cross
//! wabbit  → "ack"    winit may exit (its bnuuy links detach with it)
//! winit exits; the init resumes, switch_root runs, wabbit crosses
//! ```
//!
//! The messages are single `\n`-terminated words over the socketpair
//! `wabbit-initrd` creates and dups to [`SOCKET_FD`], whose number reaches
//! `wabbit` through the `<prefix>_HANDOFF_FD` environment variable (the
//! name is built per-binary from [`crate::brand::ENV_PREFIX`], as the
//! other `<prefix>_` variables are).
//!
//! EOF on either side is fail-open, never a stall: `wabbit` reads EOF when
//! `wabbit-initrd` dies by any cause (the watchdog thaws the world, the
//! boot proceeds, and `wabbit` continues into its switch-root polls);
//! `wabbit-initrd` reads EOF when `wabbit` dies (the sign explains, the
//! boot continues protected by nothing, which beats frozen).

use core::ffi::c_int;

/// The socketpair descriptor `wabbit-initrd` dups the socket to in the
/// child. Fixed on purpose: `dup2` clears `FD_CLOEXEC` on the copy, so the
/// descriptor number is stable whatever other descriptors either side
/// holds.
pub const SOCKET_FD: c_int = 3;

/// `wabbit` → `wabbit-initrd`: the guard is enforcing and self-tested.
pub const READY: &[u8] = b"ready\n";

/// `wabbit-initrd` → `wabbit`: the pre-shutdown self-test passed, go cross.
pub const DIE: &[u8] = b"die\n";

/// `wabbit` → `wabbit-initrd`: acknowledged; `wabbit-initrd` may exit.
pub const ACK: &[u8] = b"ack\n";

/// `wabbit-initrd` → `wabbit`: the `bpf(2)` trust grant has landed in
/// bnuuy's `TRUSTED_BPF_PIDS` map, and the cgroup migration is done.
///
/// `wabbit`'s first `bpf(2)` calls — the guard object's map creates —
/// race this grant: both sides run after the same fork, and nothing
/// else orders them. Before the grant landed, the gate read the trust
/// map without `wabbit`'s PID and denied the creates (`EPERM`), a
/// failure the lab measured as *nondeterministic* across boots of the
/// same artifact. `wabbit` therefore reads this message — blocking, on
/// the same socket the rest of the protocol uses — before its first
/// `bpf(2)` call, turning the race into a rendezvous.
pub const TRUSTED: &[u8] = b"trusted\n";
