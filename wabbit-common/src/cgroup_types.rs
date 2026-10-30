//! Cgroup *classes*: the authoring convention that lets one policy
//! define reusable, named authorization settings — "the shell class",
//! "the ultra-privileged class" — without `wabbit` ever understanding
//! classes as a format concept.
//!
//! The split is deliberate:
//!
//! * the **policy crate** owns classes at *authoring* time: `[[class]]`
//!   blocks in the TOML source, and `wabbit-policy build` compiles each
//!   concrete class into an ordinary cgroup rule — an
//!   `AuthorizationEntry` whose path follows the one convention this
//!   module spells out. Entries that reference a class (`class = "name"`)
//!   get its settings merged into theirs. The signed WSPF format
//!   carries no class concept at all: by the time a policy is signed,
//!   the classes are compiled away.
//! * **wabbit** owns the runtime half, and it is exactly one lookup: a
//!   signed run command may name a class, and the server resolves that
//!   name to the compiled entry by computing the same convention path
//!   against its own cgroup and looking the entry up in the *active*
//!   policy. No class in the policy, no run under that name.
//!
//! # The path convention
//!
//! A concrete class `shell` on a wabbit whose cgroup is
//! `/sys/fs/cgroup/wabbit` compiles to the entry
//! `/sys/fs/cgroup/wabbit/class/shell`, and each classed run gets an
//! **ephemeral child** under it: `run-<command id>` — the id is unique
//! and strictly increasing per boot, so no two runs share a cgroup and
//! no leftover can collide with a fresh one. Classless runs get the
//! same treatment under wabbit's own cgroup, with *no* authorization
//! written: deny-by-default is the least-privilege floor.
//!
//! Both the class path and the run child sit under wabbit's own cgroup,
//! whose hash is in `PROTECTED_PATHS` — so the migration wall
//! (`cgroup.procs`/`cgroup.freeze`/`cgroup.kill`) covers every run
//! cgroup by prefix, and nothing outside can move a process into one.
//!
//! # The reference mapping
//!
//! The sketch this file once carried (`CgroupPerm`, `GlobalPerm`,
//! `PathProfile`) is implemented by the policy vocabulary as follows —
//! "feasibly implemented" was the bar, and the rest is named rather
//! than silently missing:
//!
//! | sketch field | implemented as |
//! | --- | --- |
//! | `GlobalPerm::allow_mount` | the `mount` action (`ACTION_MOUNT`) |
//! | `GlobalPerm::allow_bpf` | the `bpf-attach` action (`ACTION_BPF_ATTACH`, the restricted system class; full `bpf(2)` stays wabbit-only) |
//! | `GlobalPerm::allow_kmods` | the `kmods` action (`ACTION_KMODS`) |
//! | `GlobalPerm::allow_writing_cgroupfs` | the `cgroupfs-write` action (`ACTION_CGROUPFS_WRITE`) |
//! | `GlobalPerm::allow_modifying_firewall` | the `firewall` action (`ACTION_FIREWALL`) |
//! | `priv_ns` (enter the private namespace) | the `setns` action (`ACTION_SETNS`) |
//! | `path_profile_map` | the per-cgroup path rules + the `default_deny` flag (`PATH_RULES` + `FLAG_PATH_RULES_DEFAULT_DENY` — the simplified `PathProfile`: per-operation read/write/exec allow-deny-or-fall-through, longest-deciding-prefix-wins) |
//! | `protect` | the `protect` flag (`FLAG_PROTECT` — the migration wall) |
//! | `allow_writing_execable_folders`, `allow_execing_writable_folders` | the rootfs section's per-path mount flags (RDONLY/NOEXEC at mount time) and the per-cgroup path rules — mount-level policy, not per-process action bits |
//! | `supv` | deliberately unimplemented: wabbit stays its own sole supervisor, and a "take actions that might endanger wabbit" bit would be a hole with the same shape as the trust it grants |
//! | `allow_raw_network_capture` | the `raw-capture` action (`ACTION_RAW_CAPTURE` — `AF_PACKET` and `SOCK_RAW` socket creation, at `socket_create`) |
//! | `allow_bind_net_sockets`, `allow_bind_local_sockets` | the `bind-net` action (`ACTION_BIND_NET` — network `bind(2)` denied by default); the local half of the sketch is deliberately **ungated**: `AF_UNIX` is every daemon's connective tissue (systemd, journald, dbus), and holding it hostage would break every boot — the vocabulary carries no `bind-local` at all |
//! | `allow_signaling_other_cgroups` | the `signal` action (`ACTION_SIGNAL_OTHERS` — `task_kill`, narrowed honestly: the target's *cgroup* is unreadable without the `task_struct` walks this design forbids, so the bit gates cross-*task* signaling with self-signals always exempt, and cannot distinguish same-cgroup targets) |
//! | `allow_debugging`, `allow_systemd`, `allow_power_management` | not feasible in the current gate set: each needs an LSM hook the guard does not host (`ptrace_access_check` without a target identity worth gating on, and no hook at all for the systemd/power shapes). They stay **out** of the policy vocabulary rather than present-but-unenforced — an action bit nothing denies is a lie with a signature on it |

use crate::authorization::PATH_WALK_CAP;

/// The unified cgroup hierarchy's canonical mount point.
///
/// Shared by the policy crate (which validates entries naming it) and
/// wabbit's loader (which must never put it in `PROTECTED_PATHS`: the
/// root is a *prefix of every cgroupfs path*, so walling it would deny
/// every `cgroup.procs` write on the machine).
pub const CGROUPFS_ROOT: &str = "/sys/fs/cgroup";

/// The path segment every class's compiled entry lives under: a class
/// `shell` on wabbit's cgroup is the entry `<wabbit-cgroup>/class/shell`.
///
/// The segment is a convention both sides compute — the policy crate
/// when it compiles a class into an entry, wabbit when a signed run
/// command names the class. A cgroup named `class` directly under
/// wabbit's own is therefore reserved by the format.
pub const CLASS_SEGMENT: &str = "class";

/// The ephemeral run-cgroup prefix: every run's cgroup is
/// `<parent>/run-<command id>`.
pub const RUN_PREFIX: &str = "run-";

/// The widest a class name may be. Names are path components in the
/// cgroupfs *and* pieces of the compiled entry path, which must fit the
/// eBPF walk cap — the cap is the real bound ([`class_cgroup_fits`]);
/// this keeps comfortably inside it for any plausible wabbit cgroup.
pub const CLASS_NAME_MAX_BYTES: usize = 24;

/// A valid class name: 1–[`CLASS_NAME_MAX_BYTES`] bytes of `[a-z0-9-]`,
/// no leading or trailing `-`.
///
/// A run command carries a class name on the wire, and the server
/// builds a cgroupfs path from it — so the charset is a security
/// boundary, not cosmetics: no `/` (traversal), no `.`, nothing a path
/// could reinterpret.
pub fn valid_class_name(name: &str) -> bool {
    if name.is_empty() || name.len() > CLASS_NAME_MAX_BYTES {
        return false;
    }
    let bytes = name.as_bytes();
    let all = bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    all && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && (last.is_ascii_lowercase() || last.is_ascii_digit())
}

/// Whether the compiled entry path for class `name` under wabbit's own
/// cgroup — `<own>/class/<name>` — fits inside the eBPF walk cap.
///
/// This is a **loader contract**, same shape as the rule-prefix cap:
/// `PROTECTED_PATHS` keys on the full path's hash, and the eBPF prefix
/// walk only computes hashes for the first [`PATH_WALK_CAP`] bytes, so
/// a longer class path could never be walled — the generator rejects
/// it, and the runtime refuses to resolve it, rather than protecting
/// nothing silently.
pub fn class_cgroup_fits(own: &str, name: &str) -> bool {
    valid_class_name(name) && own.len() + 1 + CLASS_SEGMENT.len() + 1 + name.len() <= PATH_WALK_CAP
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::format;

    use super::*;

    #[test]
    fn class_names_are_a_security_boundary() {
        assert!(valid_class_name("shell"));
        assert!(valid_class_name("ultra-privileged-9"));
        assert!(valid_class_name("a"));
        // Traversal and friends: the server builds cgroupfs paths from
        // these, so every shape that could reinterpret is rejected.
        assert!(!valid_class_name(""));
        assert!(!valid_class_name("/etc"));
        assert!(!valid_class_name("../escape"));
        assert!(!valid_class_name("has space"));
        assert!(!valid_class_name("UPPER"));
        assert!(!valid_class_name("under_score"));
        assert!(!valid_class_name(".hidden"));
        assert!(!valid_class_name("-leading"));
        assert!(!valid_class_name("trailing-"));
        assert!(!valid_class_name(&"x".repeat(CLASS_NAME_MAX_BYTES + 1)));
    }

    #[test]
    fn class_paths_must_fit_the_walk_cap() {
        // The realistic shape: a plausible wabbit cgroup and the widest
        // legal name, well inside the cap.
        assert!(class_cgroup_fits("/sys/fs/cgroup/wabbit", "shell"));
        assert!(class_cgroup_fits("/sys/fs/cgroup/wabbit", &"x".repeat(24)));

        // The boundary, exactly: the joined path is
        // `<own> + "/class/" + <name>`, and it must stay ≤ 64 bytes.
        let fits = format!("/{}", "w".repeat(64 - "/class/".len() - 24 - 1));
        assert!(class_cgroup_fits(&fits, &"x".repeat(24)));
        let too_long = format!("/{}", "w".repeat(64 - "/class/".len() - 24));
        assert!(!class_cgroup_fits(&too_long, &"x".repeat(24)));

        // An invalid name never fits, whatever the base.
        assert!(!class_cgroup_fits("/sys/fs/cgroup/wabbit", "sh/ell"));
    }
}
