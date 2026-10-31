//! The `default` policy section: what a cgroup with no authorization
//! entry of its own gets.
//!
//! Wire layout, all integers little endian:
//!
//! ```text
//! DefaultConfig:
//!   action_mask  u64                 (ACTION_* bits, within
//!                                     DEFAULT_ALLOWED_ACTIONS)
//!   rule_count   u32, at most MAX_PATH_RULES
//!   PathRule * rule_count            (the authorization section's rule
//!                                     encoding, verbatim)
//! ```
//!
//! The loader writes it as one more `AUTHORIZATIONS` entry under the
//! reserved `DEFAULT_CGROUP_ID`, with its rules keyed the same way, and
//! the gates fall back to it for every cgroup the `authorization` section
//! does not list. A listed cgroup gets exactly its own entry — the
//! default never adds to it.
//!
//! # What a default cannot say
//!
//! * **wall-lifting bits** — `mount`, `cgroupfs-write`, `bpf-attach`,
//!   `bpf-full`, `path-bypass`: handed to every unlisted cgroup, they
//!   would dissolve the migration, bpf, and per-cgroup file-profile
//!   walls the class model leans on. Rejected by name.
//! * **`signal`** — the `task_kill` gate never consults the default
//!   (unlisted cgroups keep their default-allow signal posture, the
//!   failure-safety contract), so the grant would mean nothing. Rejected
//!   rather than silently ignored.
//! * **an allow-list** (`default_deny`) — the default reaches every
//!   unnamed service (journald, dbus, logind, getty …); an allow-list
//!   missing one of their paths makes the boot unusable. The wire has no
//!   flags field at all: the default's rules are a deny-list.

use binrw::binrw;
use wabbit_common::authorization::{
    ACTION_BPF_ATTACH, ACTION_BPF_FULL, ACTION_CGROUPFS_WRITE, ACTION_MOUNT, ACTION_PATH_BYPASS,
    ACTION_SIGNAL_OTHERS, DEFAULT_ALLOWED_ACTIONS,
};

use crate::authorization::{KNOWN_ACTIONS, MAX_PATH_RULES, PathRule, validate_path_rules};

/// The default entry for unlisted cgroups.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DefaultConfig {
    /// The actions every unlisted cgroup may take, as `ACTION_*` bits.
    pub action_mask: u64,
    #[br(temp, assert(rule_count as usize <= MAX_PATH_RULES, "too many path rules"))]
    #[bw(try_calc = u32::try_from(path_rules.len()))]
    rule_count: u32,
    /// The deny-list every unlisted cgroup's opens are checked against.
    #[br(count = rule_count)]
    #[bw(assert(path_rules.len() <= MAX_PATH_RULES, "too many path rules"))]
    pub path_rules: Vec<PathRule>,
}

impl DefaultConfig {
    /// Enforce the section's contracts (see the module docs). Both the
    /// generator and the loader call this before anything else sees the
    /// data.
    pub fn validate(&self) -> Result<(), String> {
        if self.action_mask & !KNOWN_ACTIONS != 0 {
            return Err(format!(
                "unknown action bits in the default (mask {:#x})",
                self.action_mask
            ));
        }
        if self.action_mask
            & (ACTION_MOUNT
                | ACTION_CGROUPFS_WRITE
                | ACTION_BPF_ATTACH
                | ACTION_BPF_FULL
                | ACTION_PATH_BYPASS)
            != 0
        {
            return Err(
                "the default may not grant mount, cgroupfs-write, bpf-attach, bpf-full, \
                 or path-bypass: every unlisted cgroup would hold the walls' keys"
                    .into(),
            );
        }
        if self.action_mask & ACTION_SIGNAL_OTHERS != 0 {
            return Err(
                "the default may not grant signal: unlisted cgroups may already \
                 signal, and the signal gate never consults the default"
                    .into(),
            );
        }
        if self.action_mask & !DEFAULT_ALLOWED_ACTIONS != 0 {
            return Err(format!(
                "the default may only grant kmods, firewall, raw-capture, and bind-net \
                 (mask {:#x})",
                self.action_mask
            ));
        }
        validate_path_rules(&self.path_rules)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use binrw::{BinRead, BinWrite};
    use wabbit_common::authorization::{ACTION_BIND_NET, ACTION_KMODS};

    use super::*;
    use crate::authorization::PathRuleVerdict;

    fn sample() -> DefaultConfig {
        DefaultConfig {
            action_mask: ACTION_BIND_NET,
            path_rules: vec![PathRule {
                prefix: "/etc/shadow".into(),
                verdict: PathRuleVerdict::deny_all(),
            }],
        }
    }

    #[test]
    fn round_trips() {
        let mut writer = Cursor::new(Vec::new());
        sample().write(&mut writer).unwrap();
        let back = DefaultConfig::read(&mut Cursor::new(writer.into_inner())).unwrap();
        assert_eq!(back, sample());
        sample().validate().unwrap();
    }

    #[test]
    fn rejects_wall_lifting_and_signal_grants() {
        for bit in [
            ACTION_MOUNT,
            ACTION_CGROUPFS_WRITE,
            ACTION_BPF_ATTACH,
            ACTION_BPF_FULL,
            ACTION_PATH_BYPASS,
            ACTION_SIGNAL_OTHERS,
        ] {
            let config = DefaultConfig {
                action_mask: ACTION_KMODS | bit,
                path_rules: Vec::new(),
            };
            assert!(config.validate().is_err(), "bit {bit:#x}");
        }
    }

    #[test]
    fn rejects_bad_rules() {
        let config = DefaultConfig {
            action_mask: 0,
            path_rules: vec![PathRule {
                prefix: "/etc/".into(),
                verdict: PathRuleVerdict::deny_all(),
            }],
        };
        assert!(config.validate().is_err());
    }
}
