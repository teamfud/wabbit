//! The `authorization` policy section: per-cgroup classes for the
//! steady-state gates.
//!
//! Wire layout, all integers little endian:
//!
//! ```text
//! AuthorizationConfig:
//!   count     u32, at most MAX_AUTHORIZATIONS
//!   Authorization * count:
//!     cgroup     u32 length + UTF-8 bytes   (the canonical cgroupfs path)
//!     action_mask u64                        (ACTION_* bits)
//!     flags      u64                        (FLAG_* bits)
//!     rule_count u32
//!     PathRule * rule_count:
//!       prefix    u32 length + UTF-8 bytes  (canonical, ≤ PATH_WALK_CAP)
//!       verdict   u8  (0 = allow, 1 = deny)
//! ```
//!
//! The section carries **paths, never ids**: a cgroup's kernfs id is
//! runtime state (an inode number), so the policy names cgroups by their
//! canonical path and the loader resolves them with `stat(2)` when it
//! populates the eBPF maps (see `wabbit_policy`'s docs and AGENTS.md).
//! The same holds for path-rule prefixes, which the loader hashes with
//! the shared `path_hash`.
//!
//! # Validation
//!
//! [`AuthorizationConfig::validate`] enforces every documented contract —
//! canonical paths (absolute, no trailing `/`), the [`PATH_WALK_CAP`]
//! limit on rule prefixes (the eBPF walks' documented loader contract),
//! known action and flag bits — and both the generator (`wabbit-policy
//! build`) and the loader call it before anything else sees the data.

use std::path::{Path, PathBuf};

use bilge::prelude::*;
use binrw::binrw;
use wabbit_common::authorization::{
    ACTION_BPF_ATTACH, ACTION_CGROUPFS_WRITE, ACTION_CREDENTIALS, ACTION_EXEC, ACTION_FIREWALL,
    ACTION_KMODS, ACTION_MOUNT, ACTION_SETNS, ACTION_TAG_CONTROL, ACTION_UNSHARE,
    FLAG_PATH_RULES_DEFAULT_DENY, PATH_WALK_CAP,
};

use crate::wire::{read_path, write_path};

/// At most this many authorization entries: the eBPF `AUTHORIZATIONS` map
/// is 1024 slots, and one entry populates one slot.
pub const MAX_AUTHORIZATIONS: usize = 1024;

/// Every action bit this version knows. The generator rejects any other
/// bit, and the loader maps bits to `Authorization::action_mask` verbatim.
pub const KNOWN_ACTIONS: u64 = ACTION_SETNS
    | ACTION_UNSHARE
    | ACTION_MOUNT
    | ACTION_EXEC
    | ACTION_CREDENTIALS
    | ACTION_TAG_CONTROL
    | ACTION_BPF_ATTACH
    | ACTION_KMODS
    | ACTION_CGROUPFS_WRITE
    | ACTION_FIREWALL;

/// Every authorization flag bit this version knows.
pub const KNOWN_FLAGS: u64 = FLAG_PATH_RULES_DEFAULT_DENY;

/// One path rule's verdict: the simplified model (the reference
/// `PathAction` set needs retval rewriting an LSM program cannot do).
pub const VERDICT_ALLOW: u8 = 0;
pub const VERDICT_DENY: u8 = 1;

/// A path rule: `prefix` (and everything below it) carries `verdict` for
/// the cgroup this rule belongs to. Resolution is longest-prefix-wins.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, PartialEq)]
pub struct PathRule {
    /// The canonical path prefix this rule covers: absolute, UTF-8, no
    /// trailing `/`, at most [`PATH_WALK_CAP`] bytes (the eBPF walk's
    /// documented contract — validated, never silently truncated).
    #[br(parse_with = read_path)]
    #[bw(write_with = write_path)]
    pub prefix: PathBuf,
    #[br(try_map = |verdict: u8| verdict.try_into().map_err(|()| "unknown path rule verdict"))]
    #[bw(map = |verdict: &PathRuleVerdict| u8::from(*verdict))]
    pub verdict: PathRuleVerdict,
}

/// One authorized cgroup: the actions its processes may take, its flags,
/// and its path rules.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizationEntry {
    /// The canonical cgroupfs path (e.g. `/sys/fs/cgroup/wabbit`): the
    /// loader resolves it to a kernfs id (`stat(2)`'s `st_ino`, the same
    /// id `bpf_get_current_cgroup_id` reports) when populating the maps.
    #[br(parse_with = read_path)]
    #[bw(write_with = write_path)]
    pub cgroup: PathBuf,
    /// The actions this cgroup's processes may take, as `ACTION_*` bits.
    pub action_mask: u64,
    /// The `FLAG_*` bits (today: `FLAG_PATH_RULES_DEFAULT_DENY`).
    pub flags: u64,
    #[br(temp, assert(rule_count as usize <= MAX_PATH_RULES, "too many path rules"))]
    #[bw(try_calc = u32::try_from(path_rules.len()))]
    rule_count: u32,
    #[br(count = rule_count)]
    #[bw(assert(path_rules.len() <= MAX_PATH_RULES, "too many path rules"))]
    pub path_rules: Vec<PathRule>,
}

/// At most this many rules per entry: the eBPF `PATH_RULES` map is 4096
/// slots across every cgroup, so one entry cannot exhaust it alone.
pub const MAX_PATH_RULES: usize = 256;

/// The `authorization` section: one entry per authorized cgroup.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthorizationConfig {
    #[br(temp, assert(entry_count as usize <= MAX_AUTHORIZATIONS, "too many authorization entries"))]
    #[bw(try_calc = u32::try_from(entries.len()))]
    entry_count: u32,
    #[br(count = entry_count)]
    #[bw(assert(entries.len() <= MAX_AUTHORIZATIONS, "too many authorization entries"))]
    pub entries: Vec<AuthorizationEntry>,
}

/// A path rule's verdict.
#[bitsize(1, new = pub)]
#[derive(FromBits, DebugBits, Clone, Copy, PartialEq, Eq)]
pub struct PathRuleVerdict {
    /// `true` denies the prefix for this cgroup; `false` allows it.
    pub deny: bool,
}

impl TryFrom<u8> for PathRuleVerdict {
    type Error = ();

    fn try_from(verdict: u8) -> Result<Self, Self::Error> {
        match verdict {
            VERDICT_ALLOW => Ok(Self::new(false)),
            VERDICT_DENY => Ok(Self::new(true)),
            _ => Err(()),
        }
    }
}

impl From<PathRuleVerdict> for u8 {
    fn from(verdict: PathRuleVerdict) -> Self {
        if verdict.deny() {
            VERDICT_DENY
        } else {
            VERDICT_ALLOW
        }
    }
}

impl AuthorizationConfig {
    /// Enforce every documented contract. Both the generator and the
    /// loader call this before anything else sees the data — a violation
    /// is a policy-authoring error, not a runtime one.
    pub fn validate(&self) -> Result<(), String> {
        for entry in &self.entries {
            validate_canonical(&entry.cgroup, "cgroup")?;
            if entry.action_mask & !KNOWN_ACTIONS != 0 {
                return Err(format!(
                    "unknown action bits in {:?} (mask {:#x})",
                    entry.cgroup, entry.action_mask
                ));
            }
            if entry.flags & !KNOWN_FLAGS != 0 {
                return Err(format!(
                    "unknown flag bits in {:?} (flags {:#x})",
                    entry.cgroup, entry.flags
                ));
            }
            for rule in &entry.path_rules {
                validate_canonical(&rule.prefix, "path rule prefix")?;
                let bytes = rule.prefix.to_str().expect("validated UTF-8 above");
                if bytes.len() > PATH_WALK_CAP {
                    return Err(format!(
                        "path rule prefix {bytes:?} exceeds the {}-byte walk cap",
                        PATH_WALK_CAP
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A canonical path: absolute, UTF-8, no trailing `/` (the `path_hash`
/// key convention both sides hash).
fn validate_canonical(path: &Path, what: &str) -> Result<(), String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{what} {:?} is not UTF-8", path))?;
    if !path.is_absolute() {
        return Err(format!("{what} {text:?} is not absolute"));
    }
    if text.len() > 1 && text.ends_with('/') {
        return Err(format!("{what} {text:?} ends with a trailing '/'"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use binrw::{BinRead, BinWrite};

    use super::*;

    fn entry() -> AuthorizationEntry {
        AuthorizationEntry {
            cgroup: "/sys/fs/cgroup/wabbit".into(),
            action_mask: KNOWN_ACTIONS,
            flags: FLAG_PATH_RULES_DEFAULT_DENY,
            path_rules: vec![
                PathRule {
                    prefix: "/etc/ssh".into(),
                    verdict: PathRuleVerdict::new(false),
                },
                PathRule {
                    prefix: "/etc/shadow".into(),
                    verdict: PathRuleVerdict::new(true),
                },
            ],
        }
    }

    fn config() -> AuthorizationConfig {
        AuthorizationConfig {
            entries: vec![entry()],
        }
    }

    fn encode(config: &AuthorizationConfig) -> binrw::BinResult<Vec<u8>> {
        let mut writer = Cursor::new(Vec::new());
        config.write(&mut writer)?;
        Ok(writer.into_inner())
    }

    fn decode(bytes: &[u8]) -> binrw::BinResult<AuthorizationConfig> {
        AuthorizationConfig::read(&mut Cursor::new(bytes))
    }

    #[test]
    fn round_trips() {
        assert_eq!(decode(&encode(&config()).unwrap()).unwrap(), config());
    }

    #[test]
    fn round_trips_empty() {
        let config = AuthorizationConfig::default();
        assert_eq!(decode(&encode(&config).unwrap()).unwrap(), config);
    }

    #[test]
    fn verdicts_convert() {
        assert_eq!(u8::from(PathRuleVerdict::new(false)), VERDICT_ALLOW);
        assert_eq!(u8::from(PathRuleVerdict::new(true)), VERDICT_DENY);
        assert_eq!(
            PathRuleVerdict::try_from(VERDICT_ALLOW).unwrap(),
            PathRuleVerdict::new(false)
        );
        assert_eq!(PathRuleVerdict::try_from(2), Err(()));
    }

    #[test]
    fn validates_a_sound_config() {
        assert_eq!(config().validate(), Ok(()));
    }

    #[test]
    fn rejects_unknown_bits_and_bad_paths() {
        let mut tampered = config();
        tampered.entries[0].action_mask = !KNOWN_ACTIONS;
        assert!(config().validate().is_ok());
        assert!(tampered.validate().is_err());

        let mut tampered = config();
        tampered.entries[0].flags = !KNOWN_FLAGS;
        assert!(tampered.validate().is_err());

        let mut tampered = config();
        tampered.entries[0].cgroup = "sys/fs/cgroup/wabbit".into();
        assert!(tampered.validate().is_err());

        let mut tampered = config();
        tampered.entries[0].cgroup = "/sys/fs/cgroup/wabbit/".into();
        assert!(tampered.validate().is_err());

        let mut tampered = config();
        tampered.entries[0].path_rules[0].prefix = "x".repeat(PATH_WALK_CAP + 1).into();
        assert!(tampered.validate().is_err());
    }
}
