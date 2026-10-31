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
//!       verdict   u8, per-operation bits:
//!                   bit 0: read specified   bit 1: read denied
//!                   bit 2: write specified  bit 3: write denied
//!                   bit 4: exec specified   bit 5: exec denied
//!                 0b01 allows the operation for this prefix, 0b11 denies
//!                 it, 0b00 decides nothing (resolution falls through to
//!                 the next rule, and past every rule to the cgroup
//!                 default); bits 6–7 must be zero. A rule that decides
//!                 no operation at all is rejected by `validate`.
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

use binrw::binrw;
use wabbit_common::authorization::{
    ACTION_BIND_NET, ACTION_BPF_ATTACH, ACTION_BPF_FULL, ACTION_CGROUPFS_WRITE, ACTION_CREDENTIALS,
    ACTION_EXEC, ACTION_FIREWALL, ACTION_KMODS, ACTION_MOUNT, ACTION_RAW_CAPTURE, ACTION_SETNS,
    ACTION_SIGNAL_OTHERS, ACTION_TAG_CONTROL, ACTION_UNSHARE, FLAG_PATH_RULES_DEFAULT_DENY,
    FLAG_PROTECT, FLAG_UNPROTECTED, PATH_WALK_CAP,
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
    | ACTION_BPF_FULL
    | ACTION_KMODS
    | ACTION_CGROUPFS_WRITE
    | ACTION_FIREWALL
    | ACTION_RAW_CAPTURE
    | ACTION_BIND_NET
    | ACTION_SIGNAL_OTHERS;

/// Every authorization flag bit this version knows.
pub const KNOWN_FLAGS: u64 = FLAG_PATH_RULES_DEFAULT_DENY | FLAG_PROTECT | FLAG_UNPROTECTED;

/// One operation class a path rule can decide: the classes `file_open`
/// can see on an open (see the `PATH_RULE_*` map-value bits in
/// `wabbit-common` for what each class is). One verdict per class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OpVerdict {
    /// The rule does not decide this operation: resolution falls through
    /// to the next shallower rule that does, and past every rule to the
    /// cgroup default (`FLAG_PATH_RULES_DEFAULT_DENY`).
    #[default]
    Unspecified,
    /// The operation is allowed under this rule's prefix.
    Allow,
    /// The operation is denied under this rule's prefix.
    Deny,
}

/// A path rule's verdict: one [`OpVerdict`] per operation class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathRuleVerdict {
    /// Any open of the path at all.
    pub read: OpVerdict,
    /// A writable open (`f_mode & FMODE_WRITE`).
    pub write: OpVerdict,
    /// An execve open (`f_flags & __FMODE_EXEC`, the kernel's exec
    /// marker — never `f_mode`, which `OPEN_FMODE` cannot carry it
    /// into, and never a userspace-settable flag).
    pub exec: OpVerdict,
}

/// The six verdict bits the wire carries; bits 6–7 must be zero.
const VERDICT_WIRE_MASK: u8 = 0b0011_1111;

impl OpVerdict {
    /// This operation's two wire bits: `0b00` unspecified, `0b01` allow,
    /// `0b11` deny (`0b10` is not a value and is rejected on decode).
    const fn wire_bits(self) -> u8 {
        match self {
            Self::Unspecified => 0b00,
            Self::Allow => 0b01,
            Self::Deny => 0b11,
        }
    }

    /// The inverse of [`Self::wire_bits`].
    const fn from_wire_bits(bits: u8) -> Result<Self, ()> {
        match bits {
            0b00 => Ok(Self::Unspecified),
            0b01 => Ok(Self::Allow),
            0b11 => Ok(Self::Deny),
            _ => Err(()),
        }
    }
}

impl PathRuleVerdict {
    /// All three operations allowed — the TOML shorthand
    /// `verdict = "allow"`.
    pub const fn allow_all() -> Self {
        Self {
            read: OpVerdict::Allow,
            write: OpVerdict::Allow,
            exec: OpVerdict::Allow,
        }
    }

    /// All three operations denied — the TOML shorthand
    /// `verdict = "deny"`.
    pub const fn deny_all() -> Self {
        Self {
            read: OpVerdict::Deny,
            write: OpVerdict::Deny,
            exec: OpVerdict::Deny,
        }
    }

    /// Does this verdict decide nothing at all? A rule carrying it is
    /// inert — `validate` rejects it, because an operator who wrote it
    /// meant something and a silent no-op is the worst way to learn
    /// otherwise.
    pub const fn decides_nothing(self) -> bool {
        matches!(
            (self.read, self.write, self.exec),
            (
                OpVerdict::Unspecified,
                OpVerdict::Unspecified,
                OpVerdict::Unspecified
            )
        )
    }
}

impl TryFrom<u8> for PathRuleVerdict {
    type Error = ();

    fn try_from(verdict: u8) -> Result<Self, Self::Error> {
        if verdict & !VERDICT_WIRE_MASK != 0 {
            return Err(());
        }
        Ok(Self {
            read: OpVerdict::from_wire_bits(verdict & 0b11)?,
            write: OpVerdict::from_wire_bits((verdict >> 2) & 0b11)?,
            exec: OpVerdict::from_wire_bits((verdict >> 4) & 0b11)?,
        })
    }
}

impl From<PathRuleVerdict> for u8 {
    fn from(verdict: PathRuleVerdict) -> Self {
        verdict.read.wire_bits()
            | (verdict.write.wire_bits() << 2)
            | (verdict.exec.wire_bits() << 4)
    }
}

/// A path rule: `prefix` (and everything below it) carries `verdict` for
/// the cgroup this rule belongs to. Resolution is per operation class,
/// longest-deciding-prefix-wins (see [`OpVerdict`]).
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

impl PathRule {
    /// The [`PATH_RULES`] map value of this rule's verdict: the six
    /// per-operation `PATH_RULE_*` bits, one to one with the wire
    /// encoding. The loader and the run path write exactly this value,
    /// and the eBPF walk decodes it by operation class.
    pub fn verdict_bits(&self) -> u32 {
        use wabbit_common::authorization::{
            PATH_RULE_EXEC_ALLOW, PATH_RULE_EXEC_DENY, PATH_RULE_READ_ALLOW, PATH_RULE_READ_DENY,
            PATH_RULE_WRITE_ALLOW, PATH_RULE_WRITE_DENY,
        };
        let mut bits = 0;
        for (verdict, allow, deny) in [
            (self.verdict.read, PATH_RULE_READ_ALLOW, PATH_RULE_READ_DENY),
            (
                self.verdict.write,
                PATH_RULE_WRITE_ALLOW,
                PATH_RULE_WRITE_DENY,
            ),
            (self.verdict.exec, PATH_RULE_EXEC_ALLOW, PATH_RULE_EXEC_DENY),
        ] {
            bits |= match verdict {
                OpVerdict::Unspecified => 0,
                OpVerdict::Allow => allow,
                OpVerdict::Deny => deny,
            };
        }
        bits
    }
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

impl AuthorizationConfig {
    /// Enforce every documented contract. Both the generator and the
    /// loader call this before anything else sees the data — a violation
    /// is a policy-authoring error, not a runtime one.
    pub fn validate(&self) -> Result<(), String> {
        for (index, entry) in self.entries.iter().enumerate() {
            validate_canonical(&entry.cgroup, "cgroup")?;
            let cgroup = entry.cgroup.to_str().expect("validated UTF-8 above");
            if cgroup.len() > PATH_WALK_CAP {
                // A loader contract, same shape as the rule-prefix cap:
                // PROTECTED_PATHS keys on the full path's hash and the
                // eBPF walk only hashes the first PATH_WALK_CAP bytes,
                // so a longer cgroup path could never be walled. Better
                // rejected by name than protected by nothing.
                return Err(format!(
                    "the cgroup path {cgroup:?} exceeds the {}-byte walk cap the \
                     protection prefix walk covers",
                    PATH_WALK_CAP
                ));
            }
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
            // Walled and un-walled at once is a contradiction the
            // generator must name, not a runtime coin flip.
            if entry.flags & FLAG_PROTECT != 0 && entry.flags & FLAG_UNPROTECTED != 0 {
                return Err(format!(
                    "entry {:?} is both protected and unprotected",
                    entry.cgroup
                ));
            }
            // The cgroupfs root is a prefix of every cgroupfs path, so
            // walling it would deny every `cgroup.procs` write on the
            // machine — the root can carry action bits (the kernel's
            // module autoloads run there), but it can never be a
            // protected path.
            if entry.cgroup.as_os_str() == wabbit_common::cgroup_types::CGROUPFS_ROOT
                && entry.flags & FLAG_PROTECT != 0
            {
                return Err(format!(
                    "the cgroupfs root {} can never be a protected path",
                    entry.cgroup.display()
                ));
            }
            // One cgroup, one entry: the loader keys its maps by the
            // cgroup, and two entries for one path would silently
            // overwrite each other.
            if let Some(other) = self.entries[..index]
                .iter()
                .find(|other| other.cgroup == entry.cgroup)
            {
                return Err(format!(
                    "two authorization entries name the cgroup {}",
                    other.cgroup.display()
                ));
            }
            validate_path_rules(&entry.path_rules)?;
        }
        Ok(())
    }
}

/// The path-rule contracts every rule set shares — an entry's, or the
/// policy default's.
pub(crate) fn validate_path_rules(rules: &[PathRule]) -> Result<(), String> {
    if rules.len() > MAX_PATH_RULES {
        return Err("too many path rules".into());
    }
    for rule in rules {
        validate_canonical(&rule.prefix, "path rule prefix")?;
        let bytes = rule.prefix.to_str().expect("validated UTF-8 above");
        if bytes.len() > PATH_WALK_CAP {
            return Err(format!(
                "path rule prefix {bytes:?} exceeds the {}-byte walk cap",
                PATH_WALK_CAP
            ));
        }
        // A rule that decides nothing (every operation unspecified) is
        // inert: it matches and falls through on every open, to exactly
        // the decision an absent rule would have made. An operator who
        // wrote one meant something — reject it by name.
        if rule.verdict.decides_nothing() {
            return Err(format!(
                "the path rule for {} decides nothing: no read, write, or exec \
                 verdict (use one of them, or drop the rule)",
                rule.prefix.display()
            ));
        }
    }
    Ok(())
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
                    verdict: PathRuleVerdict::allow_all(),
                },
                PathRule {
                    prefix: "/etc/shadow".into(),
                    verdict: PathRuleVerdict::deny_all(),
                },
                // A per-operation rule: reads fine, writes denied, exec
                // left to the cgroup default — the shape the feature
                // exists for.
                PathRule {
                    prefix: "/var/www".into(),
                    verdict: PathRuleVerdict {
                        read: OpVerdict::Allow,
                        write: OpVerdict::Deny,
                        exec: OpVerdict::Unspecified,
                    },
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
        // The shorthand verdicts encode as their six bits, one pair per
        // operation.
        assert_eq!(u8::from(PathRuleVerdict::allow_all()), 0b010101);
        assert_eq!(u8::from(PathRuleVerdict::deny_all()), 0b111111);
        // And a per-operation verdict encodes each class independently.
        let web = PathRuleVerdict {
            read: OpVerdict::Allow,
            write: OpVerdict::Deny,
            exec: OpVerdict::Unspecified,
        };
        assert_eq!(u8::from(web), 0b001101);
        assert_eq!(PathRuleVerdict::try_from(0b001101).unwrap(), web);
        // Round-trips go both ways through every shorthand.
        for verdict in [
            PathRuleVerdict::allow_all(),
            PathRuleVerdict::deny_all(),
            web,
            PathRuleVerdict::default(),
        ] {
            assert_eq!(
                PathRuleVerdict::try_from(u8::from(verdict)).unwrap(),
                verdict
            );
        }
        // Reserved bits, and the non-value pair 0b10, are rejected.
        assert_eq!(PathRuleVerdict::try_from(0b00_10_00), Err(())); // 0b10 in write
        assert_eq!(PathRuleVerdict::try_from(0b10_00_00), Err(())); // 0b10 in exec
        assert_eq!(PathRuleVerdict::try_from(1 << 6), Err(()));
        assert_eq!(PathRuleVerdict::try_from(u8::MAX), Err(()));
    }

    /// The map-value translation the loader writes: one to one with the
    /// wire bits, per operation class.
    #[test]
    fn verdict_bits_match_the_wire() {
        use wabbit_common::authorization as auth;
        assert_eq!(
            PathRule {
                prefix: "/x".into(),
                verdict: PathRuleVerdict::allow_all(),
            }
            .verdict_bits(),
            auth::PATH_RULE_READ_ALLOW | auth::PATH_RULE_WRITE_ALLOW | auth::PATH_RULE_EXEC_ALLOW
        );
        assert_eq!(
            PathRule {
                prefix: "/x".into(),
                verdict: PathRuleVerdict::deny_all(),
            }
            .verdict_bits(),
            auth::PATH_RULE_READ_DENY | auth::PATH_RULE_WRITE_DENY | auth::PATH_RULE_EXEC_DENY
        );
        let web = PathRule {
            prefix: "/var/www".into(),
            verdict: PathRuleVerdict {
                read: OpVerdict::Allow,
                write: OpVerdict::Deny,
                exec: OpVerdict::Unspecified,
            },
        };
        assert_eq!(
            web.verdict_bits(),
            auth::PATH_RULE_READ_ALLOW | auth::PATH_RULE_WRITE_DENY
        );
    }

    #[test]
    fn validates_a_sound_config() {
        assert_eq!(config().validate(), Ok(()));
    }

    /// A rule that decides nothing is inert — an operator who wrote one
    /// meant something, so `validate` rejects it by name.
    #[test]
    fn rejects_a_rule_that_decides_nothing() {
        let mut inert = config();
        inert.entries[0].path_rules.push(PathRule {
            prefix: "/srv".into(),
            verdict: PathRuleVerdict::default(),
        });
        let error = inert.validate().unwrap_err();
        assert!(error.contains("decides nothing"), "{error}");
        // Every operation set is fine, including a partial one.
        let mut partial = config();
        partial.entries[0].path_rules.push(PathRule {
            prefix: "/srv".into(),
            verdict: PathRuleVerdict {
                read: OpVerdict::Unspecified,
                write: OpVerdict::Unspecified,
                exec: OpVerdict::Deny,
            },
        });
        assert_eq!(partial.validate(), Ok(()));
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

        // The walk-cap loader contract applies to the cgroup path too:
        // PROTECTED_PATHS keys on its full hash, which the eBPF prefix
        // walk could never match past the cap.
        let mut tampered = config();
        tampered.entries[0].cgroup = "x".repeat(PATH_WALK_CAP + 1).into();
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn one_cgroup_one_entry() {
        let mut duplicated = config();
        duplicated.entries.push(entry());
        assert!(duplicated.validate().is_err());
    }

    #[test]
    fn the_protect_flag_is_known() {
        let mut marked = config();
        marked.entries[0].flags = FLAG_PROTECT;
        assert_eq!(marked.validate(), Ok(()));
        // The opt-out is known too, and the contradiction is rejected.
        let mut opted_out = config();
        opted_out.entries[0].flags = FLAG_UNPROTECTED;
        assert_eq!(opted_out.validate(), Ok(()));
        let mut both = config();
        both.entries[0].flags = FLAG_PROTECT | FLAG_UNPROTECTED;
        assert!(both.validate().is_err());
        assert_eq!(
            KNOWN_FLAGS,
            FLAG_PATH_RULES_DEFAULT_DENY | FLAG_PROTECT | FLAG_UNPROTECTED
        );
    }

    /// The cgroupfs root may carry action bits (the kernel's module
    /// autoloads run there) but can never be a protected path — it is a
    /// prefix of every cgroupfs path, and walling it would deny every
    /// `cgroup.procs` write on the machine.
    #[test]
    fn the_cgroupfs_root_is_never_a_protected_path() {
        let mut autoloads = config();
        autoloads.entries[0].cgroup = wabbit_common::cgroup_types::CGROUPFS_ROOT.into();
        assert_eq!(autoloads.validate(), Ok(()));

        let mut walled = config();
        walled.entries[0].cgroup = wabbit_common::cgroup_types::CGROUPFS_ROOT.into();
        walled.entries[0].flags = FLAG_PROTECT;
        assert!(walled.validate().is_err());
    }
}
