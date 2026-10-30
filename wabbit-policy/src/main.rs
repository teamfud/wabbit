//! wabbit-policy — the off-box policy tool: generate keys, compile TOML
//! source into signed WSPF files, and audit them anywhere.
//!
//! The private signing key never lives on a target system: `gen-key`
//! makes the pair, the public half is pasted into
//! `wabbit-common/src/keys.rs` (compile-time, per the white-label
//! pattern), and only the public half ships in binaries.
//!
//! TOML is the committed source format: diffable in git, reviewable in
//! PRs, validated here — the generator is the one place bad policy is
//! rejected with names, before anything enforces it.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use wabbit_policy::{
    PRIVATE_KEY_SIZE, Policy,
    authorization::{
        AuthorizationConfig, AuthorizationEntry, MAX_PATH_RULES, OpVerdict, PathRule,
        PathRuleVerdict,
    },
    default::DefaultConfig,
    network::{BindPosture, NetworkConfig, RawCapturePosture},
    rootfs::{PathFlags, PathOverride, RootFSConfig, RootFlags},
    sign,
};
use zeroize::Zeroizing;

/// One action bit, as TOML names it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum ActionName {
    #[value(name = "setns")]
    Setns,
    #[value(name = "unshare")]
    Unshare,
    #[value(name = "mount")]
    Mount,
    #[value(name = "exec")]
    Exec,
    #[value(name = "credentials")]
    Credentials,
    #[value(name = "tag-control")]
    TagControl,
    #[value(name = "bpf-attach")]
    BpfAttach,
    #[value(name = "kmods")]
    Kmods,
    #[value(name = "cgroupfs-write")]
    CgroupfsWrite,
    #[value(name = "firewall")]
    Firewall,
    #[value(name = "raw-capture")]
    RawCapture,
    #[value(name = "bind-net")]
    BindNet,
    #[value(name = "signal")]
    Signal,
}

impl ActionName {
    /// The `ACTION_*` bit this name carries.
    fn bit(self) -> u64 {
        use wabbit_common::authorization as auth;
        match self {
            Self::Setns => auth::ACTION_SETNS,
            Self::Unshare => auth::ACTION_UNSHARE,
            Self::Mount => auth::ACTION_MOUNT,
            Self::Exec => auth::ACTION_EXEC,
            Self::Credentials => auth::ACTION_CREDENTIALS,
            Self::TagControl => auth::ACTION_TAG_CONTROL,
            Self::BpfAttach => auth::ACTION_BPF_ATTACH,
            Self::Kmods => auth::ACTION_KMODS,
            Self::CgroupfsWrite => auth::ACTION_CGROUPFS_WRITE,
            Self::Firewall => auth::ACTION_FIREWALL,
            Self::RawCapture => auth::ACTION_RAW_CAPTURE,
            Self::BindNet => auth::ACTION_BIND_NET,
            Self::Signal => auth::ACTION_SIGNAL_OTHERS,
        }
    }

    /// The enum value carrying `bit`, if this version knows it.
    fn from_bit(bit: u64) -> Option<Self> {
        use wabbit_common::authorization as auth;
        Some(match bit {
            auth::ACTION_SETNS => Self::Setns,
            auth::ACTION_UNSHARE => Self::Unshare,
            auth::ACTION_MOUNT => Self::Mount,
            auth::ACTION_EXEC => Self::Exec,
            auth::ACTION_CREDENTIALS => Self::Credentials,
            auth::ACTION_TAG_CONTROL => Self::TagControl,
            auth::ACTION_BPF_ATTACH => Self::BpfAttach,
            auth::ACTION_KMODS => Self::Kmods,
            auth::ACTION_CGROUPFS_WRITE => Self::CgroupfsWrite,
            auth::ACTION_FIREWALL => Self::Firewall,
            auth::ACTION_RAW_CAPTURE => Self::RawCapture,
            auth::ACTION_BIND_NET => Self::BindNet,
            auth::ACTION_SIGNAL_OTHERS => Self::Signal,
            _ => return None,
        })
    }

    /// The TOML spelling of an action bit, if this version knows it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "audit output spells actions itself")
    )]
    fn name_of(self) -> &'static str {
        match self {
            Self::Setns => "setns",
            Self::Unshare => "unshare",
            Self::Mount => "mount",
            Self::Exec => "exec",
            Self::Credentials => "credentials",
            Self::TagControl => "tag-control",
            Self::BpfAttach => "bpf-attach",
            Self::Kmods => "kmods",
            Self::CgroupfsWrite => "cgroupfs-write",
            Self::Firewall => "firewall",
            Self::RawCapture => "raw-capture",
            Self::BindNet => "bind-net",
            Self::Signal => "signal",
        }
    }
}

// ------------------------------------------------------------ TOML mirrors

/// The TOML shape of a policy source file. Mirrors the wire types with
/// serde-friendly spellings; conversions are total after validation.
#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct PolicyToml {
    rootfs: Option<RootFSToml>,
    /// Class definitions: named, reusable authorization settings.
    /// **Authoring sugar only** — the compile step below folds them
    /// away, and the signed format carries no class concept (see
    /// [`ClassToml`]).
    class: Option<Vec<ClassToml>>,
    authorization: Option<Vec<AuthorizationToml>>,
    network: Option<NetworkToml>,
    default: Option<DefaultToml>,
}

/// The `[default]` table: what every cgroup *no* `[[authorization]]`
/// entry names gets — an entry without a `cgroup`. A listed cgroup gets
/// exactly its own entry, never this on top.
///
/// ```toml
/// [default]
/// actions = ["bind-net"]       # kmods, firewall, raw-capture, bind-net only
///
/// [[default.path_rules]]       # a deny-list: there is no default_deny
/// prefix = "/etc/shadow"
/// verdict = "deny"
/// ```
#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct DefaultToml {
    #[serde(default)]
    actions: Vec<ActionName>,
    #[serde(default)]
    path_rules: Vec<PathRuleToml>,
}

impl From<DefaultToml> for DefaultConfig {
    fn from(default: DefaultToml) -> Self {
        Self {
            action_mask: default
                .actions
                .iter()
                .map(|name| name.bit())
                .fold(0, |mask, bit| mask | bit),
            path_rules: default
                .path_rules
                .into_iter()
                .map(|rule| {
                    let verdict = toml_rule_verdict(&rule);
                    PathRule {
                        prefix: rule.prefix,
                        verdict,
                    }
                })
                .collect(),
        }
    }
}

impl TryFrom<&DefaultConfig> for DefaultToml {
    type Error = String;

    fn try_from(default: &DefaultConfig) -> Result<Self, Self::Error> {
        let mut actions = Vec::new();
        let mut rest = default.action_mask;
        while rest != 0 {
            let bit = rest & rest.wrapping_neg();
            let action = ActionName::from_bit(bit)
                .ok_or_else(|| "the default carries an unknown action bit".to_string())?;
            actions.push(action);
            rest &= !bit;
        }
        Ok(Self {
            actions,
            path_rules: default.path_rules.iter().map(PathRuleToml::from).collect(),
        })
    }
}

/// The `[network]` table: how far each network gate reaches. Either key
/// may be omitted and keeps the strictest posture (`all`).
///
/// ```toml
/// [network]
/// bind        = "ports"   # "all" | "ports" | "off"
/// raw_capture = "icmp"    # "all" | "icmp" | "off"
/// ```
#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct NetworkToml {
    #[serde(default)]
    bind: BindName,
    #[serde(default)]
    raw_capture: RawCaptureName,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum BindName {
    #[default]
    All,
    Ports,
    Off,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum RawCaptureName {
    #[default]
    All,
    Icmp,
    Off,
}

impl From<NetworkToml> for NetworkConfig {
    fn from(network: NetworkToml) -> Self {
        Self {
            bind: match network.bind {
                BindName::All => BindPosture::All,
                BindName::Ports => BindPosture::Ports,
                BindName::Off => BindPosture::Off,
            },
            raw_capture: match network.raw_capture {
                RawCaptureName::All => RawCapturePosture::All,
                RawCaptureName::Icmp => RawCapturePosture::Icmp,
                RawCaptureName::Off => RawCapturePosture::Off,
            },
        }
    }
}

impl From<&NetworkConfig> for NetworkToml {
    fn from(network: &NetworkConfig) -> Self {
        Self {
            bind: match network.bind {
                BindPosture::All => BindName::All,
                BindPosture::Ports => BindName::Ports,
                BindPosture::Off => BindName::Off,
            },
            raw_capture: match network.raw_capture {
                RawCapturePosture::All => RawCaptureName::All,
                RawCapturePosture::Icmp => RawCaptureName::Icmp,
                RawCapturePosture::Off => RawCaptureName::Off,
            },
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct RootFSToml {
    executable: bool,
    writable: bool,
    #[serde(default)]
    overrides: Vec<OverrideToml>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct OverrideToml {
    #[serde(default)]
    inner_writable: bool,
    #[serde(default)]
    inner_executable: bool,
    #[serde(default)]
    outer_writable: bool,
    #[serde(default)]
    outer_executable: bool,
    #[serde(default)]
    outer_readable: bool,
    #[serde(default)]
    outer_visible: bool,
    #[serde(default)]
    priority: u16,
    path: PathBuf,
    #[serde(default)]
    inner_path: Option<PathBuf>,
}

/// A **class**: named, reusable authorization settings, defined once
/// and inherited by any number of cgroup entries — and, when it names a
/// cgroup, compiled into an entry of its own that a signed run command
/// can execute under.
///
/// This is the policy crate's whole understanding of classes, and it
/// ends at `wabbit-policy build`: the compile step ([`compile_classes`])
/// folds every class into ordinary cgroup rules, and the signed WSPF
/// format — and wabbit itself — never sees one. What survives the
/// compile is a **convention**: a concrete class `shell` on a wabbit
/// whose cgroup is `/sys/fs/cgroup/wabbit` becomes the entry
/// `/sys/fs/cgroup/wabbit/class/shell`, because that is the path a
/// class-naming run command resolves at runtime
/// (`wabbit_common::cgroup_types` documents the convention both sides
/// share).
///
/// ```toml
/// # a concrete class: runs may name it, so it compiles to an entry
/// [[class]]
/// name = "shell"
/// cgroup = "/sys/fs/cgroup/wabbit"   # the class entry lands at
///                                    # <cgroup>/class/<name>
/// actions = ["exec", "credentials"]
/// default_deny = true                # allow-list: unruled opens deny
/// protect = true                     # the migration wall applies
/// [[class.path_rules]]
/// prefix = "/usr"
/// verdict = "allow"
///
/// # an abstract class: settings other entries inherit, no entry of
/// # its own — nothing a run could name
/// [[class]]
/// name = "systemd-base"
/// actions = ["bpf-attach"]
///
/// # an entry inheriting the class: settings merge by union — an entry
/// # adds to its class, never subtracts
/// [[authorization]]
/// cgroup = "/sys/fs/cgroup/init.scope"
/// class = "systemd-base"
/// ```
#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct ClassToml {
    /// The class's name — what a signed run command will ask for. The
    /// charset is a security boundary (the runtime builds a cgroupfs
    /// path from it): `[a-z0-9-]`, no leading or trailing `-`.
    name: String,
    /// The wabbit cgroup whose subtree the class compiles into; the
    /// class's own entry lands at `<cgroup>/class/<name>` — the
    /// convention a class-naming run resolves. Omitted for an
    /// **abstract** class: reusable settings, no entry, nothing a run
    /// could name.
    #[serde(default)]
    cgroup: Option<PathBuf>,
    /// Action names, as [`ActionName`] spells them.
    #[serde(default)]
    actions: Vec<ActionName>,
    /// Whether unruled paths are denied (allow-list) or allowed
    /// (deny-list) — same meaning as on an authorization entry.
    #[serde(default)]
    default_deny: bool,
    /// The migration wall, as on an authorization entry: `true` walls
    /// this cgroup even bitless, `false` **opts out** of the wall its
    /// bits would give it (the `init.scope` bootstrap), absent = the
    /// default (bit-holding cgroups are walled). Same union rule as
    /// every class setting: an entry may add, never subtract.
    #[serde(default)]
    protect: Option<bool>,
    #[serde(default)]
    path_rules: Vec<PathRuleToml>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct AuthorizationToml {
    /// The canonical cgroupfs path of the cgroup this entry authorizes.
    cgroup: PathBuf,
    /// The class this entry inherits: settings merge by **union** —
    /// actions join, flags OR, path rules append — so an entry may add
    /// to its class but never subtract from it.
    #[serde(default)]
    class: Option<String>,
    /// Action names, as [`ActionName`] spells them.
    #[serde(default)]
    actions: Vec<ActionName>,
    /// Whether unruled paths are denied (allow-list) or allowed
    /// (deny-list) for this cgroup.
    #[serde(default)]
    default_deny: bool,
    /// The migration wall (`cgroup.procs`/`freeze`/`kill`): `true`
    /// walls this cgroup even if it holds no action bits; `false`
    /// **opts out** of the wall bit-holding cgroups get automatically —
    /// for the one cgroup that must accept migration from outside:
    /// PID 1 bootstraps into `init.scope` before any authorization can
    /// apply, so a walled `init.scope` would refuse its own PID 1 and
    /// kill the boot. Absent = the default (bit-holders are walled).
    #[serde(default)]
    protect: Option<bool>,
    #[serde(default)]
    path_rules: Vec<PathRuleToml>,
}

/// A path rule as authored: `prefix` plus per-operation verdicts. The
/// operations are the three classes `file_open` can see on an open —
/// read (any open), write (a writable open), exec (an execve open) —
/// each `allow` or `deny`, each optional:
///
/// ```toml
/// [[authorization.path_rules]]
/// prefix  = "/var/www"
/// verdict = "allow"        # the shorthand: all three at once
/// write   = "deny"         # overrides the shorthand's write
/// exec    = "deny"         # …and its exec — reads alone stay open
/// ```
///
/// The shorthand `verdict` and the per-operation keys union (a
/// per-operation key wins for its operation), and an operation no rule
/// decides falls through: to the next shallower rule that decides it,
/// and past every rule to the cgroup default (`default_deny`).
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
struct PathRuleToml {
    prefix: PathBuf,
    /// The all-operations shorthand: `allow` or `deny` for read, write,
    /// and exec at once.
    #[serde(default)]
    verdict: Option<VerdictName>,
    /// `allow` or `deny` for any open of this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    read: Option<VerdictName>,
    /// `allow` or `deny` for writable opens under this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    write: Option<VerdictName>,
    /// `allow` or `deny` for execve opens under this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exec: Option<VerdictName>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum VerdictName {
    #[value(name = "allow")]
    Allow,
    #[value(name = "deny")]
    Deny,
}

impl VerdictName {
    /// The wire verdict of this name.
    const fn op(self) -> OpVerdict {
        match self {
            Self::Allow => OpVerdict::Allow,
            Self::Deny => OpVerdict::Deny,
        }
    }

    /// The name of this operation verdict, if it has one (an unspecified
    /// operation serializes as an omitted key).
    const fn of_op(op: OpVerdict) -> Option<Self> {
        match op {
            OpVerdict::Allow => Some(Self::Allow),
            OpVerdict::Deny => Some(Self::Deny),
            OpVerdict::Unspecified => None,
        }
    }
}

/// One authored rule's verdict: the shorthand, then whichever
/// per-operation keys override it.
fn toml_rule_verdict(rule: &PathRuleToml) -> PathRuleVerdict {
    let mut verdict = PathRuleVerdict::default();
    if let Some(shorthand) = rule.verdict {
        verdict.read = shorthand.op();
        verdict.write = shorthand.op();
        verdict.exec = shorthand.op();
    }
    let merge = |slot: &mut OpVerdict, name: Option<VerdictName>| {
        if let Some(name) = name {
            *slot = name.op();
        }
    };
    merge(&mut verdict.read, rule.read);
    merge(&mut verdict.write, rule.write);
    merge(&mut verdict.exec, rule.exec);
    verdict
}

/// One wire verdict back to its authored spelling: three agreeing
/// operations are the shorthand and nothing else; anything else is
/// spelled per operation.
fn rule_toml(prefix: PathBuf, verdict: PathRuleVerdict) -> PathRuleToml {
    if verdict.read == verdict.write && verdict.write == verdict.exec {
        return PathRuleToml {
            prefix,
            verdict: VerdictName::of_op(verdict.read),
            read: None,
            write: None,
            exec: None,
        };
    }
    PathRuleToml {
        prefix,
        verdict: None,
        read: VerdictName::of_op(verdict.read),
        write: VerdictName::of_op(verdict.write),
        exec: VerdictName::of_op(verdict.exec),
    }
}

impl From<&PathRule> for PathRuleToml {
    fn from(rule: &PathRule) -> Self {
        rule_toml(rule.prefix.clone(), rule.verdict)
    }
}

impl TryFrom<&AuthorizationEntry> for AuthorizationToml {
    type Error = String;

    fn try_from(entry: &AuthorizationEntry) -> Result<Self, Self::Error> {
        let mut actions = Vec::new();
        let mut rest = entry.action_mask;
        while rest != 0 {
            let bit = rest & rest.wrapping_neg();
            let action = ActionName::from_bit(bit)
                .ok_or_else(|| format!("entry {:?} carries an unknown action bit", entry.cgroup))?;
            actions.push(action);
            rest &= !bit;
        }
        Ok(Self {
            cgroup: entry.cgroup.clone(),
            class: None,
            actions,
            default_deny: entry.flags & wabbit_common::authorization::FLAG_PATH_RULES_DEFAULT_DENY
                != 0,
            protect: if entry.flags & wabbit_common::authorization::FLAG_PROTECT != 0 {
                Some(true)
            } else if entry.flags & wabbit_common::authorization::FLAG_UNPROTECTED != 0 {
                Some(false)
            } else {
                None
            },
            path_rules: entry.path_rules.iter().map(PathRuleToml::from).collect(),
        })
    }
}

// ------------------------------------------------------------ conversions

/// One class after authoring validation: the settings referencing
/// entries inherit, plus (for a concrete class) the cgroup its own
/// compiled entry lands at.
#[derive(Debug)]
struct CompiledClass {
    actions: Vec<ActionName>,
    default_deny: bool,
    protect: Option<bool>,
    path_rules: Vec<PathRuleToml>,
    /// `Some(path)` for a concrete class: the entry a class-naming run
    /// command resolves at runtime (`<cgroup>/class/<name>`). `None`
    /// for an abstract class.
    entry_cgroup: Option<PathBuf>,
}

/// Validate every class definition and pre-compute its compiled shape.
/// The one place the class feature exists — everything downstream sees
/// only cgroup rules.
fn compile_classes(sources: &[ClassToml]) -> Result<BTreeMap<String, CompiledClass>, String> {
    use wabbit_common::cgroup_types::{CLASS_NAME_MAX_BYTES, CLASS_SEGMENT, valid_class_name};

    let mut classes = BTreeMap::new();
    for source in sources {
        if !valid_class_name(&source.name) {
            return Err(format!(
                "class name {:?} is not valid: 1-{CLASS_NAME_MAX_BYTES} bytes of [a-z0-9-], \
                 no leading or trailing '-'",
                source.name
            ));
        }
        // The class's own entry, when it has one: `<cgroup>/class/<name>`
        // — the convention the runtime resolves, spelled here so the
        // generator can hold it to the same walk-cap contract every
        // protected path must fit.
        let entry_cgroup = match &source.cgroup {
            None => None,
            Some(base) => {
                let base = base
                    .to_str()
                    .ok_or_else(|| format!("class {:?}: the cgroup is not UTF-8", source.name))?;
                let path = format!("{base}/{CLASS_SEGMENT}/{}", source.name);
                let cap = wabbit_common::authorization::PATH_WALK_CAP;
                if path.len() > cap {
                    return Err(format!(
                        "class {:?} compiles to {path:?}, past the {cap}-byte eBPF walk cap — \
                         a protection prefix walk could never reach it, so it could never be \
                         walled",
                        source.name
                    ));
                }
                Some(PathBuf::from(path))
            }
        };
        if classes
            .insert(
                source.name.clone(),
                CompiledClass {
                    actions: source.actions.clone(),
                    default_deny: source.default_deny,
                    protect: source.protect,
                    path_rules: source.path_rules.clone(),
                    entry_cgroup,
                },
            )
            .is_some()
        {
            return Err(format!("class {:?} is defined twice", source.name));
        }
    }
    Ok(classes)
}

/// Fold an entry's class reference into the entry: union semantics —
/// actions join, flags OR, path rules append — so an entry may **add**
/// to its class but never subtract (a class is the floor its entries
/// stand on, and the merge is the one place that has to stay obvious).
fn expand_class(
    entry: AuthorizationToml,
    classes: &BTreeMap<String, CompiledClass>,
) -> Result<AuthorizationToml, String> {
    let Some(class_name) = entry.class.clone() else {
        return Ok(entry);
    };
    let class = classes.get(&class_name).ok_or_else(|| {
        format!(
            "entry {:?} references unknown class {class_name:?}",
            entry.cgroup
        )
    })?;
    let mut actions = class.actions.clone();
    for action in entry.actions {
        if !actions.contains(&action) {
            actions.push(action);
        }
    }
    let mut path_rules = class.path_rules.clone();
    for rule in entry.path_rules {
        // A class rule and an entry rule for one prefix merge by union,
        // per operation: an entry may add to its class's rule (an
        // operation the class left unspecified) but never change one
        // the class decided — the same never-subtract rule as every
        // other class setting.
        let Some(existing) = path_rules
            .iter_mut()
            .find(|other| other.prefix == rule.prefix)
        else {
            path_rules.push(rule);
            continue;
        };
        let class_verdict = toml_rule_verdict(existing);
        let entry_verdict = toml_rule_verdict(&rule);
        for (class_op, entry_op) in [
            (class_verdict.read, entry_verdict.read),
            (class_verdict.write, entry_verdict.write),
            (class_verdict.exec, entry_verdict.exec),
        ] {
            // A disagreement is two *decided* operations that decided
            // differently; an unspecified side adds or changes nothing.
            if class_op != OpVerdict::Unspecified
                && entry_op != OpVerdict::Unspecified
                && class_op != entry_op
            {
                return Err(format!(
                    "entry {:?} disagrees with class {class_name:?} about the rule for {}",
                    entry.cgroup,
                    rule.prefix.display()
                ));
            }
        }
        let pick = |class_op, entry_op| {
            if entry_op == OpVerdict::Unspecified {
                class_op
            } else {
                entry_op
            }
        };
        *existing = rule_toml(
            rule.prefix,
            PathRuleVerdict {
                read: pick(class_verdict.read, entry_verdict.read),
                write: pick(class_verdict.write, entry_verdict.write),
                exec: pick(class_verdict.exec, entry_verdict.exec),
            },
        );
    }
    Ok(AuthorizationToml {
        cgroup: entry.cgroup,
        class: None,
        actions,
        default_deny: entry.default_deny || class.default_deny,
        // The union of the walls — and never subtract: an entry may
        // raise its class's wall, not lower it. `Some(true)` from
        // either wins; short of that, an explicit `Some(false)`
        // (the opt-out) carries; absent stays absent.
        protect: match (entry.protect, class.protect) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            (None, None) => None,
        },
        path_rules,
    })
}

/// One TOML authorization entry to its wire shape.
fn entry_to_wire(entry: AuthorizationToml) -> AuthorizationEntry {
    let mut flags = 0;
    if entry.default_deny {
        flags |= wabbit_common::authorization::FLAG_PATH_RULES_DEFAULT_DENY;
    }
    match entry.protect {
        Some(true) => flags |= wabbit_common::authorization::FLAG_PROTECT,
        Some(false) => flags |= wabbit_common::authorization::FLAG_UNPROTECTED,
        None => {}
    }
    AuthorizationEntry {
        cgroup: entry.cgroup,
        action_mask: entry
            .actions
            .iter()
            .map(|name| name.bit())
            .fold(0, |mask, bit| mask | bit),
        flags,
        path_rules: entry
            .path_rules
            .into_iter()
            .map(|rule| {
                let verdict = toml_rule_verdict(&rule);
                PathRule {
                    prefix: rule.prefix,
                    verdict,
                }
            })
            .collect(),
    }
}

impl TryFrom<PolicyToml> for Policy {
    type Error = String;

    fn try_from(source: PolicyToml) -> Result<Self, Self::Error> {
        // Classes first: every authoring reference resolves here, and
        // the compile is the one place the feature exists. After it,
        // only cgroup rules remain — the signed format and the loader
        // never see a class.
        let classes = compile_classes(source.class.as_deref().unwrap_or(&[]))?;

        let rootfs = source.rootfs.map(|rootfs| RootFSConfig {
            flags: RootFlags::new(rootfs.executable, rootfs.writable),
            overrides: rootfs
                .overrides
                .into_iter()
                .map(|override_| PathOverride {
                    flags: PathFlags::new(
                        override_.inner_writable,
                        override_.inner_executable,
                        override_.outer_writable,
                        override_.outer_executable,
                        override_.outer_readable,
                        override_.outer_visible,
                    ),
                    priority: override_.priority,
                    path: override_.path,
                    inner_path: override_.inner_path,
                })
                .collect(),
        });
        let authorization = {
            // Plain entries first, their class references resolved; then
            // each concrete class compiles to its own entry — the cgroup
            // a class-naming run resolves at runtime. A policy may carry
            // classes and no plain entries at all, so the class entries
            // append to (possibly) nothing.
            let mut entries: Vec<AuthorizationToml> = match source.authorization {
                None => Vec::new(),
                Some(plain) => plain
                    .into_iter()
                    .map(|entry| expand_class(entry, &classes))
                    .collect::<Result<Vec<_>, _>>()?,
            };
            for class in classes.values() {
                if let Some(cgroup) = &class.entry_cgroup {
                    entries.push(AuthorizationToml {
                        cgroup: cgroup.clone(),
                        class: None,
                        actions: class.actions.clone(),
                        default_deny: class.default_deny,
                        protect: class.protect,
                        path_rules: class.path_rules.clone(),
                    });
                }
            }
            if entries.is_empty() {
                None
            } else {
                Some(AuthorizationConfig {
                    entries: entries.into_iter().map(entry_to_wire).collect(),
                })
            }
        };
        let policy = Self {
            rootfs,
            authorization,
            network: source.network.map(NetworkConfig::from),
            default: source.default.map(DefaultConfig::from),
        };
        if let Some(authorization) = &policy.authorization {
            authorization.validate()?;
        }
        if let Some(default) = &policy.default {
            default.validate()?;
        }
        Ok(policy)
    }
}

impl TryFrom<&Policy> for PolicyToml {
    type Error = String;

    fn try_from(policy: &Policy) -> Result<Self, Self::Error> {
        let rootfs = policy.rootfs.as_ref().map(|rootfs| RootFSToml {
            executable: rootfs.flags.executable(),
            writable: rootfs.flags.writable(),
            overrides: rootfs
                .overrides
                .iter()
                .map(|override_| OverrideToml {
                    inner_writable: override_.flags.inner_writable(),
                    inner_executable: override_.flags.inner_executable(),
                    outer_writable: override_.flags.outer_writable(),
                    outer_executable: override_.flags.outer_executable(),
                    outer_readable: override_.flags.outer_readable(),
                    outer_visible: override_.flags.outer_visible(),
                    priority: override_.priority,
                    path: override_.path.clone(),
                    inner_path: override_.inner_path.clone(),
                })
                .collect(),
        });
        let authorization = match &policy.authorization {
            None => None,
            Some(config) if config.entries.is_empty() => None,
            Some(config) => Some(
                config
                    .entries
                    .iter()
                    .map(AuthorizationToml::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };
        // Classes do not survive the compile: the decoded policy holds
        // only the cgroup rules they became.
        Ok(Self {
            rootfs,
            class: None,
            authorization,
            network: policy.network.as_ref().map(NetworkToml::from),
            default: policy.default.as_ref().map(DefaultToml::try_from).transpose()?,
        })
    }
}

// ---------------------------------------------------------------- commands

#[derive(Parser)]
#[command(
    name = "wabbit-policy",
    about = "Generate, sign, and audit wabbit policy files",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 signing keypair.
    ///
    /// Prints the `keys.rs` line for the public half and writes the
    /// private half to a file with owner-only permissions. The public
    /// key is pasted into `wabbit-common/src/keys.rs` (or supplied at
    /// build time via `WABBIT_POLICY_PUBLIC_KEY`); the private key
    /// never leaves the blue team's machine.
    GenKey {
        /// Where to write the 32-byte private key seed.
        #[arg(long, default_value = "wabbit-policy.key")]
        key: PathBuf,
    },
    /// Compile a TOML policy source into a signed WSPF file.
    Build {
        /// The TOML source file.
        source: PathBuf,
        /// Where to write the signed policy (must not exist).
        output: PathBuf,
        /// The 32-byte private key seed file.
        #[arg(long)]
        key: PathBuf,
        /// The key id the header carries: the index of this key in
        /// `POLICY_PUBLIC_KEYS`.
        #[arg(long, default_value_t = 0)]
        key_id: u8,
    },
    /// Verify a signed policy and decode it to TOML, for audit.
    Inspect {
        /// The signed policy file.
        policy: PathBuf,
        /// Verify against this public key (hex or base64) instead of the
        /// compiled-in keys. `WABBIT_POLICY_PUBLIC_KEY` is compile-time
        /// only (`option_env!`), so a deployed keypair's public half needs
        /// this to verify with — the key it belongs to was never built in.
        #[arg(long)]
        public_key: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let Cli { command } = Cli::parse();
    match command {
        Command::GenKey { key } => gen_key(&key),
        Command::Build {
            source,
            output,
            key,
            key_id,
        } => build(&source, &output, &key, key_id),
        Command::Inspect { policy, public_key } => inspect(&policy, public_key.as_deref()),
    }
}

/// Read a 32-byte private key seed file, zeroized on drop.
fn read_key(path: &Path) -> Result<[u8; PRIVATE_KEY_SIZE]> {
    let bytes =
        Zeroizing::new(fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    let key: [u8; PRIVATE_KEY_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must hold exactly 32 bytes", path.display()))?;
    Ok(key)
}

fn gen_key(key_path: &Path) -> Result<()> {
    use rand_core::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying = signing_key.verifying_key();

    let secret = Zeroizing::new(signing_key.to_bytes());
    let mut file =
        fs::File::create(key_path).with_context(|| format!("creating {}", key_path.display()))?;
    file.write_all(secret.as_slice())?;
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", key_path.display()))?;

    // The public half travels beside the secret as hex (mode 0644): the
    // deployment wizard and any later tooling reads it from here instead
    // of parsing the human guidance printed below.
    let public_hex = hex::encode(verifying.as_bytes());
    let public_path = format!("{}.pub", key_path.display());
    fs::write(&public_path, format!("{public_hex}\n"))
        .with_context(|| format!("writing {public_path}"))?;
    fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("chmod 644 {public_path}"))?;

    println!(
        "wrote the private key seed to {} (mode 0600)",
        key_path.display()
    );
    println!("wrote the public half to {public_path}");
    println!("keep the seed off every target system; it signs policy they trust.");
    println!();
    println!("build the wabbit chain with it compiled in:");
    println!("WABBIT_POLICY_PUBLIC_KEY={public_hex} ./vm/build-artifact.sh");
    println!("verify a policy against it:");
    println!("wabbit-policy inspect policy.wspf --public-key {public_hex}");
    Ok(())
}

fn build(source_path: &Path, output: &Path, key: &Path, key_id: u8) -> Result<()> {
    let text = fs::read_to_string(source_path)
        .with_context(|| format!("reading {}", source_path.display()))?;
    let source: PolicyToml =
        toml::from_str(&text).with_context(|| format!("parsing {}", source_path.display()))?;
    // For the build report: classes exist only here, so count them
    // before the compile folds them away.
    let source_class_count = source.class.as_ref().map(|classes| classes.len());
    let policy = Policy::try_from(source)
        .map_err(|error| anyhow::anyhow!("{}: {error}", source_path.display()))?;
    if let Some(authorization) = &policy.authorization {
        if authorization.entries.len() > wabbit_policy::authorization::MAX_AUTHORIZATIONS {
            bail!("too many authorization entries");
        }
        for entry in &authorization.entries {
            if entry.path_rules.len() > MAX_PATH_RULES {
                bail!(
                    "entry {:?} carries more than {} path rules",
                    entry.cgroup,
                    MAX_PATH_RULES
                );
            }
        }
    }
    let key = read_key(key)?;
    let bytes = sign(&policy, key_id, &key)?;
    let mut file =
        fs::File::create_new(output).with_context(|| format!("creating {}", output.display()))?;
    file.write_all(&bytes)?;
    let classes = source_class_count.unwrap_or(0);
    println!(
        "built {} ({} bytes, key id {key_id})",
        output.display(),
        bytes.len()
    );
    if classes > 0 {
        let entries = policy
            .authorization
            .as_ref()
            .map(|config| config.entries.len())
            .unwrap_or(0);
        println!(
            "compiled {classes} class{} away into {entries} cgroup rule{}",
            if classes == 1 { "" } else { "es" },
            if entries == 1 { "" } else { "s" },
        );
    }
    Ok(())
}

fn inspect(path: &Path, public_key: Option<&str>) -> Result<()> {
    // Verify first: against the explicit key when given (deployed keypairs —
    // the env override is compile-time only, so `option_env!` cannot carry a
    // runtime key), else against the compiled-in keys.
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let policy = match public_key {
        Some(key) => wabbit_policy::from_bytes_with_key(&bytes, key),
        None => wabbit_policy::from_bytes(&bytes),
    }
    .with_context(|| format!("parsing policy {}", path.display()))?;
    // Decode to TOML for the audit output.
    let toml = PolicyToml::try_from(&policy).map_err(|error| anyhow::anyhow!("{error}"))?;
    let text = toml::to_string_pretty(&toml).context("encoding the decoded policy")?;
    println!("# verified: {}", path.display());
    print!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names_round_trip_bits() {
        use wabbit_common::authorization::*;
        for (bit, name) in [
            (ACTION_SETNS, "setns"),
            (ACTION_UNSHARE, "unshare"),
            (ACTION_MOUNT, "mount"),
            (ACTION_EXEC, "exec"),
            (ACTION_CREDENTIALS, "credentials"),
            (ACTION_TAG_CONTROL, "tag-control"),
            (ACTION_BPF_ATTACH, "bpf-attach"),
            (ACTION_KMODS, "kmods"),
            (ACTION_CGROUPFS_WRITE, "cgroupfs-write"),
            (ACTION_FIREWALL, "firewall"),
            (ACTION_RAW_CAPTURE, "raw-capture"),
            (ACTION_BIND_NET, "bind-net"),
            (ACTION_SIGNAL_OTHERS, "signal"),
        ] {
            let parsed = ActionName::from_bit(bit).expect("known action bit");
            assert_eq!(parsed.bit(), bit, "the {name} bit");
            assert_eq!(parsed.name_of(), name);
        }
        assert_eq!(ActionName::from_bit(1 << 20), None);
    }

    #[test]
    fn toml_round_trips_a_policy() {
        let source = PolicyToml {
            authorization: Some(vec![AuthorizationToml {
                cgroup: "/sys/fs/cgroup/wabbit".into(),
                class: None,
                actions: vec![ActionName::Mount, ActionName::Kmods],
                default_deny: true,
                protect: None,
                path_rules: vec![PathRuleToml {
                    prefix: "/etc/ssh".into(),
                    verdict: Some(VerdictName::Allow),
                    read: None,
                    write: None,
                    exec: None,
                }],
            }]),
            class: None,
            rootfs: None,
            network: Some(NetworkToml {
                bind: BindName::Ports,
                raw_capture: RawCaptureName::Off,
            }),
            default: Some(DefaultToml {
                actions: vec![ActionName::BindNet],
                path_rules: vec![PathRuleToml {
                    prefix: "/etc/shadow".into(),
                    verdict: Some(VerdictName::Deny),
                    read: None,
                    write: None,
                    exec: None,
                }],
            }),
        };
        let policy = Policy::try_from(
            toml::from_str::<PolicyToml>(&toml::to_string(&source).unwrap()).unwrap(),
        )
        .unwrap();
        let back = PolicyToml::try_from(&policy).unwrap();
        assert_eq!(
            toml::to_string_pretty(&source).unwrap(),
            toml::to_string_pretty(&back).unwrap()
        );
    }

    /// The authored shape of a classed policy, as TOML text, for the
    /// compile tests below.
    fn classed_source_toml() -> String {
        r#"
[[class]]
name = "shell"
cgroup = "/sys/fs/cgroup/wabbit"
actions = ["exec", "credentials"]
default_deny = true
protect = true

[[class.path_rules]]
prefix = "/usr"
verdict = "allow"

[[class]]
name = "ultra-privileged"
cgroup = "/sys/fs/cgroup/wabbit"
actions = ["mount", "kmods", "bpf-attach", "cgroupfs-write", "firewall"]

[[class]]
name = "systemd-base"
actions = ["bpf-attach"]

[[authorization]]
cgroup = "/sys/fs/cgroup/init.scope"
class = "systemd-base"
actions = ["kmods"]

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
actions = ["mount"]
default_deny = false
"#
        .to_string()
    }

    fn parse(text: &str) -> Result<Policy, String> {
        let source: PolicyToml = toml::from_str(text).unwrap();
        Policy::try_from(source)
    }

    /// The core promise: after the compile, only cgroup rules remain —
    /// a concrete class is an entry at the runtime convention path, and
    /// a classed entry carries the union of its class and itself.
    #[test]
    fn classes_compile_away_into_cgroup_rules() {
        let policy = parse(&classed_source_toml()).unwrap();
        let config = policy.authorization.as_ref().unwrap();

        // The concrete classes became entries at the convention path
        // `<wabbit-cgroup>/class/<name>` — the path a class-naming run
        // resolves at runtime.
        let shell = config
            .entries
            .iter()
            .find(|entry| entry.cgroup == Path::new("/sys/fs/cgroup/wabbit/class/shell"))
            .expect("the shell class compiled to an entry");
        use wabbit_common::authorization as auth;
        assert_eq!(
            shell.action_mask,
            auth::ACTION_EXEC | auth::ACTION_CREDENTIALS
        );
        assert_eq!(
            shell.flags,
            auth::FLAG_PATH_RULES_DEFAULT_DENY | auth::FLAG_PROTECT
        );
        assert_eq!(shell.path_rules.len(), 1);
        assert_eq!(shell.path_rules[0].prefix, Path::new("/usr"));

        let ultra = config
            .entries
            .iter()
            .find(|entry| entry.cgroup == Path::new("/sys/fs/cgroup/wabbit/class/ultra-privileged"))
            .expect("the ultra-privileged class compiled to an entry");
        assert_eq!(
            ultra.action_mask,
            auth::ACTION_MOUNT
                | auth::ACTION_KMODS
                | auth::ACTION_BPF_ATTACH
                | auth::ACTION_CGROUPFS_WRITE
                | auth::ACTION_FIREWALL
        );

        // The abstract class compiled to nothing of its own…
        assert!(
            !config.entries.iter().any(|entry| entry
                .cgroup
                .to_str()
                .unwrap()
                .contains("systemd-base"))
        );

        // …and the classed entry carries the union: the class's
        // bpf-attach plus its own kmods — added, never subtracted.
        let init_scope = config
            .entries
            .iter()
            .find(|entry| entry.cgroup == Path::new("/sys/fs/cgroup/init.scope"))
            .expect("the classed entry survived");
        assert_eq!(
            init_scope.action_mask,
            auth::ACTION_BPF_ATTACH | auth::ACTION_KMODS
        );

        // The whole section still validates, and inspect decodes it as
        // plain entries — no class concept survives the compile.
        config.validate().unwrap();
        let inspected = PolicyToml::try_from(&policy).unwrap();
        assert!(inspected.class.is_none());
        assert!(
            inspected
                .authorization
                .as_ref()
                .unwrap()
                .iter()
                .all(|entry| entry.class.is_none())
        );
    }

    #[test]
    fn class_inheritance_is_union_so_entries_only_add() {
        let policy = parse(
            r#"
[[class]]
name = "base"
default_deny = true
protect = true

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
class = "base"
default_deny = false
protect = false
"#,
        )
        .unwrap();
        let entry = &policy.authorization.unwrap().entries[0];
        use wabbit_common::authorization as auth;
        // The entry may add to its class but never subtract: both flags
        // stay on, whatever the entry says.
        assert_eq!(
            entry.flags,
            auth::FLAG_PATH_RULES_DEFAULT_DENY | auth::FLAG_PROTECT
        );
    }

    #[test]
    fn class_rules_append_and_disagreements_are_rejected() {
        let agreeing = parse(
            r#"
[[class]]
name = "base"

[[class.path_rules]]
prefix = "/etc"
verdict = "deny"

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
class = "base"

[[authorization.path_rules]]
prefix = "/etc"
verdict = "deny"

[[authorization.path_rules]]
prefix = "/var"
verdict = "allow"
"#,
        )
        .unwrap();
        let entry = &agreeing.authorization.unwrap().entries[0];
        // Appended, and the agreeing duplicate folded to one rule.
        assert_eq!(entry.path_rules.len(), 2);

        let disagreeing = parse(
            r#"
[[class]]
name = "base"

[[class.path_rules]]
prefix = "/etc"
verdict = "deny"

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
class = "base"

[[authorization.path_rules]]
prefix = "/etc"
verdict = "allow"
"#,
        );
        let error = disagreeing.unwrap_err();
        assert!(error.contains("disagrees"), "{error}");
    }

    /// The per-operation verdicts: the shorthand `verdict` unions with
    /// the per-operation keys, compiles to the wire verdicts, and
    /// inspects back to its per-operation spelling.
    #[test]
    fn per_operation_verdicts_compile_and_inspect() {
        use wabbit_common::authorization as auth;
        let policy = parse(
            r#"
[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
default_deny = false

[[authorization.path_rules]]
prefix  = "/var/www"
verdict = "allow"
write   = "deny"
exec    = "deny"
"#,
        )
        .unwrap();
        let rule = &policy.authorization.as_ref().unwrap().entries[0].path_rules[0];
        // The shorthand set all three; the per-operation keys overrode
        // write and exec; read alone stayed open.
        assert_eq!(rule.verdict.read, OpVerdict::Allow);
        assert_eq!(rule.verdict.write, OpVerdict::Deny);
        assert_eq!(rule.verdict.exec, OpVerdict::Deny);
        assert_eq!(
            rule.verdict_bits(),
            auth::PATH_RULE_READ_ALLOW
                | auth::PATH_RULE_WRITE_DENY
                | auth::PATH_RULE_EXEC_DENY
        );

        // Inspect spells mixed operations per operation, never as the
        // shorthand.
        let inspected = PolicyToml::try_from(&policy).unwrap();
        let rule = &inspected.authorization.as_ref().unwrap()[0].path_rules[0];
        assert_eq!(rule.verdict, None);
        assert_eq!(rule.read, Some(VerdictName::Allow));
        assert_eq!(rule.write, Some(VerdictName::Deny));
        assert_eq!(rule.exec, Some(VerdictName::Deny));

        // A partial rule (exec alone) survives its own round trip.
        let policy = parse(
            r#"
[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"

[[authorization.path_rules]]
prefix = "/var/www"
exec   = "deny"
"#,
        )
        .unwrap();
        let rule = &policy.authorization.as_ref().unwrap().entries[0].path_rules[0];
        assert_eq!(rule.verdict.read, OpVerdict::Unspecified);
        assert_eq!(rule.verdict.exec, OpVerdict::Deny);
    }

    /// Class rules and entry rules for one prefix union per operation:
    /// the entry may fill an operation the class left unspecified, and
    /// may never change one the class decided.
    #[test]
    fn class_rules_union_per_operation() {
        let policy = parse(
            r#"
[[class]]
name = "web"

[[class.path_rules]]
prefix = "/var/www"
read   = "allow"

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
class  = "web"

[[authorization.path_rules]]
prefix = "/var/www"
write  = "deny"
exec   = "deny"
"#,
        )
        .unwrap();
        let rule = &policy.authorization.as_ref().unwrap().entries[0].path_rules[0];
        assert_eq!(rule.verdict.read, OpVerdict::Allow);
        assert_eq!(rule.verdict.write, OpVerdict::Deny);
        assert_eq!(rule.verdict.exec, OpVerdict::Deny);

        // …but a decision the class made is not the entry's to change.
        let error = parse(
            r#"
[[class]]
name = "web"

[[class.path_rules]]
prefix = "/var/www"
read = "deny"

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
class  = "web"

[[authorization.path_rules]]
prefix = "/var/www"
read = "allow"
"#,
        )
        .unwrap_err();
        assert!(error.contains("disagrees"), "{error}");
    }

    #[test]
    fn unknown_class_references_and_bad_names_are_rejected() {
        let error = parse(
            r#"
[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
class = "no-such-class"
"#,
        )
        .unwrap_err();
        assert!(error.contains("unknown class"), "{error}");

        let error = parse(
            r#"
[[class]]
name = "../escape"
cgroup = "/sys/fs/cgroup/wabbit"

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
"#,
        )
        .unwrap_err();
        assert!(error.contains("class name"), "{error}");

        // A concrete class whose compiled path would blow the eBPF
        // walk cap can never be walled, so the generator refuses it.
        let error = parse(&format!(
            r#"
[[class]]
name = "{}"
cgroup = "/sys/fs/cgroup/{}"

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit"
"#,
            "c".repeat(24),
            "d".repeat(40)
        ))
        .unwrap_err();
        assert!(error.contains("walk cap"), "{error}");

        let twice = parse(
            r#"
[[class]]
name = "dup"
cgroup = "/sys/fs/cgroup/wabbit"

[[class]]
name = "dup"
cgroup = "/sys/fs/cgroup/wabbit"
"#,
        )
        .unwrap_err();
        assert!(twice.contains("twice"), "{twice}");
    }

    /// A class and an entry naming the same compiled cgroup: the
    /// one-cgroup-one-entry rule catches the collision by name.
    #[test]
    fn a_class_cannot_shadow_an_entry() {
        let error = parse(
            r#"
[[class]]
name = "shell"
cgroup = "/sys/fs/cgroup/wabbit"

[[authorization]]
cgroup = "/sys/fs/cgroup/wabbit/class/shell"
"#,
        )
        .unwrap_err();
        assert!(error.contains("two authorization entries"), "{error}");
    }

    /// A policy may carry classes and no plain entries at all — the
    /// concrete classes still compile to their entries (the regression:
    /// the class entries used to append only to a non-empty section and
    /// silently vanished).
    #[test]
    fn classes_compile_even_without_plain_entries() {
        let policy = parse(
            r#"
[[class]]
name = "shell"
cgroup = "/sys/fs/cgroup/wabbit"
actions = ["exec"]
"#,
        )
        .unwrap();
        let config = policy.authorization.expect("the class compiled");
        assert_eq!(config.entries.len(), 1);
        assert_eq!(
            config.entries[0].cgroup,
            std::path::Path::new("/sys/fs/cgroup/wabbit/class/shell")
        );
    }

    /// The bootstrap shape, exactly as a bootable deployment needs it:
    /// `init.scope` carries bits (its PID 1 loads boot modules and
    /// spawns into walled unit cgroups) yet opts out of the wall — PID 1
    /// bootstraps into it from outside every wall, and a walled
    /// init.scope would refuse its own PID 1 and kill the boot.
    #[test]
    fn the_bootstrap_opt_out_compiles() {
        let policy = parse(
            r#"
[[class]]
name = "boot-hardware"
actions = ["kmods"]

[[authorization]]
cgroup = "/sys/fs/cgroup/init.scope"
class = "boot-hardware"
actions = ["cgroupfs-write"]
protect = false
"#,
        )
        .unwrap();
        let config = policy.authorization.unwrap();
        assert_eq!(config.entries.len(), 1);
        let entry = &config.entries[0];
        use wabbit_common::authorization as auth;
        assert_eq!(
            entry.action_mask,
            auth::ACTION_KMODS | auth::ACTION_CGROUPFS_WRITE
        );
        // Opted out, not walled: the UNPROTECTED bit, and no PROTECT.
        assert_eq!(entry.flags, auth::FLAG_UNPROTECTED);
        config.validate().unwrap();
    }

    /// `[network]` compiles each gate's reach independently; an omitted
    /// key keeps the strictest posture, and an unknown name is refused.
    #[test]
    fn network_postures_compile() {
        let policy = parse(
            r#"
[network]
bind = "ports"
"#,
        )
        .unwrap();
        assert_eq!(
            policy.network,
            Some(NetworkConfig {
                bind: BindPosture::Ports,
                raw_capture: RawCapturePosture::All,
            })
        );
        assert_eq!(parse("").unwrap().network, None);
        assert!(toml::from_str::<PolicyToml>("[network]\nbind = \"listeners\"\n").is_err());
    }

    /// `[default]` compiles to the default entry; the grants it may not
    /// carry, and an allow-list, are refused by name.
    #[test]
    fn the_default_section_compiles_and_refuses_wall_keys() {
        use wabbit_common::authorization as auth;
        let policy = parse(
            r#"
[default]
actions = ["bind-net"]

[[default.path_rules]]
prefix = "/etc/shadow"
verdict = "deny"
"#,
        )
        .unwrap();
        let default = policy.default.expect("the default compiled");
        assert_eq!(default.action_mask, auth::ACTION_BIND_NET);
        assert_eq!(default.path_rules.len(), 1);

        for action in ["cgroupfs-write", "mount", "bpf-attach", "signal"] {
            let error = parse(&format!("[default]\nactions = [\"{action}\"]\n")).unwrap_err();
            assert!(error.contains("default may not"), "{action}: {error}");
        }
        assert!(toml::from_str::<PolicyToml>("[default]\ndefault_deny = true\n").is_err());
    }
}
