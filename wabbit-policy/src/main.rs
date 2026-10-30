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
        AuthorizationConfig, AuthorizationEntry, MAX_PATH_RULES, PathRule, PathRuleVerdict,
    },
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
    authorization: Option<Vec<AuthorizationToml>>,
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

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct AuthorizationToml {
    /// The canonical cgroupfs path of the cgroup this entry authorizes.
    cgroup: PathBuf,
    /// Action names, as [`ActionName`] spells them.
    #[serde(default)]
    actions: Vec<ActionName>,
    /// Whether unruled paths are denied (allow-list) or allowed
    /// (deny-list) for this cgroup.
    #[serde(default)]
    default_deny: bool,
    #[serde(default)]
    path_rules: Vec<PathRuleToml>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct PathRuleToml {
    prefix: PathBuf,
    /// `allow` or `deny`.
    verdict: VerdictName,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum VerdictName {
    #[value(name = "allow")]
    Allow,
    #[value(name = "deny")]
    Deny,
}

impl From<&PathRule> for PathRuleToml {
    fn from(rule: &PathRule) -> Self {
        Self {
            prefix: rule.prefix.clone(),
            verdict: if rule.verdict.deny() {
                VerdictName::Deny
            } else {
                VerdictName::Allow
            },
        }
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
            actions,
            default_deny: entry.flags & wabbit_common::authorization::FLAG_PATH_RULES_DEFAULT_DENY
                != 0,
            path_rules: entry.path_rules.iter().map(PathRuleToml::from).collect(),
        })
    }
}

// ------------------------------------------------------------ conversions

impl TryFrom<PolicyToml> for Policy {
    type Error = String;

    fn try_from(source: PolicyToml) -> Result<Self, Self::Error> {
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
        let authorization = source.authorization.map(|entries| AuthorizationConfig {
            entries: entries
                .into_iter()
                .map(|entry| AuthorizationEntry {
                    cgroup: entry.cgroup,
                    action_mask: entry
                        .actions
                        .iter()
                        .map(|name| name.bit())
                        .fold(0, |mask, bit| mask | bit),
                    flags: if entry.default_deny {
                        wabbit_common::authorization::FLAG_PATH_RULES_DEFAULT_DENY
                    } else {
                        0
                    },
                    path_rules: entry
                        .path_rules
                        .into_iter()
                        .map(|rule| PathRule {
                            prefix: rule.prefix,
                            verdict: PathRuleVerdict::new(matches!(
                                rule.verdict,
                                VerdictName::Deny
                            )),
                        })
                        .collect(),
                })
                .collect(),
        });
        let policy = Self {
            rootfs,
            authorization,
        };
        if let Some(authorization) = &policy.authorization {
            authorization.validate()?;
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
        Ok(Self {
            rootfs,
            authorization,
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
    println!(
        "built {} ({} bytes, key id {key_id})",
        output.display(),
        bytes.len()
    );
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
                actions: vec![ActionName::Mount, ActionName::Kmods],
                default_deny: true,
                path_rules: vec![PathRuleToml {
                    prefix: "/etc/ssh".into(),
                    verdict: VerdictName::Allow,
                }],
            }]),
            rootfs: None,
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
}
