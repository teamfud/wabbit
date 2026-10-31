//! The `startup` policy section's runtime: launch each `[[startup]]`
//! program at its chosen point in system startup, in the class it names.
//!
//! The section is signed policy, so these launches spend the same trust
//! a signed IPC run command does — the class a `[[startup]]` entry names
//! is the same named profile a run resolves through
//! ([`crate::runs::class_entry`], the one convention path), and each
//! launched program gets the same ephemeral-cgroup treatment: created
//! under its class's cgroup (or wabbit's own, classless), migrated into
//! *before its first syscall* (see [`crate::runs::migrate_command`]),
//! released when it ends. Nothing a policy launches ever runs in
//! wabbit's own cgroup, and the migration wall covers every run cgroup
//! by prefix (see `crate::runs`).
//!
//! # The points
//!
//! * **`initrd`** — after the guard enforces, before `switch_root`:
//!   [`launch_initrd`], called on the main thread before the runtime
//!   exists, blocking (the point is for short one-shots; a program
//!   still running at the crossing is killed by a systemd initrd's
//!   sweep and runs on a deleted ramfs under a busybox one — the
//!   honest cost of an entry that does not exit).
//! * **`systemd`** — wabbit has crossed into the booted system:
//!   [`launch_post_crossing`] runs them at once.
//! * **`unit`** — the named unit has reached active
//!   (`systemctl is-active`): [`launch_post_crossing`] polls for each,
//!   launches on active, and times out per the entry's `timeout_secs`
//!   (`0` waits forever).
//!
//! # Ordering and ids
//!
//! Entries launch in policy order, one at a time per point. Each
//! entry's run id is `ID_BASE + its index in the section` — far above
//! the IPC counter's reachable space, so a startup run cgroup can
//! never collide with an IPC run's (both name the cgroup
//! `run-<id>`), and unique per entry per boot, so no two entries
//! share one.
//!
//! Failures are per-entry and fail-open: a launch that cannot resolve
//! its class, create its cgroup, or spawn its program logs a warning
//! and the next entry runs — a broken `[[startup]]` entry never takes
//! the boot's enforcement or its IPC server down with it.
//!
//! # What the policy authorizes
//!
//! A `[[startup]]` entry can name *any* class — including one carrying
//! `bpf-full`, `cgroupfs-write`, or any other wall-adjacent bit — and
//! the class resolution performs no further check. That is by design:
//! the signature on the policy is the authorization, the same trust a
//! signed IPC run command carries, and the signer who writes
//! `class = "ultra-privileged"` into a `[[startup]]` entry meant it.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use log::{info, warn};
use wabbit_policy::{
    authorization::AuthorizationEntry,
    startup::{StartupEntry, StartupKind},
};

use crate::{
    policy::Policy,
    runs::{self, PreparedRun, RunAuthorizer},
};

/// How long the unit point waits between polls of the unit's state.
const UNIT_POLL: Duration = Duration::from_millis(200);

/// Polls between progress log lines, for a unit that stays inactive.
const PROGRESS_EVERY: u64 = 250;

/// The id base for startup runs: far above the IPC counter's reachable
/// space (a boot would need two hundred trillion accepted commands),
/// so a startup cgroup can never collide with an IPC run's. The entry's
/// index in the section offsets it; see the module docs.
const ID_BASE: u64 = 1 << 48;

/// The `initrd` point: run its entries now, blocking, on the main
/// thread — before the tokio runtime exists (the callers hold that
/// line: [`launch_initrd`] runs between the handoff and the crossing).
///
/// Per-entry fail-open: a failed entry warns and the next one runs.
pub fn launch_initrd(policy: &Policy, authorizer: &Arc<dyn RunAuthorizer>) {
    if !section_validates(policy) {
        return;
    }
    for (index, entry) in entries_all(policy)
        .into_iter()
        .filter(|(_, entry)| entry.kind == StartupKind::Initrd)
    {
        if let Err(error) = launch_entry_blocking(entry, ID_BASE + index as u64, policy, authorizer)
        {
            warn!(
                "the initrd-point startup entry {index} ({}): {error:#}",
                describe(entry)
            );
        }
    }
}

/// The `systemd` and `unit` points: run their entries, in policy order,
/// awaiting each unit's active state per its own `timeout_secs`. Called
/// once the runtime exists, from a task that outlives the runs.
///
/// Per-entry fail-open: a failed entry warns and the next one runs.
pub async fn launch_post_crossing(policy: &Policy, authorizer: &Arc<dyn RunAuthorizer>) {
    if !section_validates(policy) {
        return;
    }
    for (index, entry) in entries_all(policy)
        .into_iter()
        .filter(|(_, entry)| matches!(entry.kind, StartupKind::Systemd | StartupKind::Unit))
    {
        let id = ID_BASE + index as u64;
        let outcome = async {
            if entry.kind == StartupKind::Unit {
                wait_for_unit(entry).await?;
            }
            launch_entry(entry, id, policy, authorizer).await
        }
        .await;
        if let Err(error) = outcome {
            warn!(
                "the post-crossing startup entry {index} ({}): {error:#}",
                describe(entry)
            );
        }
    }
}

/// One entry, blocking (the `initrd` point — before the runtime).
fn launch_entry_blocking(
    entry: &StartupEntry,
    id: u64,
    policy: &Policy,
    authorizer: &Arc<dyn RunAuthorizer>,
) -> Result<()> {
    let (program, args) = argv(entry);
    let prepared = prepare(entry, id, policy, authorizer)?;
    let mut child = match runs::spawn_migrated_blocking(program.as_str(), &args, &prepared) {
        Ok(child) => child,
        Err(error) => {
            authorizer.release_run(&prepared);
            return Err(error);
        }
    };
    // EOF on stdin: a program reading it proceeds, in its cgroup, under
    // its class.
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .context("waiting for the startup program");
    authorizer.release_run(&prepared);
    let output = output?;
    info!(
        "the startup program {program} ({}): exited {}",
        describe(entry),
        output.status
    );
    Ok(())
}

/// One entry, on the tokio runtime (the `systemd` and `unit` points).
async fn launch_entry(
    entry: &StartupEntry,
    id: u64,
    policy: &Policy,
    authorizer: &Arc<dyn RunAuthorizer>,
) -> Result<()> {
    let (program, args) = argv(entry);
    let prepared = prepare(entry, id, policy, authorizer)?;
    let mut child = match runs::spawn_migrated(program.as_str(), &args, &prepared) {
        Ok(child) => child,
        Err(error) => {
            authorizer.release_run(&prepared);
            return Err(error);
        }
    };
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .await
        .context("waiting for the startup program");
    authorizer.release_run(&prepared);
    let output = output?;
    info!(
        "the startup program {program} ({}): exited {}",
        describe(entry),
        output.status
    );
    Ok(())
}

/// Resolve the entry's class and create its ephemeral run cgroup: the
/// class's settings (or no authorization, for a classless entry) keyed
/// by the cgroup's fresh kernfs id — the same treatment an IPC run gets.
fn prepare(
    entry: &StartupEntry,
    id: u64,
    policy: &Policy,
    authorizer: &Arc<dyn RunAuthorizer>,
) -> Result<PreparedRun> {
    let class = resolve_class(entry, policy, authorizer)?;
    let prepared = authorizer
        .prepare_run(class.as_ref(), id)
        .context("preparing the startup run cgroup")?;
    info!(
        "prepared the startup run cgroup {}{}",
        prepared.cgroup.display(),
        if class.is_some() {
            " (classed)"
        } else {
            " (classless)"
        }
    );
    Ok(prepared)
}

/// The entry's class, resolved through the convention path against the
/// active policy (`None` for a classless entry — the policy default,
/// or the deny-by-default floor).
fn resolve_class(
    entry: &StartupEntry,
    policy: &Policy,
    authorizer: &Arc<dyn RunAuthorizer>,
) -> Result<Option<AuthorizationEntry>> {
    if entry.class.is_empty() {
        return Ok(None);
    }
    let own = authorizer.own_cgroup();
    Ok(Some(runs::class_entry(policy, &own, &entry.class)?))
}

/// The entry's program and arguments. The argv was validated at build
/// and at decode (non-empty, NUL-free, bounded) — the first element is
/// the program, the rest its arguments. Owned `String`s, because the
/// entry may outlive its `StartupConfig`.
fn argv(entry: &StartupEntry) -> (String, Vec<String>) {
    let mut args = entry.argv.iter().map(|arg| arg.value.clone());
    let program = args.next().expect("validate guarantees a program");
    (program, args.collect())
}

/// Wait for the entry's unit to reach active, polling
/// `systemctl is-active --quiet`, timing out per the entry's
/// `timeout_secs` (`0` waits forever).
///
/// `systemctl` failing to *run* (absent binary) fails the entry at once
/// — polling cannot fix a missing tool — while a *nonzero exit* (the
/// unit inactive or activating yet) is the poll's ordinary answer.
async fn wait_for_unit(entry: &StartupEntry) -> Result<()> {
    let deadline = (entry.timeout_secs != 0)
        .then(|| Instant::now() + Duration::from_secs(u64::from(entry.timeout_secs)));
    let mut polls: u64 = 0;
    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            bail!(
                "timed out after {}s waiting for {} to reach active",
                entry.timeout_secs,
                entry.unit
            );
        }
        match unit_active(&entry.unit).await {
            Ok(true) => {
                info!("the unit {} reached active", entry.unit);
                return Ok(());
            }
            Ok(false) => {}
            Err(error) => return Err(error),
        }
        if polls > 0 && polls % PROGRESS_EVERY == 0 {
            info!("still waiting for {} to reach active", entry.unit);
        }
        polls += 1;
        tokio::time::sleep(UNIT_POLL).await;
    }
}

/// Whether `systemctl` reports the unit active (`exit 0`). A nonzero
/// exit is "not active (yet)"; a failure to run the binary is an error.
async fn unit_active(unit: &str) -> Result<bool> {
    let status = tokio::process::Command::new("systemctl")
        .arg("is-active")
        .arg("--quiet")
        .arg(unit)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .with_context(|| format!("running systemctl is-active for {unit}"))?;
    Ok(status.success())
}

/// The section's `validate` contract, the same one the generator
/// enforces — the loader runs it before any entry launches (an invalid
/// *signed* section is a generator bug, so the section skips whole,
/// warn-first, and nothing launches).
fn section_validates(policy: &Policy) -> bool {
    let Some(config) = policy.startup.as_ref() else {
        return true;
    };
    if let Err(error) = config.validate() {
        warn!(
            "the policy's startup section is invalid ({error}); \
             skipping it — an invalid signed section is a generator bug"
        );
        return false;
    }
    true
}

/// Every entry with its index in the section (the run id's offset —
/// global, so the initrd and post-crossing launchers never reuse an id).
fn entries_all(policy: &Policy) -> Vec<(usize, &StartupEntry)> {
    policy
        .startup
        .as_ref()
        .map(|config| config.entries.iter().enumerate().collect())
        .unwrap_or_default()
}

/// One entry, for log lines: its point, unit, and class.
fn describe(entry: &StartupEntry) -> String {
    let kind = match entry.kind {
        StartupKind::Initrd => "initrd point",
        StartupKind::Systemd => "systemd point",
        StartupKind::Unit => "unit point",
    };
    format!(
        "{kind}{unit}{class}",
        unit = if entry.unit.is_empty() {
            String::new()
        } else {
            format!(" {}", entry.unit)
        },
        class = if entry.class.is_empty() {
            String::new()
        } else {
            format!(" class {}", entry.class)
        },
    )
}

#[cfg(test)]
mod tests {
    use wabbit_policy::{
        authorization::{AuthorizationConfig, AuthorizationEntry},
        startup::{StartupConfig, WireString},
    };

    use super::*;

    /// A policy carrying one startup entry per point, for the
    /// partitioning tests.
    fn policy() -> Policy {
        let entry = |kind: StartupKind, unit: &str| StartupEntry {
            kind,
            unit: unit.into(),
            class: "shell".into(),
            timeout_secs: 0,
            argv: vec![WireString {
                value: "/bin/true".into(),
            }],
        };
        Policy {
            rootfs: None,
            authorization: Some(AuthorizationConfig {
                entries: vec![AuthorizationEntry {
                    cgroup: "/sys/fs/cgroup/wabbit/class/shell".into(),
                    action_mask: 0,
                    flags: 0,
                    path_rules: Vec::new(),
                }],
            }),
            network: None,
            default: None,
            startup: Some(StartupConfig {
                entries: vec![
                    entry(StartupKind::Initrd, ""),
                    entry(StartupKind::Systemd, ""),
                    entry(StartupKind::Unit, "multi-user.target"),
                ],
            }),
        }
    }

    #[test]
    fn entries_partition_by_point() {
        let policy = policy();
        let initrd: Vec<_> = entries_all(&policy)
            .into_iter()
            .filter(|(_, entry)| entry.kind == StartupKind::Initrd)
            .collect();
        assert_eq!(initrd.len(), 1);
        assert_eq!(initrd[0].1.kind, StartupKind::Initrd);
        assert_eq!(initrd[0].0, 0, "the global index (the run id's offset)");

        let post: Vec<_> = entries_all(&policy)
            .into_iter()
            .filter(|(_, entry)| matches!(entry.kind, StartupKind::Systemd | StartupKind::Unit))
            .map(|(index, _)| index)
            .collect();
        // The post-crossing set keeps the *global* indices — the run
        // ids are ID_BASE + index, unique per entry across the points.
        assert_eq!(post, [1, 2]);
    }

    #[test]
    fn argv_splits_program_from_arguments() {
        let mut entry = entries_all(&policy())
            .into_iter()
            .find(|(_, entry)| entry.kind == StartupKind::Unit)
            .map(|(_, entry)| entry.clone())
            .unwrap();
        entry.argv = vec![
            WireString {
                value: "/usr/bin/probe".into(),
            },
            WireString {
                value: "--online".into(),
            },
            WireString {
                value: "extra arg".into(),
            },
        ];
        let (program, args) = argv(&entry);
        assert_eq!(program, "/usr/bin/probe");
        assert_eq!(args, ["--online", "extra arg"]);
    }

    #[test]
    fn describe_names_the_point() {
        let policy = policy();
        let entries = entries_all(&policy);
        assert_eq!(describe(entries[0].1), "initrd point class shell");
        assert_eq!(
            describe(entries[2].1),
            "unit point multi-user.target class shell"
        );
        let classless = StartupEntry {
            kind: StartupKind::Systemd,
            unit: String::new(),
            class: String::new(),
            timeout_secs: 0,
            argv: vec![WireString {
                value: "/bin/true".into(),
            }],
        };
        assert_eq!(describe(&classless), "systemd point");
    }

    /// A unit that exists (on a systemd host) or times out fast (on a
    /// dev box): the poll loop's shape, end to end — timeout honored,
    /// progress made, active reported.
    #[tokio::test]
    async fn the_unit_poll_times_out_or_finds_active() {
        let mut entry = entries_all(&policy())
            .into_iter()
            .find(|(_, entry)| entry.kind == StartupKind::Unit)
            .map(|(_, entry)| entry.clone())
            .unwrap();
        entry.unit = "no-such-unit-unicorn.service".into();
        entry.timeout_secs = 1;
        let started = Instant::now();
        let outcome = wait_for_unit(&entry).await;
        let error = outcome.expect_err("the unit never reaches active");
        assert!(
            error.to_string().contains("no-such-unit-unicorn.service"),
            "{error}"
        );
        // A 1-second timeout bounds the wait to about that.
        assert!(started.elapsed() < Duration::from_secs(10));

        // A unit that *is* active (on a systemd host) reports it.
        entry.unit = "multi-user.target".into();
        entry.timeout_secs = 30;
        if unit_active("multi-user.target").await.unwrap_or(false) {
            wait_for_unit(&entry)
                .await
                .expect("an active unit is found");
        } else {
            eprintln!("skipping: the test host has no active multi-user.target");
        }
    }
}
