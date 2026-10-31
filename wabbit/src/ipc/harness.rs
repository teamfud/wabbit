//! The IPC harness: the full **off-box → on-box** flow against the real
//! server, with the authorization each run receives recorded whole and
//! asserted against the compiled class it named.
//!
//! # What "off-box" and "on-box" mean here
//!
//! The client crate splits in two halves and the split *is* the boundary
//! (see `wabbit_ipc`'s docs): minting (`CommandClient`) needs the signing
//! key, the target boot's id, and the counter — and touches no socket;
//! delivery (`wabbit_ipc::deliver`) needs a socket path and the base64,
//! and nothing else — no key, no counter, no validation. The harness
//! drives exactly that split: every artifact is minted through the
//! client half while the socket points at **nothing** (the off-box
//! machine has no server), and delivered through `deliver` alone. The
//! CLI verbs — `encode-run` off box, the positional base64 on box — are
//! this same library pair.
//!
//! # What is asserted
//!
//! * the artifact is one printable line of base64; the real server
//!   decodes it; the run **executes on box** (a real `sh`, captured
//!   output, exit code, and the cgroup's `cgroup.procs` written by the
//!   child's own pre-exec migration);
//! * the class a run names resolves to **exactly** its compiled entry —
//!   action mask, flags, and path rules cloned whole — out of a policy
//!   carrying seventeen of them (the resolution must find the *right*
//!   entry, not just any): one class per action bit across the whole
//!   vocabulary, plus a flags-and-rules class whose verdict shapes map
//!   onto their `PATH_RULE_*` bits one to one;
//! * the run cgroup is the real shape — `run-<command id>` under the
//!   class's (or wabbit's own) cgroup, a fresh id per run — created by
//!   [`crate::runs::create_run_cgroup`], the same function the guard's
//!   `prepare_run` creates it with;
//! * every completed run **releases** its cgroup;
//! * the wire gates hold end to end: an unknown class refused by name
//!   with nothing prepared and its id burned, hostile class names never
//!   leaving the minter, a foreign signature and a foreign boot id
//!   refused, a replayed artifact worth nothing, the classless floor
//!   carrying no authorization — and the server still serving after
//!   every one of them.
//!
//! # What this deliberately does not prove
//!
//! The eBPF write itself — `Guard::prepare_run` inserting the recorded
//! entry into `AUTHORIZATIONS`/`PATH_RULES` keyed by the recorded
//! cgroup id, and the gates consulting it — is the boot self-test's
//! proof (`Guard::self_test`, which runs against the loaded guard on
//! every boot). The harness pins the contract at the trait the server
//! and the guard share: the server's resolution hands the guard exactly
//! this entry, and the guard's own proof covers what it does with it.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::Result;
use ed25519_dalek::SigningKey;
use tokio::sync::Notify;
use wabbit_common::authorization as auth;
use wabbit_ipc::{CommandClient, CommandOutcome};
use wabbit_policy::authorization::{
    AuthorizationConfig, AuthorizationEntry, OpVerdict, PathRule, PathRuleVerdict,
};

use super::{IpcState, read_boot_id, run_server};
use crate::{
    policy::Policy,
    runs::{self, PreparedRun, RunAuthorizer},
};

/// The signing seed the harness mints with — and whose public half the
/// server verifies against. A deployment's real key lives off box by
/// design; here the harness is both boxes at once, and this seed is the
/// whole key list the server gets.
const SEED: [u8; 32] = [0xA5; 32];

/// wabbit's own cgroup as the harness's authorizer reports it — the
/// subtree the class entries compile under (`<own>/class/<name>`).
const OWN: &str = "/sys/fs/cgroup/wabbit";

/// One recorded prepare: everything the server asked the authorizer to
/// grant one run, kept whole for the assertions.
struct Recorded {
    /// The class entry the server resolved for the run, cloned whole —
    /// exactly what `Guard::prepare_run` would write into
    /// `AUTHORIZATIONS` and `PATH_RULES` (keyed by [`Self::cgroup_id`]).
    class: Option<AuthorizationEntry>,
    /// The cgroupfs parent the run cgroup was created under, as the
    /// cgroupfs spells it: the class's compiled cgroup for a classed
    /// run, wabbit's own for a classless one.
    parent: String,
    /// The run cgroup's path — under the harness's temp root, mirroring
    /// the real shape — and its kernfs-shaped id.
    cgroup: PathBuf,
    cgroup_id: u64,
    /// The command id the run carried — also its cgroup's name.
    command_id: u64,
}

/// The harness's run authorizer: records every prepare and release, and
/// creates the run cgroups with the *real* [`runs::create_run_cgroup`]
/// — the same function the guard's `prepare_run` creates them with —
/// under a temp root mirroring the cgroupfs shape. The spawned run child
/// self-migrates exactly as on a real boot: a `cgroup.procs` file sits in
/// the created cgroup for the pre-exec write.
struct HarnessAuthorizer {
    /// The temp root standing in for `/`: a classed run's cgroup lands
    /// at `<root>/<own without the leading slash>/class/<name>/run-<id>`.
    root: PathBuf,
    preparations: StdMutex<Vec<Recorded>>,
    releases: StdMutex<Vec<PathBuf>>,
}

impl HarnessAuthorizer {
    fn new(label: &str) -> Arc<Self> {
        let root = std::env::temp_dir().join(format!(
            "wabbit-ipc-harness-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Arc::new(Self {
            root,
            preparations: StdMutex::new(Vec::new()),
            releases: StdMutex::new(Vec::new()),
        })
    }
}

impl Drop for HarnessAuthorizer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl RunAuthorizer for HarnessAuthorizer {
    fn own_cgroup(&self) -> String {
        OWN.to_string()
    }

    fn prepare_run(
        &self,
        class: Option<&AuthorizationEntry>,
        command_id: u64,
    ) -> Result<PreparedRun> {
        // The cgroupfs parent as the cgroupfs spells it, then the same
        // parent rooted under the harness's temp tree (`Path::join` with
        // an absolute path *replaces* the base, so the leading slash
        // comes off) — the fake mirrors the real shape underneath its
        // own root.
        let parent = class
            .map(|entry| entry.cgroup.display().to_string())
            .unwrap_or_else(|| OWN.to_string());
        let rooted = self.root.join(parent.trim_start_matches('/'));
        let (cgroup, cgroup_id) = runs::create_run_cgroup(&rooted, command_id)?;
        // The self-migration's landing target: a real cgroupfs exposes
        // `cgroup.procs` in every cgroup.
        std::fs::write(cgroup.join("cgroup.procs"), b"")?;
        self.preparations.lock().unwrap().push(Recorded {
            class: class.cloned(),
            parent,
            cgroup: cgroup.clone(),
            cgroup_id,
            command_id,
        });
        Ok(PreparedRun {
            cgroup,
            cgroup_id,
            rule_prefix_hashes: Vec::new(),
        })
    }

    fn release_run(&self, run: &PreparedRun) {
        let _ = std::fs::remove_dir_all(&run.cgroup);
        self.releases.lock().unwrap().push(run.cgroup.clone());
    }
}

/// The server state with the harness's key injected — the same
/// construction `server_state` performs, minus the compiled-in key list:
/// the harness signs with [`SEED`], so `SEED`'s public half is the whole
/// list as far as this server is concerned.
fn harness_state(policy: Policy, authorizer: Arc<dyn RunAuthorizer>) -> Arc<IpcState> {
    let key = SigningKey::from_bytes(&SEED);
    Arc::new(IpcState {
        active_policy: StdMutex::new(policy),
        boot_id: read_boot_id().expect("the test host has a boot id"),
        last_command_id: std::sync::atomic::AtomicU64::new(0),
        public_keys: vec![key.verifying_key()],
        authorizer,
        stop: Arc::new(Notify::new()),
    })
}

/// The compiled entry of class `name` under [`OWN`] — spelled with the
/// same [`runs::class_cgroup_path`] convention the server resolves with,
/// so the fixture and the runtime cannot drift.
fn class_entry(
    name: &str,
    action_mask: u64,
    flags: u64,
    path_rules: Vec<PathRule>,
) -> AuthorizationEntry {
    AuthorizationEntry {
        cgroup: PathBuf::from(runs::class_cgroup_path(OWN, name).unwrap()),
        action_mask,
        flags,
        path_rules,
    }
}

/// One path rule, for the fixtures.
fn rule(prefix: &str, verdict: PathRuleVerdict) -> PathRule {
    PathRule {
        prefix: prefix.into(),
        verdict,
    }
}

/// A policy carrying exactly these authorization entries (the shape a
/// `wabbit-policy build` compile leaves: classes folded away into
/// entries, no class concept surviving).
fn policy_with(entries: Vec<AuthorizationEntry>) -> Policy {
    Policy {
        rootfs: None,
        authorization: Some(AuthorizationConfig { entries }),
        network: None,
        default: None,
        startup: None,
    }
}

/// One temp directory per harness test, labeled for the failure messages.
fn temp_dir_for(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wabbit-ipc-harness-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Poll until the server's socket exists (bind), up to five seconds.
async fn wait_for_socket(socket: &Path) {
    for _ in 0..500 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the IPC socket {} never appeared", socket.display());
}

/// The core ask: a run payload minted **off box** — no server in
/// existence, the socket path pointing at nothing — reaches the **on
/// box** server through the delivery half alone, executes there, and
/// carries exactly the class it named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_off_box_mint_reaches_the_on_box_run() {
    let directory = temp_dir_for("offbox");
    let socket = directory.join("socket");
    let counter = directory.join("counter");

    let authorizer = HarnessAuthorizer::new("offbox");
    let shell = class_entry(
        "shell",
        auth::ACTION_EXEC | auth::ACTION_CREDENTIALS,
        auth::FLAG_PATH_RULES_DEFAULT_DENY,
        vec![rule("/usr", PathRuleVerdict::allow_all())],
    );
    let state = harness_state(
        policy_with(vec![shell.clone()]),
        Arc::clone(&authorizer) as Arc<dyn RunAuthorizer>,
    );

    // OFF BOX — the minting half, with no server in existence: the socket
    // path points at nothing yet, and minting touches no socket. The
    // key, the target boot's id, and the counter are the whole of what
    // minting needs — which is what lets the key live wherever it lives.
    let minter = CommandClient::with_boot_id(
        socket.clone(),
        &SEED,
        counter,
        wabbit_ipc::read_boot_id().expect("the test host has a boot id"),
    );
    let minted = minter
        .mint_run_in_class("sh", ["-c", "echo off-box"], Some("shell"))
        .expect("minting needs no server");
    // One printable line: the pasteable, carriable artifact.
    assert!(minted.is_ascii());
    assert_eq!(minted.lines().count(), 1);

    // ON BOX — the server, then the delivery half alone: a socket path
    // and the base64. No key, no counter, no validation.
    let server = tokio::spawn(run_server(socket.clone(), state));
    wait_for_socket(&socket).await;
    let outcome = wabbit_ipc::deliver(&socket, &minted).expect("the delivered run completes");

    // The program ran on box, and its output came back.
    let CommandOutcome::Completed(output) = outcome else {
        panic!("expected a completed run, got {outcome:?}");
    };
    assert_eq!(output.status, Some(0));
    assert_eq!(output.stdout, b"off-box\n");

    // The authorization the run received: the shell class resolved out
    // of the active policy — mask, flags, and path rules whole — and the
    // real cgroup shape, `run-<command id>` under the class's compiled
    // cgroup, created by the same function the guard's `prepare_run`
    // creates it with.
    {
        let preparations = authorizer.preparations.lock().unwrap();
        assert_eq!(preparations.len(), 1);
        let recorded = &preparations[0];
        assert_eq!(
            recorded.class.as_ref(),
            Some(&shell),
            "the run carries exactly the shell class"
        );
        assert_eq!(recorded.parent, shell.cgroup.display().to_string());
        assert_eq!(recorded.command_id, 1, "the fresh counter's first mint");
        let rooted = authorizer
            .root
            .join(shell.cgroup.display().to_string().trim_start_matches('/'));
        assert_eq!(
            recorded.cgroup,
            runs::run_cgroup_path(&rooted, 1),
            "the run cgroup is run-<command id> under its class's compiled cgroup"
        );
        assert_ne!(recorded.cgroup_id, 0, "the run cgroup has a kernfs id");
    }
    // And the cgroup died with the run.
    {
        let releases = authorizer.releases.lock().unwrap();
        assert_eq!(releases.len(), 1, "the completed run released its cgroup");
        assert!(!releases[0].exists(), "the released run cgroup is gone");
    }

    server.abort();
    std::fs::remove_dir_all(&directory).ok();
}

/// Every grantable perm arrives at its run: one class per action bit —
/// the whole vocabulary — plus a flags-and-path-rules class, all in ONE
/// policy, so each run's resolution must pick its own entry out of
/// seventeen, not just any. What arrives at the authorizer is asserted
/// equal to the compiled entry, whole: mask, flags, and rules.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_grantable_perm_arrives_at_its_run() {
    let directory = temp_dir_for("perms");
    let socket = directory.join("socket");
    let counter = directory.join("counter");

    let authorizer = HarnessAuthorizer::new("perms");

    // The full action vocabulary, one class per bit.
    let vocabulary: &[(u64, &str)] = &[
        (auth::ACTION_SETNS, "bit-setns"),
        (auth::ACTION_UNSHARE, "bit-unshare"),
        (auth::ACTION_MOUNT, "bit-mount"),
        (auth::ACTION_EXEC, "bit-exec"),
        (auth::ACTION_CREDENTIALS, "bit-credentials"),
        (auth::ACTION_TAG_CONTROL, "bit-tag-control"),
        (auth::ACTION_BPF_ATTACH, "bit-bpf-attach"),
        (auth::ACTION_BPF_FULL, "bit-bpf-full"),
        (auth::ACTION_KMODS, "bit-kmods"),
        (auth::ACTION_CGROUPFS_WRITE, "bit-cgroupfs-write"),
        (auth::ACTION_FIREWALL, "bit-firewall"),
        (auth::ACTION_RAW_CAPTURE, "bit-raw-capture"),
        (auth::ACTION_BIND_NET, "bit-bind-net"),
        (auth::ACTION_SIGNAL_OTHERS, "bit-signal"),
        (auth::ACTION_PATH_BYPASS, "bit-path-bypass"),
    ];
    let mut cases: Vec<(&str, AuthorizationEntry)> = vocabulary
        .iter()
        .map(|(bit, name)| (*name, class_entry(name, *bit, 0, Vec::new())))
        .collect();

    // The flags-and-rules class: both flag bits a class can carry, and
    // one rule per verdict shape the wire has — the shorthand allows,
    // the shorthand denies, a per-operation mix, and a partial rule
    // that decides exec alone.
    let flagged_rules = vec![
        rule("/allow-all", PathRuleVerdict::allow_all()),
        rule("/deny-all", PathRuleVerdict::deny_all()),
        rule(
            "/mixed",
            PathRuleVerdict {
                read: OpVerdict::Allow,
                write: OpVerdict::Deny,
                exec: OpVerdict::Deny,
            },
        ),
        rule(
            "/exec-only",
            PathRuleVerdict {
                read: OpVerdict::Unspecified,
                write: OpVerdict::Unspecified,
                exec: OpVerdict::Deny,
            },
        ),
    ];
    cases.push((
        "flagged",
        class_entry(
            "flagged",
            auth::ACTION_KMODS,
            auth::FLAG_PROTECT | auth::FLAG_PATH_RULES_DEFAULT_DENY,
            flagged_rules,
        ),
    ));

    let state = harness_state(
        policy_with(cases.iter().map(|(_, entry)| entry.clone()).collect()),
        Arc::clone(&authorizer) as Arc<dyn RunAuthorizer>,
    );
    let server = tokio::spawn(run_server(socket.clone(), state));
    wait_for_socket(&socket).await;

    let minter = CommandClient::with_boot_id(
        socket.clone(),
        &SEED,
        counter,
        wabbit_ipc::read_boot_id().expect("the test host has a boot id"),
    );

    // One run per class, delivered in order: the ids run 1..=17, each
    // run lands in its own class's cgroup, and each carries exactly
    // that class's entry.
    let mut cgroup_ids = Vec::new();
    for (index, (name, expected)) in cases.iter().enumerate() {
        let id = index as u64 + 1;
        // Off box: mint naming this class. On box: deliver alone.
        let minted = minter
            .mint_run_in_class("sh", ["-c", "true"], Some(name))
            .unwrap();
        let outcome = wabbit_ipc::deliver(&socket, &minted)
            .unwrap_or_else(|error| panic!("the {name} run: {error}"));
        assert!(
            matches!(outcome, CommandOutcome::Completed(_)),
            "the {name} run executed on box"
        );

        // What arrived: exactly the compiled entry — mask, flags, and
        // path rules whole — resolved out of the seventeen this policy
        // carries, and the real cgroup shape under that class's own
        // compiled cgroup, named by this run's id.
        {
            let preparations = authorizer.preparations.lock().unwrap();
            assert_eq!(preparations.len(), index + 1, "one preparation per run");
            let recorded = preparations.last().unwrap();
            assert_eq!(
                recorded.class.as_ref(),
                Some(expected),
                "the {name} class arrives whole: mask, flags, and rules"
            );
            assert_eq!(recorded.parent, expected.cgroup.display().to_string());
            assert_eq!(recorded.command_id, id);
            let rooted = authorizer
                .root
                .join(expected.cgroup.display().to_string().trim_start_matches('/'));
            assert_eq!(
                recorded.cgroup,
                runs::run_cgroup_path(&rooted, id),
                "the {name} run cgroup is run-<command id> under its own class"
            );
            assert_ne!(recorded.cgroup_id, 0, "the run cgroup has a kernfs id");
            cgroup_ids.push(recorded.cgroup_id);
        }
    }

    // Every run cgroup got a fresh id, and every run was released.
    let mut distinct = cgroup_ids.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), cgroup_ids.len(), "every run cgroup is fresh");
    assert_eq!(
        authorizer.releases.lock().unwrap().len(),
        cases.len(),
        "every completed run released its cgroup"
    );

    // The flagged class's rules, decoded: each verdict shape arrives as
    // exactly its `PATH_RULE_*` map bits — the one-to-one the loader
    // relies on when it writes a rule verbatim.
    use auth::{
        PATH_RULE_EXEC_ALLOW, PATH_RULE_EXEC_DENY, PATH_RULE_READ_ALLOW, PATH_RULE_READ_DENY,
        PATH_RULE_WRITE_ALLOW, PATH_RULE_WRITE_DENY,
    };
    let flagged = {
        let preparations = authorizer.preparations.lock().unwrap();
        // The last case delivered is the flagged class.
        assert_eq!(preparations.last().unwrap().class.as_ref().map(|e| e.cgroup.clone()),
            Some(class_entry("flagged", 0, 0, Vec::new()).cgroup));
        preparations.last().unwrap().class.as_ref().unwrap().clone()
    };
    let expected_bits = [
        PATH_RULE_READ_ALLOW | PATH_RULE_WRITE_ALLOW | PATH_RULE_EXEC_ALLOW,
        PATH_RULE_READ_DENY | PATH_RULE_WRITE_DENY | PATH_RULE_EXEC_DENY,
        PATH_RULE_READ_ALLOW | PATH_RULE_WRITE_DENY | PATH_RULE_EXEC_DENY,
        PATH_RULE_EXEC_DENY,
    ];
    for (recorded_rule, bits) in flagged.path_rules.iter().zip(expected_bits) {
        assert_eq!(
            recorded_rule.verdict_bits(),
            bits,
            "the {} rule's map bits",
            recorded_rule.prefix.display()
        );
    }

    server.abort();
    std::fs::remove_dir_all(&directory).ok();
}

/// The wire gates, end to end: every refusal refuses by name, burns what
/// it must, and leaves the server serving; the classless floor carries
/// nothing; hostile class names never leave the minter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wire_gates_hold_end_to_end() {
    let directory = temp_dir_for("gates");
    let socket = directory.join("socket");
    let counter = directory.join("counter");
    let boot_id = wabbit_ipc::read_boot_id().expect("the test host has a boot id");

    let authorizer = HarnessAuthorizer::new("gates");
    let shell = class_entry("shell", auth::ACTION_EXEC, 0, Vec::new());
    let state = harness_state(
        policy_with(vec![shell.clone()]),
        Arc::clone(&authorizer) as Arc<dyn RunAuthorizer>,
    );
    let server = tokio::spawn(run_server(socket.clone(), state));
    wait_for_socket(&socket).await;

    // The minter: the deployment's key half, pointed at this socket.
    // Every mint spends the shared counter's next id.
    let minter =
        || CommandClient::with_boot_id(socket.clone(), &SEED, counter.clone(), boot_id);

    // A class the policy does not define: refused by name, nothing ever
    // prepared, and the id burned — the next mint is fresh.
    let minted = minter()
        .mint_run_in_class("sh", ["-c", "true"], Some("no-such-class"))
        .unwrap();
    let error = wabbit_ipc::deliver(&socket, &minted)
        .unwrap_err()
        .to_string();
    assert!(error.contains("no class"), "{error}");
    assert!(
        authorizer.preparations.lock().unwrap().is_empty(),
        "nothing is prepared for a refused class"
    );

    // The id burned on the refusal: the counter minted 1 for it, so the
    // next mint is 2 and goes straight through.
    let minted = minter()
        .mint_run_in_class("sh", ["-c", "echo recovered"], Some("shell"))
        .unwrap();
    wabbit_ipc::deliver(&socket, &minted).expect("the server serves on after a refusal");
    {
        let preparations = authorizer.preparations.lock().unwrap();
        assert_eq!(preparations.len(), 1);
        assert_eq!(preparations[0].command_id, 2, "the refusal burned its id");
        assert_eq!(preparations[0].class.as_ref(), Some(&shell));
    }

    // Hostile class names never leave the minter: the client refuses to
    // sign anything that could reinterpret as a path.
    for hostile in ["../escape", "sh/ell", "UPPER", "has space", ""] {
        assert!(
            minter()
                .mint_run_in_class("sh", ["-c", "true"], Some(hostile))
                .is_err(),
            "the minter refuses to sign {hostile:?}"
        );
    }

    // A foreign signing key: the signature gate.
    let foreign = CommandClient::with_boot_id(
        socket.clone(),
        &[0xEE; 32],
        directory.join("foreign-counter"),
        boot_id,
    );
    let minted = foreign.mint_run("sh", ["-c", "true"]).unwrap();
    let error = wabbit_ipc::deliver(&socket, &minted)
        .unwrap_err()
        .to_string();
    assert!(error.contains("signature"), "{error}");

    // A command minted for another boot: this boot never accepts it.
    let mut other_boot = boot_id;
    other_boot[0] ^= 1;
    let minted = CommandClient::with_boot_id(
        socket.clone(),
        &SEED,
        directory.join("other-boot-counter"),
        other_boot,
    )
    .mint_run("sh", ["-c", "true"])
    .unwrap();
    let error = wabbit_ipc::deliver(&socket, &minted)
        .unwrap_err()
        .to_string();
    assert!(error.contains("another boot"), "{error}");

    // A replayed artifact: the exact same bytes, worth nothing twice.
    let minted = minter().mint_run("sh", ["-c", "echo once"]).unwrap();
    wabbit_ipc::deliver(&socket, &minted).expect("the first delivery runs");
    let replay = wabbit_ipc::deliver(&socket, &minted)
        .unwrap_err()
        .to_string();
    assert!(replay.contains("already used"), "{replay}");

    // The classless floor: no class named, no authorization of its own —
    // the run cgroup under wabbit's own cgroup, carrying nothing.
    let minted = minter().mint_run("sh", ["-c", "echo floor"]).unwrap();
    let outcome = wabbit_ipc::deliver(&socket, &minted).expect("a classless run completes");
    assert!(matches!(outcome, CommandOutcome::Completed(_)));
    {
        let preparations = authorizer.preparations.lock().unwrap();
        let recorded = preparations.last().unwrap();
        assert_eq!(
            recorded.class, None,
            "the classless floor carries no authorization"
        );
        assert_eq!(
            recorded.parent, OWN,
            "the classless parent is wabbit's own cgroup"
        );
    }

    // And the server is still serving after every gate: one more run.
    let minted = minter().mint_run("sh", ["-c", "echo alive"]).unwrap();
    wabbit_ipc::deliver(&socket, &minted).expect("the server outlives its refusals");

    server.abort();
    std::fs::remove_dir_all(&directory).ok();
}