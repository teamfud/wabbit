//! The steady-state guard: the `wabbit` side of loading and running
//! `wabbit-ebpf`.
//!
//! [`Guard::load`] is the startup diagram's "load and attach bpf
//! protections in non-enforce mode": the object loads with its maps (aya
//! creates them from the `.maps` section), wabbit's own PID and cgroup are
//! trusted **before the first program attaches** — the gates would
//! otherwise deny the very `bpf(2)` calls that attach them — and every LSM
//! gate and tracepoint attaches in observing mode (`ENFORCING == 0`).
//!
//! [`Guard::self_test`] is the diagram's self-test loops. Workers re-exec
//! this binary from a sacrificial cgroup under wabbit's own — outside
//! wabbit's trust (a fork inherits the cgroup, but a fresh PID and a fresh
//! cgroup id are exactly what the gates key on) — and each performs
//! exactly one syscall. The observing phase asserts the gates *fired and
//! traced their decisions* into `DECISIONS`; the enforcing flip re-runs the
//! steps expecting `EPERM`.
//!
//! # Which denials are provable, honestly
//!
//! wabbit-initrd's bnuuy gates stay attached while it lives (until the
//! handoff's exit), and LSM hooks run in attach order: bnuuy attached
//! first, and the LSM chain stops at the first denial — so
//! for the hooks both defend (`bpf`, `kernel_read_file`, module-tree
//! writes, bpffs opens) bnuuy's verdict wins and guard's gate never runs.
//! A worker there is *still denied* (defense in depth), but the denial is
//! bnuuy's, not provably guard's. The self-test therefore splits:
//!
//! * **reachable steps** — a mount over the protected cgroup paths, a
//!   netfilter netlink socket, a writable cgroupfs open, a legacy firewall
//!   `setsockopt`, the sketch's gates (a raw-capture socket, a network
//!   bind, a cross-task signal), and the per-operation path-rule steps
//!   (a seeded rule denies write and exec under one prefix; read stays
//!   open) — hooks bnuuy does not wall (`PATH_RULES` and the sketch's
//!   gates are guard's alone) — run in *both* phases with full
//!   assertions: observing = allowed + `DECISIONS` trace, enforcing =
//!   `EPERM`. Two steps assert the *default allows* instead, in both
//!   phases: the rule-prefix read and the self-signal — the flip must
//!   never cost a process its opens' unruled classes or `raise(3)`.
//! * **shadowed steps** — `bpf(2)`, `finit_module(2)`, a module-tree
//!   writable open — run in the *enforcing* phase only, expecting `EPERM`
//!   from *either* layer, with no `DECISIONS` assertion: under bnuuy the
//!   early gate denies first, standalone guard's does. Both prove the
//!   system denies; neither proves which.
//!
//! Standalone (dev) runs have no bnuuy, so there the shadowed steps are
//! guard's own — the split costs nothing.
//!
//! # Worker protocol
//!
//! A worker is `--<name>-selftest-<step>` on this binary's own
//! `/proc/self/exe`: that path resolves the *inode* (a memfd-launched
//! wabbit's `current_exe()` string is `/memfd:<name> (deleted)` and cannot
//! be exec'd), so re-exec works in every launch mode. The worker first
//! blocks reading one byte from stdin — the parent moves it into the
//! sacrificial cgroup after the fork and *then* writes the byte, so the
//! worker's syscall cannot race its own migration — then performs its one
//! syscall and exits:
//!
//! | exit | meaning |
//! | --- | --- |
//! | 0 | the syscall was denied with `EPERM` |
//! | 1 | the syscall went through (or failed with another errno) |
//! | 3 | the worker could not set the test up |
//! | 4 | inconclusive (missing capability) |

use std::{
    env, fs,
    io::{self, Read, Write},
    mem::size_of,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use aya::{
    Btf,
    maps::{Array, HashMap, MapError},
    programs::{Lsm, TracePoint},
};
use log::{debug, info, warn};
use rustix::{
    io::Errno,
    mount::{MountFlags, mount},
};
use wabbit_common::{
    authorization::{
        CODE_WOULD_DENY, CgroupKey, ENFORCE, HOOK_BIND, HOOK_FILE_OPEN, HOOK_SB_MOUNT,
        HOOK_SETSOCKOPT, HOOK_SOCKET_CREATE, HOOK_TASK_KILL, decision_key, path_hash,
    },
    brand::NAME,
};

use wabbit_policy::network::{BindPosture, NetworkConfig, RawCapturePosture};

use crate::policy::Policy;

/// The unified cgroup hierarchy's mount point (wabbit-initrd mounts or
/// verifies it before wabbit starts).
const CGROUPFS_ROOT: &str = "/sys/fs/cgroup";

/// tracefs's mount point, for tracepoint attach.
const TRACING_ROOT: &str = "/sys/kernel/tracing";

/// The `sched_process_fork` record layouts this object carries variants
/// for: 44 for a vanilla `trace_entry` header, 48 for RHEL's
/// lazy-preempt-padded one. See `wabbit-ebpf/src/tracepoints/watch.rs`.
const CHILD_PID_VANILLA: usize = 44;
const CHILD_PID_PREEMPT_LAZY: usize = 48;

/// The loaded guard: the `aya::Ebpf` object, held for this process's whole
/// lifetime because the attachment's lifetime *is* the enforcement — its
/// links detach the moment it drops.
#[derive(Debug)]
pub struct Guard {
    ebpf: aya::Ebpf,
    /// The wabbit cgroup directory (`$CGROUPFS_ROOT/<cgroup>`), the path
    /// the authorization model keys on and whose hash `PROTECTED_PATHS`
    /// carries.
    cgroup: PathBuf,
    /// The cgroup's kernfs id — the same id
    /// `bpf_get_current_cgroup_id` reports for a task inside it and
    /// `stat(2)` reports as the directory's `st_ino`.
    cgroup_id: u64,
    /// The network gates' reach as loaded into `NET_POSTURE`: the
    /// self-test proves exactly the postures in force.
    network: NetworkConfig,
}

/// What [`Guard::seed_path_rule_steps`] seeded, for
/// [`Guard::release_path_rule_steps`] to undo: the map entries and their
/// priors (captured so a policy that named the selftest cgroup keeps its
/// authorization), and the prefix directory with its targets.
struct RuleSeed {
    /// The selftest cgroup's kernfs id — the map keys' cgroup half.
    cgroup_id: u64,
    /// The seeded rule's key: the cgroup id and the hashed prefix.
    rule_key: wabbit_common::authorization::PathRuleKey,
    /// The `PATH_RULES` value at the key before the seed, if any.
    prior_rule: Option<u32>,
    /// The selftest cgroup's `AUTHORIZATIONS` value before the seed, if
    /// any.
    prior_authorization: Option<wabbit_common::authorization::Authorization>,
    /// The data file the read and write steps open.
    data: PathBuf,
    /// The exec target the exec step execves: a copy of this binary.
    exec_target: PathBuf,
    /// The prefix directory holding both targets.
    dir: PathBuf,
}

impl RuleSeed {
    /// The read/write steps' target, as a worker argument.
    fn data_arg(&self) -> String {
        self.data.display().to_string()
    }

    /// The exec step's target, as a worker argument.
    fn exec_arg(&self) -> String {
        self.exec_target.display().to_string()
    }
}

impl Guard {
    /// Load the guard object, trust wabbit itself, populate the maps from
    /// `policy`'s authorization section, and attach every gate in
    /// observing mode.
    ///
    /// The map population happens between `trust_self` and the first
    /// attach: while the world is (in the full flow) still frozen under
    /// winit's babysit, so nothing races the loader.
    pub fn load(btf: &Btf, policy: &Policy) -> Result<Guard> {
        let mut ebpf = aya::EbpfLoader::new()
            .btf(Some(btf))
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/guard"
            )))?;

        let (cgroup, cgroup_id) =
            self_cgroup().context("finding this process's cgroup in cgroup v2")?;
        trust_self(&mut ebpf, &cgroup, cgroup_id)?;
        populate_authorizations(&mut ebpf, policy, &cgroup)
            .context("populating the authorization maps")?;
        populate_default(&mut ebpf, policy).context("populating the default entry")?;
        let network = policy.network.clone().unwrap_or_default();
        populate_net_posture(&mut ebpf, &network).context("populating NET_POSTURE")?;

        // Every gate attaches observing (`ENFORCING == 0`, its loaded
        // default): the self-test phase of the diagram.
        attach_lsm(&mut ebpf, btf, "bpf", &["bpf_gate"])?;
        attach_lsm(&mut ebpf, btf, "kernel_read_file", &["kmod_gate"])?;
        attach_lsm(
            &mut ebpf,
            btf,
            "file_open",
            &["file_open_modern", "file_open_legacy"],
        )?;
        attach_lsm(&mut ebpf, btf, "sb_mount", &["sb_mount"])?;
        attach_lsm(&mut ebpf, btf, "socket_setsockopt", &["firewall_gate"])?;
        attach_lsm(&mut ebpf, btf, "socket_create", &["netfilter_netlink_gate"])?;
        attach_lsm(&mut ebpf, btf, "socket_create", &["raw_capture_gate"])?;
        attach_lsm(&mut ebpf, btf, "socket_bind", &["bind_gate"])?;
        attach_lsm(&mut ebpf, btf, "task_kill", &["signal_gate"])?;
        let tracepoints = attach_tracepoints(&mut ebpf)?;
        if !tracepoints {
            warn!("tracepoints unavailable: fork and module-load self-test assertions are skipped");
        }
        info!(
            "guard loaded: 9 gates attached (observing), tracepoints {}",
            if tracepoints {
                "attached"
            } else {
                "unavailable"
            }
        );

        Ok(Guard {
            ebpf,
            cgroup,
            cgroup_id,
            network,
        })
    }

    /// The diagram's self-test loops: observe, assert the decisions were
    /// traced, flip to enforcing, and re-test expecting denials.
    pub fn self_test(&mut self) -> Result<()> {
        let selftest_cgroup = self
            .create_selftest_cgroup()
            .context("creating the sacrificial selftest cgroup")?;

        // Seed the selftest cgroup as a *listed* boundary (an entry with
        // no action bits and one path rule) before any step runs: the
        // signal gate's posture is default-allow, so a cross-task kill is
        // denied here exactly because this cgroup is listed without the
        // `signal` bit — the enforcing `signal` step depends on it, and
        // the path-rule steps need their seeded rule and targets.
        let seeded = self.seed_path_rule_steps(&selftest_cgroup)?;

        // The observing phase: every reachable step must be *allowed* and
        // have traced its would-deny decision. The workers' forks must be
        // recorded from the kernel side.
        //
        // These steps are the hooks bnuuy does not wall (see the module
        // docs): guard's gates provably fire under wabbit-initrd's babysit
        // and standalone alike.
        let mut reachable: Vec<(&str, String)> = vec![
            (STEP_MOUNT, self.cgroup_string()),
            (STEP_NETFILTER, String::new()),
            (
                STEP_CGROUPFS_WRITE,
                selftest_cgroup.join("cgroup.procs").display().to_string(),
            ),
            (STEP_FIREWALL, String::new()),
            // kill(getppid(), 0): signal 0 performs the whole permission
            // walk — LSM hook included — without delivering anything, so
            // the step is side-effect-free even when it passes. Denied
            // in the enforcing round exactly because the selftest cgroup
            // is a *listed* boundary without the `signal` bit.
            (STEP_SIGNAL, String::new()),
        ];
        // The network gates are tested at exactly the reach the policy
        // gave them: a gate switched off has nothing to deny, and an
        // ephemeral bind is a deny step only where the posture gates it.
        // (`AF_PACKET` is gated under both `all` and `icmp`.)
        let mut always_allowed: Vec<&str> = vec![STEP_SIGNAL_SELF];
        if self.network.raw_capture != RawCapturePosture::Off {
            reachable.push((STEP_RAW_CAPTURE, String::new()));
        }
        if self.network.bind != BindPosture::Off {
            reachable.push((STEP_BIND_NET, String::new()));
        }
        if self.network.bind == BindPosture::All {
            reachable.push((STEP_BIND_EPHEMERAL, String::new()));
        } else {
            always_allowed.push(STEP_BIND_EPHEMERAL);
        }
        for (step, arg) in &reachable {
            let pid = self.run_worker(&selftest_cgroup, step, arg.as_str(), false)?;
            self.check_fork_event(pid, step)?;
        }

        // The exemptions, allowed in *both* phases (the enforcing round
        // below repeats them): the signal gate's `kill(getpid(), 0)` —
        // the flip must never cost a process `raise(3)` — and, unless
        // the bind posture is `all`, the port-0 bind a client makes
        // before connecting.
        for step in &always_allowed {
            let pid = self.run_worker(&selftest_cgroup, step, "", false)?;
            self.check_fork_event(pid, step)?;
        }

        // The per-operation path-rule steps: a seeded rule denies write
        // and exec under one prefix and leaves read to the default, so
        // the steps prove each operation class independently. bnuuy
        // hosts no `PATH_RULES`, so every denial here is provably
        // guard's own — these are reachable steps, assertable in both
        // phases.
        if let Some(seeded) = &seeded {
            for (step, arg) in [
                (STEP_RULES_READ, seeded.data_arg()),
                (STEP_RULES_WRITE, seeded.data_arg()),
                (STEP_RULES_EXEC, seeded.exec_arg()),
            ] {
                let pid = self.run_worker(&selftest_cgroup, step, &arg, false)?;
                self.check_fork_event(pid, step)?;
            }
        }
        self.check_decisions("observing")?;

        // The flip: the diagram's "start enforcing".
        self.set_enforcing(ENFORCE).context("flipping ENFORCING")?;
        info!("guard is enforcing");

        // The enforcing phase owns the module-load assertion: the
        // observing phase *allows* every reachable syscall by design, and
        // some of those legitimately trigger in-tree auto-loads on
        // modular kernels (the firewall step's legacy `setsockopt`
        // requests `ip_tables`, loaded by modprobe, on Rocky 9 — measured).
        // Clear the trace here so the assertion below proves the
        // protection, not the observation.
        let mut module_loads: HashMap<_, u32, u8> = self
            .ebpf
            .map_mut("MODULE_LOADS")
            .context("finding MODULE_LOADS")?
            .try_into()
            .context("opening MODULE_LOADS")?;
        let observed: Vec<u32> = module_loads
            .keys()
            .collect::<Result<Vec<u32>, MapError>>()
            .context("reading MODULE_LOADS")?;
        for pid in observed {
            debug!("observing phase recorded a module load by pid {pid}");
            let _ = module_loads.remove(&pid);
        }
        drop(module_loads);

        // The enforcing phase: the reachable steps must now be denied with
        // `EPERM`, and their forks still recorded. The self-signal
        // exemption is the exception by design: still allowed.
        for (step, arg) in &reachable {
            let pid = self.run_worker(&selftest_cgroup, step, arg.as_str(), true)?;
            self.check_fork_event(pid, step)?;
        }
        for step in &always_allowed {
            let pid = self.run_worker(&selftest_cgroup, step, "", false)?;
            self.check_fork_event(pid, step)?;
        }

        // The per-operation rule steps under enforcement: write and exec
        // under the seeded prefix must now be denied with `EPERM`, and
        // read must stay allowed — the "individually" in the feature:
        // blocking two classes under a prefix cannot cost the third its
        // openings.
        if let Some(seeded) = &seeded {
            let pid = self
                .run_worker(&selftest_cgroup, STEP_RULES_READ, &seeded.data_arg(), false)?;
            self.check_fork_event(pid, STEP_RULES_READ)?;
            let pid = self
                .run_worker(&selftest_cgroup, STEP_RULES_WRITE, &seeded.data_arg(), true)?;
            self.check_fork_event(pid, STEP_RULES_WRITE)?;
            let pid = self
                .run_worker(&selftest_cgroup, STEP_RULES_EXEC, &seeded.exec_arg(), true)?;
            self.check_fork_event(pid, STEP_RULES_EXEC)?;
        }

        // The shadowed steps (see the module docs): denied by *either*
        // layer under wabbit-initrd's babysit, by guard standalone. The
        // module-tree write step needs a real file to open.
        if let Some(modules_file) = find_module_tree_file() {
            let pid = self.run_worker(&selftest_cgroup, STEP_MODULES_WRITE, &modules_file, true)?;
            self.check_fork_event(pid, STEP_MODULES_WRITE)?;
        } else {
            debug!("no module tree found: skipping the module-tree write step");
        }
        let pid = self.run_worker(&selftest_cgroup, STEP_BPF, "", true)?;
        self.check_fork_event(pid, STEP_BPF)?;
        let pid = self.run_worker(&selftest_cgroup, STEP_KMOD, "", true)?;
        self.check_fork_event(pid, STEP_KMOD)?;
        let pid = self.run_worker(&selftest_cgroup, STEP_MOUNT, &self.cgroup_string(), true)?;
        self.check_fork_event(pid, STEP_MOUNT)?;

        // Nothing may have loaded a module while enforcing: the gates deny
        // every untrusted load, and modprobe's request_module spawns run
        // outside every trust map.
        let module_loads: HashMap<_, u32, u8> = self
            .ebpf
            .map_mut("MODULE_LOADS")
            .context("finding MODULE_LOADS")?
            .try_into()
            .context("opening MODULE_LOADS")?;
        let loaders: Vec<u32> = module_loads
            .keys()
            .collect::<Result<Vec<u32>, MapError>>()
            .context("reading MODULE_LOADS")?;
        if !loaders.is_empty() {
            bail!(
                "modules were loaded during the enforcing self-test by PIDs {loaders:?}: \
                 the module-load gates did not hold"
            );
        }

        if let Some(seeded) = seeded {
            self.release_path_rule_steps(&seeded);
        }
        let _ = fs::remove_dir(&selftest_cgroup);
        info!("guard self-tests passed; enforcing");
        Ok(())
    }

    /// The embedded object, mutably — for the eBPF logger's sink.
    pub fn ebpf_mut(&mut self) -> &mut aya::Ebpf {
        &mut self.ebpf
    }

    /// Flip [`ENFORCING`]. `map_mut` borrows, so the flip is repeatable —
    /// the future policy-loading step flips it again.
    fn set_enforcing(&mut self, value: u32) -> Result<()> {
        let mut enforcing: Array<_, u32> = self
            .ebpf
            .map_mut("ENFORCING")
            .context("finding ENFORCING")?
            .try_into()
            .context("opening ENFORCING")?;
        enforcing.set(0, value, 0).context("writing ENFORCING")
    }

    /// The sacrificial cgroup the self-test workers run in: a child of
    /// wabbit's own, so a fresh kernfs id (outside wabbit's trust) without
    /// polluting the root of the hierarchy.
    fn create_selftest_cgroup(&self) -> Result<PathBuf> {
        let dir = self.cgroup.join("selftest");
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", dir.display()));
            }
        }
        Ok(dir)
    }

    fn cgroup_string(&self) -> String {
        self.cgroup.display().to_string()
    }

    /// Seed the self-test's per-operation path-rule steps: one temp
    /// prefix holding two targets, one rule on it denying **write and
    /// exec only** (read left to the default), and an `Authorization`
    /// entry for the selftest cgroup so its rules are consulted at all —
    /// action-less and default-allow, exactly what the cgroup already
    /// behaves like today, where no entry means no rules either.
    ///
    /// Priors are captured so the release can restore byte-for-byte what
    /// was there: a policy that names this cgroup (none does today) must
    /// not lose its entry to a self-test. `None` (warned, never failed)
    /// when the environment cannot host the steps — the same skip-shaped
    /// honesty as `find_module_tree_file`'s absent module tree.
    fn seed_path_rule_steps(&mut self, selftest_cgroup: &Path) -> Result<Option<RuleSeed>> {
        use wabbit_common::authorization::{
            AUTH_VERSION, Authorization, PATH_RULE_EXEC_DENY, PATH_RULE_WRITE_DENY, PATH_WALK_CAP,
            PathRuleKey,
        };

        let dir = env::temp_dir().join(format!("{NAME}-selftest-rules"));
        let Some(prefix) = dir.to_str().map(str::to_owned) else {
            warn!("the path-rule self-test prefix is not UTF-8: skipping the path-rule steps");
            return Ok(None);
        };
        if prefix.len() > PATH_WALK_CAP {
            warn!(
                "the path-rule self-test prefix {prefix:?} exceeds the {PATH_WALK_CAP}-byte walk \
                 cap: skipping the path-rule steps"
            );
            return Ok(None);
        }
        let cgroup_id = fs::metadata(selftest_cgroup)
            .with_context(|| {
                format!("stat(2) on the selftest cgroup {}", selftest_cgroup.display())
            })?
            .ino();
        if let Err(error) = fs::create_dir_all(&dir) {
            warn!(
                "could not create the path-rule self-test prefix {}: {error}; \
                 skipping the path-rule steps",
                dir.display()
            );
            return Ok(None);
        }
        // The data file: one target for the read and write steps, opened
        // one way per step so the two operation classes prove
        // independently on the same path.
        let data = dir.join("data");
        if let Err(error) = fs::write(&data, b"wabbit self-test path-rule data\n") {
            warn!(
                "could not create the path-rule self-test data file {}: {error}; \
                 skipping the path-rule steps",
                data.display()
            );
            return Ok(None);
        }
        // The exec target: a copy of this binary, so an *allowed* exec is
        // a real, complete execve (not a noexec decoy that would die at
        // the kernel's own `path_noexec` check before the gate ever saw
        // it), and the re-exec reports the verdict through the confirm
        // flag.
        let exec_target = dir.join("exec-target");
        let own_image = match fs::read("/proc/self/exe") {
            Ok(image) => image,
            Err(error) => {
                warn!(
                    "could not read /proc/self/exe for the path-rule self-test: {error}; \
                     skipping the path-rule steps"
                );
                return Ok(None);
            }
        };
        if let Err(error) = fs::write(&exec_target, own_image) {
            warn!(
                "could not create the path-rule self-test exec target {}: {error}; \
                 skipping the path-rule steps",
                exec_target.display()
            );
            return Ok(None);
        }
        if let Err(error) =
            fs::set_permissions(&exec_target, fs::Permissions::from_mode(0o755))
        {
            warn!(
                "could not make the path-rule self-test exec target executable: {error}; \
                 skipping the path-rule steps"
            );
            return Ok(None);
        }

        let rule_key = PathRuleKey {
            cgroup_id,
            path_hash: path_hash(prefix.as_bytes()),
        };
        let prior_authorization = {
            let mut authorizations: HashMap<_, CgroupKey, Authorization> = self
                .ebpf
                .map_mut("AUTHORIZATIONS")
                .context("finding AUTHORIZATIONS")?
                .try_into()
                .context("opening AUTHORIZATIONS")?;
            let prior = authorizations.get(&CgroupKey { cgroup_id }, 0).ok();
            authorizations
                .insert(
                    CgroupKey { cgroup_id },
                    Authorization {
                        version: AUTH_VERSION,
                        size: size_of::<Authorization>() as u32,
                        generation: 0,
                        action_mask: 0,
                        namespace_id: 0,
                        // flags 0: default-allow, what a cgroup with no
                        // entry already is — the entry exists only so
                        // the rule walk consults its rules.
                        flags: 0,
                    },
                    0,
                )
                .context("seeding the selftest cgroup's authorization")?;
            prior
        };
        let prior_rule = {
            let mut path_rules: HashMap<_, PathRuleKey, u32> = self
                .ebpf
                .map_mut("PATH_RULES")
                .context("finding PATH_RULES")?
                .try_into()
                .context("opening PATH_RULES")?;
            let prior = path_rules.get(&rule_key, 0).ok();
            // Write and exec denied, read unspecified — the default
            // (allow, per the flags above) decides it: the exact shape
            // the per-operation verdicts exist to express.
            path_rules
                .insert(rule_key, PATH_RULE_WRITE_DENY | PATH_RULE_EXEC_DENY, 0)
                .context("seeding the selftest path rule")?;
            prior
        };

        debug!("seeded the path-rule self-test under {prefix:?}");
        Ok(Some(RuleSeed {
            cgroup_id,
            rule_key,
            prior_rule,
            prior_authorization,
            data,
            exec_target,
            dir,
        }))
    }

    /// Undo one seed: restore the prior map entries (or remove what the
    /// seed added) and, best-effort, the prefix directory. Never fails
    /// the caller — the steps' verdicts are already decided, and a
    /// leftover entry keyed by the selftest cgroup's id is inert.
    fn release_path_rule_steps(&mut self, seeded: &RuleSeed) {
        use wabbit_common::authorization::Authorization;

        let rule_restore = self
            .ebpf
            .map_mut("PATH_RULES")
            .context("finding PATH_RULES")
            .and_then(|map| {
                let mut rules: HashMap<_, wabbit_common::authorization::PathRuleKey, u32> = map
                    .try_into()
                    .context("opening PATH_RULES")?;
                Ok(match seeded.prior_rule {
                    Some(prior) => rules.insert(seeded.rule_key, prior, 0),
                    None => rules.remove(&seeded.rule_key),
                })
            });
        match rule_restore {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!("releasing the selftest path rule: {error:#}"),
            Err(error) => warn!("releasing the selftest path rule: {error:#}"),
        }

        let auth_key = CgroupKey {
            cgroup_id: seeded.cgroup_id,
        };
        let auth_restore = self
            .ebpf
            .map_mut("AUTHORIZATIONS")
            .context("finding AUTHORIZATIONS")
            .and_then(|map| {
                let mut authorizations: HashMap<_, CgroupKey, Authorization> = map
                    .try_into()
                    .context("opening AUTHORIZATIONS")?;
                Ok(match seeded.prior_authorization {
                    Some(prior) => authorizations.insert(auth_key, prior, 0),
                    None => authorizations.remove(&auth_key),
                })
            });
        match auth_restore {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!("releasing the selftest authorization: {error:#}"),
            Err(error) => warn!("releasing the selftest authorization: {error:#}"),
        }

        if let Err(error) = fs::remove_dir_all(&seeded.dir)
            && seeded.dir.exists()
        {
            warn!(
                "could not remove the path-rule self-test prefix {}: {error}",
                seeded.dir.display()
            );
        }
    }

    /// Spawn one worker in the sacrificial cgroup and assert its verdict.
    ///
    /// `expect_blocked` selects the phase's expectation: the observing
    /// phase (`false`) requires the syscall went through (these are the
    /// *reachable* steps, hooks bnuuy does not wall — see the module
    /// docs); the enforcing phase (`true`) requires the `EPERM` denial.
    fn run_worker(
        &self,
        selftest_cgroup: &Path,
        step: &str,
        arg: &str,
        expect_blocked: bool,
    ) -> Result<u32> {
        // `/proc/self/exe` resolves the inode, so re-exec works from every
        // launch mode — a memfd-launched wabbit's `current_exe()` string is
        // `/memfd:<name> (deleted)` and cannot be exec'd as a path.
        let mut command = Command::new("/proc/self/exe");
        command.arg(selftest_flag(step));
        if !arg.is_empty() {
            command.arg(arg);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning the {step} self-test worker"))?;
        let pid = child.id();
        // The worker blocks on stdin until this write: the cgroup migration
        // below always lands before the worker's syscall.
        fs::write(selftest_cgroup.join("cgroup.procs"), format!("{pid}\n"))
            .with_context(|| format!("moving worker {pid} into the selftest cgroup"))?;
        {
            let mut stdin = child
                .stdin
                .take()
                .context("the worker's stdin pipe was already closed")?;
            stdin
                .write_all(b"o")
                .with_context(|| format!("signaling worker {pid} to proceed"))?;
        }
        let status = child
            .wait()
            .with_context(|| format!("waiting for the {step} worker"))?;
        let code = match status.code() {
            Some(code) => code,
            None => bail!("the {step} worker terminated by signal: {status}"),
        };
        let what = format!("the {step} step");
        match (code, expect_blocked) {
            (0, true) | (1, false) => debug!("{what}: verdict {code} as expected"),
            (1, true) => bail!("{what}: FAILED, the gate did not deny"),
            (0, false) => bail!("{what}: FAILED, denied in the observing phase"),
            (3, _) => bail!("{what}: the worker could not set the test up"),
            (4, _) => bail!("{what}: inconclusive (missing capability)"),
            (other, _) => bail!("{what}: unexpected worker exit {other}"),
        }
        Ok(pid)
    }

    /// Assert the fork watcher recorded the worker's fork, and clean the
    /// entry so later rounds see a fresh map.
    ///
    /// `map_mut` borrows the map without removing it (`take_map` would
    /// consume it on the first call and every later check would fail
    /// "finding FORK_EVENTS" — the exact failure the first lab run of
    /// this self-test caught).
    fn check_fork_event(&mut self, pid: u32, step: &str) -> Result<()> {
        let mut fork_events: HashMap<_, u32, u8> = self
            .ebpf
            .map_mut("FORK_EVENTS")
            .with_context(|| format!("finding FORK_EVENTS for the {step} worker"))?
            .try_into()
            .context("opening FORK_EVENTS")?;
        match fork_events.get(&pid, 0) {
            Ok(_) => {
                fork_events
                    .remove(&pid)
                    .with_context(|| format!("cleaning FORK_EVENTS entry {pid}"))?;
                Ok(())
            }
            Err(MapError::KeyNotFound) => {
                let mut seen: Vec<u32> = Vec::new();
                for key in fork_events.keys() {
                    match key {
                        Ok(key) if seen.len() < 16 => seen.push(key),
                        Ok(_) => break,
                        Err(_) => break,
                    }
                }
                bail!(
                    "the fork watcher did not record the {step} worker's fork \
                     (pid {pid}): the sched_process_fork tracepoint is not \
                     seeing forks; the map holds {seen:?}"
                );
            }
            Err(error) => Err(error).context("reading FORK_EVENTS"),
        }
    }

    /// Assert the observing phase traced a would-deny decision for every
    /// reachable hook.
    ///
    /// On failure this names *every* missing hook and dumps every
    /// `DECISIONS` key the run actually recorded: the first question a
    /// failed self-test must answer is whether a gate did not fire at
    /// all, or fired and traced a different decision than asserted (the
    /// dump distinguishes them — no key for the hook is "did not fire", a
    /// key with another code is "fired, decided otherwise").
    fn check_decisions(&mut self, phase: &str) -> Result<()> {
        let decisions: HashMap<_, u32, u32> = self
            .ebpf
            .map_mut("DECISIONS")
            .context("finding DECISIONS")?
            .try_into()
            .context("opening DECISIONS")?;
        let recorded: Vec<u32> = decisions
            .keys()
            .collect::<Result<Vec<u32>, MapError>>()
            .context("reading DECISIONS keys")?;
        let mut missing: Vec<u32> = Vec::new();
        // A bind gate switched off decides nothing; `socket_create` is
        // traced by the netfilter step whatever the raw-capture posture.
        let mut hooks = vec![
            HOOK_SB_MOUNT,
            HOOK_SOCKET_CREATE,
            HOOK_FILE_OPEN,
            HOOK_SETSOCKOPT,
            HOOK_TASK_KILL,
        ];
        if self.network.bind != BindPosture::Off {
            hooks.push(HOOK_BIND);
        }
        for hook in hooks {
            match decisions.get(&decision_key(hook, CODE_WOULD_DENY), 0) {
                Ok(_) => {}
                Err(MapError::KeyNotFound) => missing.push(hook),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("reading the DECISIONS key of hook {hook}"));
                }
            }
        }
        if !missing.is_empty() {
            let recorded = recorded
                .iter()
                .map(|key| format!("hook {} code {}", key >> 16, key & 0xffff))
                .collect::<Vec<_>>();
            bail!(
                "the {phase} phase traced no would-deny decision for hooks \
                 {missing:?} (hook ids): those gates did not fire. DECISIONS \
                 recorded: {}",
                recorded.join(", "),
            );
        }
        Ok(())
    }
}

// ------------------------------------------------------------- the steps

/// The self-test steps, as `--<name>-selftest-<step>` flags.
const STEP_MOUNT: &str = "mount";
const STEP_NETFILTER: &str = "netfilter";
const STEP_CGROUPFS_WRITE: &str = "cgroupfs-write";
const STEP_FIREWALL: &str = "firewall";
const STEP_BPF: &str = "bpf";
const STEP_KMOD: &str = "kmod";
const STEP_MODULES_WRITE: &str = "modules-write";
const STEP_RULES_READ: &str = "path-rules-read";
const STEP_RULES_WRITE: &str = "path-rules-write";
const STEP_RULES_EXEC: &str = "path-rules-exec";
const STEP_RAW_CAPTURE: &str = "raw-capture";
const STEP_BIND_NET: &str = "bind-net";
const STEP_BIND_EPHEMERAL: &str = "bind-ephemeral";
const STEP_SIGNAL: &str = "signal";
const STEP_SIGNAL_SELF: &str = "signal-self";
/// Not a step but a re-exec target: `worker_main` dispatches it before
/// anything else (it must not read stdin), and only a *successful*
/// execve of the rules-exec target can reach it — so its exit code is
/// the observing-phase verdict of the exec step.
const STEP_RULES_EXEC_CONFIRM: &str = "path-rules-exec-confirm";

fn selftest_flag(step: &str) -> String {
    format!("--{NAME}-selftest-{step}")
}

/// Dispatch a self-test worker if the command line asks for one.
///
/// `Some(exit_code)` means this process *is* a worker and has already
/// performed its one syscall; the caller must exit before doing anything
/// else. `None` means this is the real wabbit.
pub fn worker_main() -> Option<i32> {
    let mut args = env::args().skip(1);
    let flag = args.next()?;
    // The exec-confirm re-exec: reached only through a successful
    // execve of the rules-exec target — the observing-phase verdict of
    // the exec step. It must not read stdin: the parent's start byte was
    // consumed by the first image, and the pipe sits at EOF. Its exit is
    // the verdict: the exec went through.
    if flag == selftest_flag(STEP_RULES_EXEC_CONFIRM) {
        return Some(verdict::ALLOWED);
    }
    let Some(step) = flag.strip_prefix(&format!("--{NAME}-selftest-")) else {
        return None;
    };
    // A worker never initializes the logger, mounts anything, or touches
    // the maps: it reads one byte (the parent's migration-done signal),
    // performs one syscall, and reports by exit code.
    if std::io::stdin().read_exact(&mut [0u8; 1]).is_err() {
        eprintln!("{NAME} self-test worker {step}: could not read the start byte");
        return Some(3);
    }
    let arg = args.next();
    match step {
        STEP_MOUNT => Some(worker_step_mount(arg.as_deref())),
        STEP_NETFILTER => Some(worker_step_netfilter()),
        STEP_CGROUPFS_WRITE => Some(worker_step_cgroupfs_write(arg.as_deref())),
        STEP_FIREWALL => Some(worker_step_firewall()),
        STEP_BPF => Some(worker_step_bpf()),
        STEP_KMOD => Some(worker_step_kmod()),
        STEP_MODULES_WRITE => Some(worker_step_modules_write(arg.as_deref())),
        STEP_RULES_READ => Some(worker_step_rules_read(arg.as_deref())),
        STEP_RULES_WRITE => Some(worker_step_rules_write(arg.as_deref())),
        STEP_RULES_EXEC => Some(worker_step_rules_exec(arg.as_deref())),
        STEP_RAW_CAPTURE => Some(worker_step_raw_capture()),
        STEP_BIND_NET => Some(worker_step_bind(SELFTEST_BIND_PORT)),
        STEP_BIND_EPHEMERAL => Some(worker_step_bind(0)),
        STEP_SIGNAL => Some(worker_step_signal()),
        STEP_SIGNAL_SELF => Some(worker_step_signal_self()),
        other => {
            eprintln!("{NAME} self-test worker: unknown step {other}");
            Some(3)
        }
    }
}

/// A worker's exit-code verdict.
mod verdict {
    /// The syscall was denied with `EPERM`.
    pub const BLOCKED: i32 = 0;
    /// The syscall went through (or failed with another errno).
    pub const ALLOWED: i32 = 1;
    /// The worker could not set the test up.
    pub const SETUP_FAILED: i32 = 3;
    /// Inconclusive (missing capability).
    pub const INCONCLUSIVE: i32 = 4;
}

/// `EPERM`, as every gate denies.
const EPERM_ERRNO: i32 = libc::EPERM;

/// Capability bits, from `uapi/linux/capability.h`.
const CAP_SYS_MODULE: u32 = 16;
const CAP_SYS_ADMIN: u32 = 21;

/// The first `bpf(2)` command (`BPF_MAP_CREATE`), the second member of
/// `enum bpf_cmd`.
const BPF_MAP_CREATE: libc::c_long = 0;

/// The size the kernel accepts for `union bpf_attr`.
const BPF_ATTR_SIZE: usize = 128;

/// `AF_NETLINK` and `NETLINK_NETFILTER`, from `uapi/linux/netlink.h`.
const AF_NETLINK: libc::c_int = 16;
const NETLINK_NETFILTER: libc::c_int = 12;

/// `SOL_IP` (`IPPROTO_IP`, 0) and `IPT_SO_SET_REPLACE` (`IPT_BASE_CTL`,
/// 64), the legacy firewall `setsockopt` shape.
const SOL_IP: libc::c_int = 0;
const IPT_SO_SET_REPLACE: libc::c_int = 64;

/// Report `errno` as a verdict: `EPERM` means a gate denied us, anything
/// else means the syscall proceeded into the kernel's own checking.
#[inline]
fn errno_verdict(what: &str) -> i32 {
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == EPERM_ERRNO {
        verdict::BLOCKED
    } else {
        eprintln!("{NAME} self-test {what}: errno {errno}");
        verdict::ALLOWED
    }
}

/// `mount(2)` over a protected cgroupfs path must be denied.
///
/// The filesystem type is deliberately garbage: if the LSM gate lets the
/// call through (the observing phase), the mount fails later in the
/// kernel's own filesystem lookup with `ENODEV` — no mount ever happens —
/// so the step is side-effect-free in both phases. Without `CAP_SYS_ADMIN`
/// the capability check denies with `EPERM` *before* the LSM runs, making
/// the verdict meaningless.
///
/// The target must be NUL-terminated for the syscall (`CString`): a bare
/// `&str::as_ptr()` hands the kernel an unterminated pointer, the path
/// walk resolves heap garbage instead of the cgroup path, and the gate
/// never sees the path it is being tested against — the exact bug the
/// first lab run caught as "hook 4: the gate did not fire".
fn worker_step_mount(target: Option<&str>) -> i32 {
    let Some(target) = target else {
        eprintln!("{NAME} self-test mount: no target given");
        return verdict::SETUP_FAILED;
    };
    if !has_capability(CAP_SYS_ADMIN) {
        eprintln!("{NAME} self-test mount: no CAP_SYS_ADMIN, an EPERM would be ambiguous");
        return verdict::INCONCLUSIVE;
    }
    let Ok(target) = std::ffi::CString::new(target) else {
        eprintln!("{NAME} self-test mount: the target contains a NUL");
        return verdict::SETUP_FAILED;
    };
    let Ok(fstype) = std::ffi::CString::new("no-such-filesystem") else {
        unreachable!("the fstype contains no NUL")
    };
    let ret = unsafe {
        libc::mount(
            std::ptr::null(), // dev_name: the garbage fstype never needs one
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret >= 0 {
        eprintln!(
            "{NAME} self-test mount: mount() succeeded over {}",
            target.to_string_lossy()
        );
        return verdict::ALLOWED;
    }
    errno_verdict("mount")
}

/// `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` — the nftables
/// management channel — must be denied.
fn worker_step_netfilter() -> i32 {
    let fd = unsafe {
        libc::socket(
            AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        )
    };
    if fd >= 0 {
        eprintln!("{NAME} self-test netfilter: netfilter netlink socket created");
        unsafe { libc::close(fd) };
        return verdict::ALLOWED;
    }
    errno_verdict("netfilter socket")
}

/// A writable open under a protected cgroupfs path must be denied — the
/// `cgroup.procs` migration wall itself.
fn worker_step_cgroupfs_write(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("{NAME} self-test cgroupfs-write: no path given");
        return verdict::SETUP_FAILED;
    };
    let file = match fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("{NAME} self-test cgroupfs-write: {error}");
            return error
                .raw_os_error()
                .map(|errno| {
                    if errno == EPERM_ERRNO {
                        verdict::BLOCKED
                    } else {
                        verdict::SETUP_FAILED
                    }
                })
                .unwrap_or(verdict::SETUP_FAILED);
        }
    };
    drop(file);
    eprintln!("{NAME} self-test cgroupfs-write: writable open of {path} succeeded");
    verdict::ALLOWED
}

/// `setsockopt(SOL_IP, IPT_SO_SET_REPLACE, …)` — the legacy firewall rule
/// path — must be denied.
///
/// The option value is deliberately empty: if the gate lets the call
/// through, the kernel's own option handling rejects it (`ENOPROTOOPT`)
/// without touching any rule.
fn worker_step_firewall() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        eprintln!("{NAME} self-test firewall: could not open a UDP socket");
        return verdict::SETUP_FAILED;
    }
    let ret = unsafe { libc::setsockopt(fd, SOL_IP, IPT_SO_SET_REPLACE, std::ptr::null(), 0) };
    unsafe { libc::close(fd) };
    if ret >= 0 {
        eprintln!("{NAME} self-test firewall: IPT_SO_SET_REPLACE went through");
        return verdict::ALLOWED;
    }
    errno_verdict("firewall setsockopt")
}

/// `bpf(BPF_MAP_CREATE, …)` — an all-zero attr — must be denied. Allowed
/// through, the kernel rejects it with `EINVAL` of its own.
fn worker_step_bpf() -> i32 {
    let attr = [0u8; BPF_ATTR_SIZE];
    let ret = unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_CREATE, attr.as_ptr(), attr.len()) };
    if ret >= 0 {
        eprintln!("{NAME} self-test bpf: bpf() succeeded for an untrusted cgroup");
        return verdict::ALLOWED;
    }
    errno_verdict("bpf()")
}

/// `finit_module(2)` of a non-module image must be denied. The image is
/// this worker's own ELF: allowed through, the module loader rejects it
/// (`ENOEXEC`/`EINVAL`) without loading anything.
fn worker_step_kmod() -> i32 {
    if !has_capability(CAP_SYS_MODULE) {
        eprintln!("{NAME} self-test kmod: no CAP_SYS_MODULE, an EPERM would be ambiguous");
        return verdict::INCONCLUSIVE;
    }
    let file = match fs::File::open("/proc/self/exe") {
        Ok(file) => file,
        Err(error) => {
            eprintln!("{NAME} self-test kmod: {error}");
            return verdict::SETUP_FAILED;
        }
    };
    let params = b"\0";
    let ret =
        unsafe { libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0) };
    if ret >= 0 {
        eprintln!("{NAME} self-test kmod: finit_module() loaded a module");
        return verdict::ALLOWED;
    }
    errno_verdict("finit_module()")
}

/// A writable open under a module tree must be denied.
fn worker_step_modules_write(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("{NAME} self-test modules-write: no path given");
        return verdict::SETUP_FAILED;
    };
    match fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => {
            drop(file);
            eprintln!("{NAME} self-test modules-write: writable open of {path} succeeded");
            verdict::ALLOWED
        }
        Err(error) => match error.raw_os_error() {
            Some(errno) if errno == EPERM_ERRNO => verdict::BLOCKED,
            Some(_) => verdict::ALLOWED,
            None => verdict::SETUP_FAILED,
        },
    }
}

// ------------------------------------------------------- path-rule steps

/// A read-only open under the rules prefix. The seeded rule denies only
/// write and exec, so this must go through in *both* phases — the
/// "individually" in the per-operation verdicts: blocking writes and
/// exec under a prefix while its reads stay open.
fn worker_step_rules_read(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("{NAME} self-test path-rules-read: no path given");
        return verdict::SETUP_FAILED;
    };
    match fs::File::open(path) {
        Ok(_) => {
            eprintln!("{NAME} self-test path-rules-read: read open of {path} succeeded");
            verdict::ALLOWED
        }
        Err(error) => match error.raw_os_error() {
            Some(errno) if errno == EPERM_ERRNO => verdict::BLOCKED,
            Some(_) => {
                eprintln!("{NAME} self-test path-rules-read: errno {:?} (not EPERM)", error);
                verdict::ALLOWED
            }
            None => verdict::SETUP_FAILED,
        },
    }
}

/// A writable open under the rules prefix: the seeded rule denies
/// writes there, so this is the per-operation gate's write verdict.
fn worker_step_rules_write(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("{NAME} self-test path-rules-write: no path given");
        return verdict::SETUP_FAILED;
    };
    match fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => {
            drop(file);
            eprintln!("{NAME} self-test path-rules-write: writable open of {path} succeeded");
            verdict::ALLOWED
        }
        Err(error) => match error.raw_os_error() {
            Some(errno) if errno == EPERM_ERRNO => verdict::BLOCKED,
            Some(_) => {
                eprintln!("{NAME} self-test path-rules-write: errno {:?} (not EPERM)", error);
                verdict::ALLOWED
            }
            None => verdict::SETUP_FAILED,
        },
    }
}

/// `execve(2)` of a copy of this binary under the rules prefix: the
/// seeded rule denies exec there, so this is the per-operation gate's
/// exec verdict — the kernel's `__FMODE_EXEC` marker in `f_flags`, not
/// writability, not readability.
///
/// Allowed through (the observing phase), the exec succeeds and the
/// image re-executes carrying [`STEP_RULES_EXEC_CONFIRM`], whose
/// dispatch in [`worker_main`] exits the `ALLOWED` verdict without
/// touching stdin (the parent's start byte was consumed by this image,
/// and the pipe sits at EOF). Denied (the enforcing phase), the
/// syscall fails before any image change and the errno is the verdict.
fn worker_step_rules_exec(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("{NAME} self-test path-rules-exec: no path given");
        return verdict::SETUP_FAILED;
    };
    let Ok(target) = std::ffi::CString::new(path) else {
        eprintln!("{NAME} self-test path-rules-exec: the target contains a NUL");
        return verdict::SETUP_FAILED;
    };
    let argv0 = target.clone();
    let Ok(confirm) = std::ffi::CString::new(selftest_flag(STEP_RULES_EXEC_CONFIRM)) else {
        unreachable!("the self-test flag contains no NUL");
    };
    // NUL-terminated `argv` (and an empty `envp` — the confirm step
    // needs nothing), each buffer outliving the call.
    let argv = [argv0.as_ptr(), confirm.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<std::ffi::c_char>()];
    let ret = unsafe { libc::execve(target.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    // `execve` returns only on failure; on success this image is gone.
    debug_assert!(ret < 0, "execve returned on success");
    errno_verdict("path-rules execve")
}

// ------------------------------------------------- the sketch's action bits

/// `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` — tcpdump's own channel, the
/// capture surface the raw-capture gate denies.
///
/// Allowed through (the observing phase), the socket is closed at once —
/// no promiscuous mode, no ring buffers, no footprint. On a modular
/// kernel without the module loaded, the kernel's own request_module may
/// fail the socket with a non-`EPERM` errno instead (the module gates
/// hold); that is still `ALLOWED` per the verdict protocol — the LSM
/// verdict, not the socket, is what the phase asserts, and the
/// observing trace is the proof.
fn worker_step_raw_capture() -> i32 {
    // The protocol is `ETH_P_ALL` (0x0003) in network byte order, the
    // spelling tcpdump itself uses.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0x0300) };
    if fd >= 0 {
        eprintln!("{NAME} self-test raw-capture: packet socket created");
        unsafe { libc::close(fd) };
        return verdict::ALLOWED;
    }
    errno_verdict("raw capture socket")
}

/// The loopback port the `bind-net` step claims. Any specific port proves
/// the gate (the LSM hook runs before the kernel's own port checks, so a
/// port in use reads `EADDRINUSE` — allowed — and still traces); the
/// socket never listens, so even a successful bind has no footprint.
const SELFTEST_BIND_PORT: u16 = 47_811;

/// `bind(2)` of an `AF_INET` stream socket on loopback `port`: the
/// network-endpoint acquisition the bind gate's net bit governs — a
/// specific port (`bind-net`, gated unless the posture is `off`) or port
/// 0 (`bind-ephemeral`, gated only under `all`). The socket is setup — a
/// plain stream socket no gate touches — and the bind is the tested
/// syscall.
fn worker_step_bind(port: u16) -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        eprintln!("{NAME} self-test bind: could not open a stream socket");
        return verdict::SETUP_FAILED;
    }
    // Loopback, and the socket is closed at once: the closest a bind
    // gets to no footprint at all.
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_LOOPBACK,
        },
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        libc::bind(
            fd,
            &address as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };
    if ret >= 0 {
        eprintln!("{NAME} self-test bind: bound loopback port {port}");
        return verdict::ALLOWED;
    }
    errno_verdict("bind()")
}

/// `kill(getppid(), 0)` — a signal *permission probe* at the parent,
/// which is wabbit itself. Signal 0 performs the whole permission walk —
/// the `task_kill` LSM hook included — without delivering anything, so
/// the step is side-effect-free in both phases: observing passes,
/// enforcing is denied before anything is sent.
fn worker_step_signal() -> i32 {
    let ret = unsafe { libc::kill(libc::getppid(), 0) };
    if ret >= 0 {
        eprintln!("{NAME} self-test signal: kill(getppid(), 0) went through");
        return verdict::ALLOWED;
    }
    errno_verdict("signal kill()")
}

/// `kill(getpid(), 0)` — the signal gate's self-exemption, asserted in
/// both phases: the flip must never cost a process `raise(3)`.
fn worker_step_signal_self() -> i32 {
    let ret = unsafe { libc::kill(libc::getpid(), 0) };
    if ret >= 0 {
        return verdict::ALLOWED;
    }
    errno_verdict("signal-self kill()")
}

// -------------------------------------------------------------- helpers

/// wabbit's own cgroup: the v2 entry of `/proc/self/cgroup` under
/// [`CGROUPFS_ROOT`], with its kernfs id from `stat(2)` — the same id
/// `bpf_get_current_cgroup_id` reports for a task inside it.
fn self_cgroup() -> Result<(PathBuf, u64)> {
    let content = fs::read_to_string("/proc/self/cgroup").context("reading /proc/self/cgroup")?;
    let relative = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .with_context(|| {
            format!("no cgroup v2 entry in /proc/self/cgroup: {NAME} needs the unified hierarchy")
        })?
        .trim();
    let dir = Path::new(CGROUPFS_ROOT).join(relative.trim_start_matches('/'));
    let id = fs::metadata(&dir)
        .with_context(|| format!("stat(2) on the cgroup directory {}", dir.display()))?
        .ino();
    Ok((dir, id))
}

/// Trust wabbit itself: its PID, its cgroup, and its cgroup's path —
/// **before the first program attaches**, because the gates would
/// otherwise deny the `bpf(2)` calls that attach them.
fn trust_self(ebpf: &mut aya::Ebpf, cgroup: &Path, cgroup_id: u64) -> Result<()> {
    let mut trusted_pids: HashMap<_, u32, u32> = ebpf
        .map_mut("TRUSTED_PIDS")
        .context("finding TRUSTED_PIDS")?
        .try_into()
        .context("opening TRUSTED_PIDS")?;
    trusted_pids
        .insert(std::process::id(), 1, 0)
        .context("trusting this PID")?;

    let mut trusted_cgroups: HashMap<_, CgroupKey, u32> = ebpf
        .map_mut("TRUSTED_CGROUPS")
        .context("finding TRUSTED_CGROUPS")?
        .try_into()
        .context("opening TRUSTED_CGROUPS")?;
    let key = CgroupKey { cgroup_id };
    trusted_cgroups
        .insert(key, 1, 0)
        .context("trusting this cgroup")?;

    // The cgroup's path is protected: everything below it (cgroup.procs,
    // cgroup.freeze, cgroup.kill) is walled off for everyone outside it —
    // the migration wall the whole class model leans on.
    let mut protected: HashMap<_, u64, u32> = ebpf
        .map_mut("PROTECTED_PATHS")
        .context("finding PROTECTED_PATHS")?
        .try_into()
        .context("opening PROTECTED_PATHS")?;
    let canonical = cgroup.display().to_string();
    protected
        .insert(path_hash(canonical.as_bytes()), 1, 0)
        .with_context(|| format!("protecting the cgroup path {canonical}"))?;
    Ok(())
}

/// Write the network gates' reach (the policy's `network` section, or
/// the strictest posture without one) into `NET_POSTURE`.
fn populate_net_posture(ebpf: &mut aya::Ebpf, network: &NetworkConfig) -> Result<()> {
    use wabbit_common::authorization::{NET_POSTURE_BIND, NET_POSTURE_RAW_CAPTURE};

    let mut posture: Array<_, u32> = ebpf
        .map_mut("NET_POSTURE")
        .context("finding NET_POSTURE")?
        .try_into()
        .context("opening NET_POSTURE")?;
    posture
        .set(NET_POSTURE_BIND, network.bind.map_value(), 0)
        .context("writing the bind posture")?;
    posture
        .set(NET_POSTURE_RAW_CAPTURE, network.raw_capture.map_value(), 0)
        .context("writing the raw-capture posture")?;
    info!(
        "network gates: bind {:?}, raw capture {:?}",
        network.bind, network.raw_capture
    );
    Ok(())
}

/// Populate the authorization maps from the policy's `authorization`
/// section: the diagram's "create maps based on configuration".
///
/// Naming is by path, resolution is at load: a cgroup's kernfs id is
/// runtime state (`stat(2)`'s `st_ino` — the same id
/// `bpf_get_current_cgroup_id` reports), so the policy carries the
/// canonical cgroupfs path and this resolves it. Path-rule prefixes are
/// hashed with the shared `path_hash`, the same key convention the eBPF
/// walk incrementally maintains.
///
/// **Missing authorized cgroups are created, not skipped**: the policy is
/// signed, kernfs carries no symlinks, and an empty cgroup directory is
/// inert — and the entry naming a cgroup that does not exist *yet*
/// (the compiled class directories under wabbit's own subtree, and the
/// boot-time grants for cgroups systemd has not created when the guard
/// loads: `init.scope`, unit cgroups) could never resolve otherwise.
/// systemd reuses existing directories, so the kernfs node — the id the
/// maps key on — is the very one its processes land in.
///
/// **Failure asymmetry** (the documented contract): a missing or
/// unresolvable entry warns and skips — never aborts the guard load.
/// The maps' empty state is deny-by-default for every untrusted cgroup,
/// so enforcement-with-no-authorizations is safe; no-enforcement-because-
/// the-policy-file-missed-an-entry would not be. A section that fails
/// validation is a broken generator (the CLI validates at build), so it
/// warns and skips whole.
fn populate_authorizations(ebpf: &mut aya::Ebpf, policy: &Policy, own_cgroup: &Path) -> Result<()> {
    use wabbit_common::authorization::{AUTH_VERSION, Authorization, PATH_WALK_CAP, PathRuleKey};
    use wabbit_policy::authorization::AuthorizationEntry;

    let Some(config) = &policy.authorization else {
        debug!("the policy carries no authorization section");
        return Ok(());
    };
    if let Err(error) = config.validate() {
        warn!(
            "the policy's authorization section is invalid ({error}); \
             skipping it — an invalid signed section is a generator bug"
        );
        return Ok(());
    }

    // The migration wall keys on the path's hash, and the eBPF prefix
    // walk only hashes the first PATH_WALK_CAP bytes — a deeper own
    // cgroup could never be walled, so the whole subtree model degrades
    // and the operator must hear it now, not discover it in an audit.
    if own_cgroup
        .to_str()
        .is_some_and(|path| path.len() > PATH_WALK_CAP)
    {
        warn!(
            "wabbit's own cgroup {} is deeper than the {PATH_WALK_CAP}-byte eBPF walk cap; \
             the migration wall cannot cover paths this deep",
            own_cgroup.display()
        );
    }

    // Resolve first, map by map (aya's map handles each mutably borrow the
    // `Ebpf` object, so no two can be held at once): every cgroup path →
    // its kernfs id, skipped entries dropped here, then each map populated
    // from the resolved list.
    let mut resolved: Vec<(&AuthorizationEntry, u64)> = Vec::new();
    for entry in &config.entries {
        // Resolve the canonical cgroup path to the kernfs id the maps key
        // on. A path that does not resolve is a policy/target mismatch —
        // unless wabbit simply creates it: the policy is signed, kernfs
        // has no symlinks (the directories cannot escape), and an empty
        // cgroup directory is inert. This is load-bearing for entries
        // naming cgroups that do not exist *yet*: the guard loads in the
        // initramfs phase, before systemd creates init.scope or any unit
        // cgroup, and a boot-time grant (the `kmods` class that lets PID
        // 1 mount /boot/efi, the systemd-modules-load cgroup) must
        // resolve now anyway — systemd reuses existing directories, so
        // the kernfs node (and the id the maps key on) is the very one
        // its processes will land in.
        let cgroup = entry.cgroup.to_str().context("the cgroup path is UTF-8")?;
        if let Err(error) = fs::metadata(cgroup) {
            if let Err(error) = fs::create_dir_all(&entry.cgroup) {
                warn!(
                    "creating the authorized cgroup {} failed ({error}); \
                     skipping its entry — deny-by-default applies to it",
                    entry.cgroup.display()
                );
                continue;
            }
            info!("created the authorized cgroup {}", entry.cgroup.display());
        }
        let ino = fs::metadata(cgroup)
            .with_context(|| format!("stat(2) on the authorized cgroup {cgroup}"))?
            .ino();
        resolved.push((entry, ino));
    }

    {
        let mut authorizations: HashMap<_, CgroupKey, Authorization> = ebpf
            .map_mut("AUTHORIZATIONS")
            .context("finding AUTHORIZATIONS")?
            .try_into()
            .context("opening AUTHORIZATIONS")?;
        for (entry, ino) in &resolved {
            let key = CgroupKey { cgroup_id: *ino };
            let value = Authorization {
                version: AUTH_VERSION,
                size: size_of::<Authorization>() as u32,
                generation: 0,
                action_mask: entry.action_mask,
                namespace_id: 0,
                flags: entry.flags,
            };
            let cgroup = entry.cgroup.to_str().expect("validated UTF-8");
            authorizations
                .insert(key, value, 0)
                .with_context(|| format!("authorizing the cgroup {cgroup}"))?;
        }
    }

    {
        let mut protected: HashMap<_, u64, u32> = ebpf
            .map_mut("PROTECTED_PATHS")
            .context("finding PROTECTED_PATHS")?
            .try_into()
            .context("opening PROTECTED_PATHS")?;
        for (entry, _) in &resolved {
            // The migration wall: every cgroup holding an action bit is
            // protected (the walls around those bits are load-bearing),
            // `FLAG_PROTECT` extends the same wall to cgroups that hold
            // none, and `FLAG_UNPROTECTED` opts a cgroup out of the
            // implicit wall — the `init.scope` bootstrap, where PID 1
            // migrates itself in from outside every wall before any
            // authorization can apply to it. Everything below a walled
            // path — `cgroup.procs`, `cgroup.freeze`, `cgroup.kill` — is
            // denied to every cgroup outside it, so nothing can move a
            // process into a protected cgroup or kill it through the
            // cgroupfs.
            let cgroup = entry.cgroup.to_str().expect("validated UTF-8");
            if cgroup == wabbit_common::cgroup_types::CGROUPFS_ROOT {
                // Never the root: it is a prefix of every cgroupfs path,
                // so walling it would deny every `cgroup.procs` write on
                // the machine. The generator rejects a `protect` flag on
                // it; an entry there (the kernel's module autoloads run
                // in the root cgroup) carries bits but no wall.
                info!(
                    "the authorized cgroupfs root carries no wall: every cgroupfs path is under it"
                );
                continue;
            }
            if !entry_is_protected(entry.action_mask, entry.flags) {
                continue;
            }
            protected
                .insert(path_hash(cgroup.as_bytes()), 1, 0)
                .with_context(|| format!("protecting the cgroup path {cgroup}"))?;
        }
    }

    {
        let mut path_rules: HashMap<_, PathRuleKey, u32> = ebpf
            .map_mut("PATH_RULES")
            .context("finding PATH_RULES")?
            .try_into()
            .context("opening PATH_RULES")?;
        for (entry, ino) in &resolved {
            for rule in &entry.path_rules {
                // The generator validates the prefix (canonical, UTF-8,
                // within the walk cap) and the verdict (it decides
                // something); hashing the prefix and translating the
                // verdict here are total.
                let prefix = rule.prefix.to_str().context("the rule prefix is UTF-8")?;
                let rule_key = PathRuleKey {
                    cgroup_id: *ino,
                    path_hash: path_hash(prefix.as_bytes()),
                };
                path_rules
                    .insert(rule_key, rule.verdict_bits(), 0)
                    .with_context(|| format!("writing the {prefix:?} rule"))?;
            }
        }
    }

    let populated = resolved.len();
    info!(
        "populated {} authorized cgroup{} from the policy",
        populated,
        if populated == 1 { "" } else { "s" }
    );
    Ok(())
}

/// Populate the policy's `default` section: one more `AUTHORIZATIONS`
/// entry, and its rules, under the reserved [`DEFAULT_CGROUP_ID`] — what
/// the gates fall back to for a cgroup with no entry of its own.
///
/// The default names no cgroup, so there is nothing to resolve and
/// nothing to wall. The same failure asymmetry as the authorization
/// section: an invalid default (a generator bug) warns and is skipped,
/// leaving unlisted cgroups at the floor — no bits, no rules.
///
/// [`DEFAULT_CGROUP_ID`]: wabbit_common::authorization::DEFAULT_CGROUP_ID
fn populate_default(ebpf: &mut aya::Ebpf, policy: &Policy) -> Result<()> {
    use wabbit_common::authorization::{AUTH_VERSION, Authorization, DEFAULT_CGROUP_ID, PathRuleKey};

    let Some(default) = &policy.default else {
        debug!("the policy carries no default section: unlisted cgroups stay at the floor");
        return Ok(());
    };
    if let Err(error) = default.validate() {
        warn!(
            "the policy's default section is invalid ({error}); \
             skipping it — an invalid signed section is a generator bug"
        );
        return Ok(());
    }

    {
        let mut authorizations: HashMap<_, CgroupKey, Authorization> = ebpf
            .map_mut("AUTHORIZATIONS")
            .context("finding AUTHORIZATIONS")?
            .try_into()
            .context("opening AUTHORIZATIONS")?;
        // No flags: the default's rules are a deny-list by construction.
        let value = Authorization {
            version: AUTH_VERSION,
            size: size_of::<Authorization>() as u32,
            generation: 0,
            action_mask: default.action_mask,
            namespace_id: 0,
            flags: 0,
        };
        authorizations
            .insert(
                CgroupKey {
                    cgroup_id: DEFAULT_CGROUP_ID,
                },
                value,
                0,
            )
            .context("writing the default entry")?;
    }

    {
        let mut path_rules: HashMap<_, PathRuleKey, u32> = ebpf
            .map_mut("PATH_RULES")
            .context("finding PATH_RULES")?
            .try_into()
            .context("opening PATH_RULES")?;
        for rule in &default.path_rules {
            let prefix = rule.prefix.to_str().context("the rule prefix is UTF-8")?;
            let rule_key = PathRuleKey {
                cgroup_id: DEFAULT_CGROUP_ID,
                path_hash: path_hash(prefix.as_bytes()),
            };
            path_rules
                .insert(rule_key, rule.verdict_bits(), 0)
                .with_context(|| format!("writing the default {prefix:?} rule"))?;
        }
    }

    info!(
        "populated the default entry: actions {:#x}, {} path rule{}",
        default.action_mask,
        default.path_rules.len(),
        if default.path_rules.len() == 1 { "" } else { "s" }
    );
    Ok(())
}

/// Whether an entry's cgroup gets the migration wall: every bit-holding
/// cgroup is walled (the walls around those bits are load-bearing),
/// [`FLAG_PROTECT`] walls a bitless one, and [`FLAG_UNPROTECTED`] opts
/// out of the implicit wall — the signed policy's one accepted
/// exception, for the cgroup PID 1 must migrate itself into before
/// anything can authorize it.
fn entry_is_protected(action_mask: u64, flags: u64) -> bool {
    use wabbit_common::authorization::{FLAG_PROTECT, FLAG_UNPROTECTED};
    if flags & FLAG_PROTECT != 0 {
        return true;
    }
    action_mask != 0 && flags & FLAG_UNPROTECTED == 0
}

/// Attach one LSM gate, trying the candidate programs in order: the first
/// that loads is the one whose layout fits the running kernel (the
/// verifier validates the arguments against the kernel's BTF, so a
/// mismatched candidate fails loudly).
fn attach_lsm(ebpf: &mut aya::Ebpf, btf: &Btf, hook: &str, candidates: &[&str]) -> Result<()> {
    for candidate in candidates {
        let program: &mut Lsm = ebpf
            .program_mut(candidate)
            .with_context(|| format!("finding the {candidate} program"))?
            .try_into()
            .with_context(|| format!("opening the {candidate} program"))?;
        match program.load(hook, btf) {
            Ok(()) => {}
            Err(error) => {
                // Aya's error Display carries the kernel's whole verifier
                // log — megabytes for a complex program — and the console
                // is the one channel live while the world is frozen: the
                // WARN carries the headline reason only (the variant
                // mechanism makes the miss *expected* — one candidate is
                // designed to lose on every kernel), the full dump stays
                // at debug.
                let error_text = format!("{error}");
                let headline = error_text.lines().next().unwrap_or(&error_text);
                warn!("{candidate} does not fit this kernel: {headline}");
                debug!("full verifier output for {candidate}: {error_text}");
                continue;
            }
        }
        program
            .attach()
            .with_context(|| format!("attaching the {candidate} gate to {hook}"))?;
        info!("gate {hook} attached ({candidate})");
        return Ok(());
    }
    bail!("no program fits this kernel for the {hook} gate")
}

/// Attach the tracepoints, returning whether they are available.
///
/// The fork watcher's `child_pid` offset is parsed from the running
/// kernel's own format file — the ground truth the record layout cannot be
/// read from a load failure — and selects between the two compiled
/// variants (both attached when the parsed offset matches neither).
fn attach_tracepoints(ebpf: &mut aya::Ebpf) -> Result<bool> {
    if !ensure_tracefs() {
        return Ok(false);
    }

    let format_path = format!("{TRACING_ROOT}/events/sched/sched_process_fork/format");
    let format_file =
        fs::read_to_string(&format_path).with_context(|| format!("reading {format_path}"))?;
    let child_pid_offset = parse_child_pid_offset(&format_file)
        .context("parsing child_pid's offset from the format file")?;
    let variants: &[&str] = match child_pid_offset {
        CHILD_PID_VANILLA => &["fork_watcher_vanilla"],
        CHILD_PID_PREEMPT_LAZY => &["fork_watcher_preempt_lazy"],
        other => {
            warn!(
                "sched_process_fork child_pid sits at offset {other}, matching no \
                 compiled fork watcher; attaching both known layouts"
            );
            &["fork_watcher_vanilla", "fork_watcher_preempt_lazy"]
        }
    };

    for variant in variants {
        attach_tracepoint(ebpf, variant, "sched", "sched_process_fork")?;
    }
    attach_tracepoint(ebpf, "module_load_logger", "module", "module_load")?;
    // The load-path scaffold: proves the logger pipe reaches userspace.
    attach_tracepoint(ebpf, "sys_enter_trace", "raw_syscalls", "sys_enter")?;
    Ok(true)
}

fn attach_tracepoint(ebpf: &mut aya::Ebpf, name: &str, category: &str, event: &str) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("finding the {name} tracepoint"))?
        .try_into()
        .with_context(|| format!("opening the {name} tracepoint"))?;
    program.load().with_context(|| format!("loading {name}"))?;
    program
        .attach(category, event)
        .with_context(|| format!("attaching {name} to {category}/{event}"))?;
    Ok(())
}

/// `child_pid`'s offset within the `sched_process_fork` record, as the
/// running kernel's own format file spells it.
fn parse_child_pid_offset(format_file: &str) -> Option<usize> {
    format_file
        .lines()
        .find(|line| line.trim_start().starts_with("field:") && line.contains("child_pid"))
        .and_then(|line| line.split_once("offset:"))
        .and_then(|(_, offset)| offset.split(';').next())
        .and_then(|offset| offset.trim().parse().ok())
}

/// Make tracefs visible, mounting it if nothing is yet. A bare initrd has
/// it unmounted; wabbit-initrd mounts it for its own watchers, and the
/// mount travels with `/sys` across the switch.
fn ensure_tracefs() -> bool {
    if Path::new(TRACING_ROOT).join("events").is_dir() {
        return true;
    }
    let _ = fs::create_dir_all(TRACING_ROOT);
    match mount(
        "tracefs",
        TRACING_ROOT,
        "tracefs",
        MountFlags::empty(),
        None,
    ) {
        Ok(()) => {}
        Err(Errno::BUSY) => {}
        Err(error) => {
            debug!("mounting tracefs failed: {error}");
            return false;
        }
    }
    Path::new(TRACING_ROOT).join("events").is_dir()
}

/// Parse `CapEff` out of `/proc/self/status` and test one capability bit.
fn has_capability(cap: u32) -> bool {
    parse_cap_eff(&fs::read_to_string("/proc/self/status").unwrap_or_default())
        .is_some_and(|caps| caps & (1u128 << cap) != 0)
}

/// Extract the `CapEff:` line of a `/proc/self/status` body as a bitmask.
fn parse_cap_eff(status: &str) -> Option<u128> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u128::from_str_radix(hex.trim(), 16).ok())
}

/// The first regular file under a module tree, for the module-tree write
/// step. Checked at depth ≤ 2: the trees are `<root>/<kversion>/<file>`.
fn find_module_tree_file() -> Option<String> {
    for root in ["/usr/lib/modules", "/lib/modules"] {
        let root = Path::new(root);
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                return Some(path.display().to_string());
            }
            let Ok(files) = fs::read_dir(&path) else {
                continue;
            };
            for file in files.flatten() {
                if file.path().is_file() {
                    return Some(file.path().display().to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The format file verbatim from Ubuntu 24.04 (kernel 6.8): a vanilla
    /// `trace_entry` header, `child_pid` at 44.
    const VANILLA_FORMAT: &str = "\
name: sched_process_fork
format:
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;
";

    /// The format file verbatim from Rocky 9 (kernel 5.14.0-687.el9):
    /// RHEL's lazy-preempt header pad pushes `child_pid` to 48.
    const RHEL_LAZY_FORMAT: &str = "\
name: sched_process_fork
format:
\tfield:char child_comm[TASK_COMM_LEN];\toffset:32;\tsize:16;\tsigned:1;
\tfield:pid_t child_pid;\toffset:48;\tsize:4;\tsigned:1;
";

    #[test]
    fn child_pid_offsets_parse() {
        assert_eq!(parse_child_pid_offset(VANILLA_FORMAT), Some(44));
        assert_eq!(parse_child_pid_offset(RHEL_LAZY_FORMAT), Some(48));
        assert_eq!(parse_child_pid_offset("nothing here\n"), None);
    }

    #[test]
    fn capability_bits_parse() {
        let caps = parse_cap_eff("Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n")
            .expect("the CapEff line is present");
        assert!(caps & (1u128 << CAP_SYS_MODULE) != 0);
        assert!(caps & (1u128 << CAP_SYS_ADMIN) != 0);
        assert_eq!(parse_cap_eff("Uid:\t0\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tnot hex\n"), None);
    }

    #[test]
    fn the_migration_wall_rule() {
        use wabbit_common::authorization::{FLAG_PROTECT, FLAG_UNPROTECTED};
        // Bit-holders are walled by default — the walls around the bits
        // are load-bearing.
        assert!(entry_is_protected(1, 0));
        // A bitless cgroup is not, unless the policy says so.
        assert!(!entry_is_protected(0, 0));
        assert!(entry_is_protected(0, FLAG_PROTECT));
        // The bootstrap opt-out: bits, unwalled — the signed policy's
        // one accepted exception (PID 1's self-migration into
        // init.scope).
        assert!(!entry_is_protected(1, FLAG_UNPROTECTED));
        // And the explicit wall beats the opt-out (the generator rejects
        // the pair, but the rule is deterministic regardless).
        assert!(entry_is_protected(1, FLAG_PROTECT | FLAG_UNPROTECTED));
    }

    #[test]
    fn module_trees_walk_depth_two() {
        // The trees on the targets are `<root>/<kversion>/<file>`; the
        // search must not return the kversion directory itself.
        if let Some(path) = find_module_tree_file() {
            assert!(
                Path::new(&path).is_file(),
                "find_module_tree_file returned a non-file"
            );
        }
    }
}

// ------------------------------------------------------------------- the runs

/// The [`crate::runs::RunAuthorizer`] for the loaded guard: how the
/// IPC server's run commands get their ephemeral cgroups (see
/// `crate::runs` for the model). Implemented on the `Mutex` wrapper
/// the server holds, because concurrent commands each prepare a run
/// and the map writes need the guard's `&mut`.
impl crate::runs::RunAuthorizer for std::sync::Mutex<Guard> {
    fn own_cgroup(&self) -> String {
        self.lock()
            .expect("the guard lock is not poisoned")
            .cgroup_string()
    }

    fn prepare_run(
        &self,
        class: Option<&wabbit_policy::authorization::AuthorizationEntry>,
        command_id: u64,
    ) -> Result<crate::runs::PreparedRun> {
        self.lock()
            .expect("the guard lock is not poisoned")
            .prepare_run(class, command_id)
    }

    fn release_run(&self, run: &crate::runs::PreparedRun) {
        self.lock()
            .expect("the guard lock is not poisoned")
            .release_run(run)
    }
}

impl Guard {
    /// Create the ephemeral run cgroup (`crate::runs::create_run_cgroup`
    /// does the filesystem half) and authorize it with exactly the
    /// class's settings — keyed by its fresh kernfs id, so the class's
    /// compiled bits reach the gates for the run's processes and
    /// nothing else's. A classless run writes no authorization at all:
    /// it is an unlisted cgroup, so it gets the policy's default entry
    /// when there is one and the deny-by-default floor otherwise.
    fn prepare_run(
        &mut self,
        class: Option<&wabbit_policy::authorization::AuthorizationEntry>,
        command_id: u64,
    ) -> Result<crate::runs::PreparedRun> {
        use wabbit_common::authorization::{AUTH_VERSION, Authorization, PathRuleKey};

        let parent = match class {
            // The class's own cgroup — the convention entry the server
            // resolved from the active policy.
            Some(entry) => entry.cgroup.clone(),
            None => self.cgroup.clone(),
        };
        let (cgroup, cgroup_id) = crate::runs::create_run_cgroup(&parent, command_id)?;
        let mut run = crate::runs::PreparedRun {
            cgroup,
            cgroup_id,
            rule_prefix_hashes: Vec::new(),
        };

        if let Some(entry) = class {
            {
                let mut authorizations: HashMap<_, CgroupKey, Authorization> = self
                    .ebpf
                    .map_mut("AUTHORIZATIONS")
                    .context("finding AUTHORIZATIONS")?
                    .try_into()
                    .context("opening AUTHORIZATIONS")?;
                let value = Authorization {
                    version: AUTH_VERSION,
                    size: size_of::<Authorization>() as u32,
                    generation: 0,
                    action_mask: entry.action_mask,
                    namespace_id: 0,
                    flags: entry.flags,
                };
                authorizations
                    .insert(CgroupKey { cgroup_id }, value, 0)
                    .context("authorizing the run cgroup")?;
            }
            {
                let mut path_rules: HashMap<_, PathRuleKey, u32> = self
                    .ebpf
                    .map_mut("PATH_RULES")
                    .context("finding PATH_RULES")?
                    .try_into()
                    .context("opening PATH_RULES")?;
                for rule in &entry.path_rules {
                    let prefix = rule.prefix.to_str().context("the rule prefix is UTF-8")?;
                    let key = PathRuleKey {
                        cgroup_id,
                        path_hash: path_hash(prefix.as_bytes()),
                    };
                    run.rule_prefix_hashes.push(key.path_hash);
                    path_rules
                        .insert(key, rule.verdict_bits(), 0)
                        .with_context(|| format!("writing the run's {prefix:?} rule"))?;
                }
            }
        }

        // The migration wall needs no write of its own: the run cgroup
        // sits under wabbit's own cgroup and the class's entry, both of
        // whose hashes are already in PROTECTED_PATHS, and the eBPF
        // prefix walk covers everything below a protected path — so
        // nothing outside can move a process into the run, or freeze
        // or kill it through the cgroupfs.
        info!(
            "prepared the run cgroup {}{}",
            run.cgroup.display(),
            if class.is_some() {
                " (classed)"
            } else {
                " (classless: the policy default, or deny-by-default)"
            }
        );
        Ok(run)
    }

    /// Undo one run: remove its authorization from the maps and, best
    /// effort, the directory. Never fails — the command's outcome is
    /// already decided, and a leftover cgroup is over-strict (its walls
    /// stay up), never a hole.
    fn release_run(&mut self, run: &crate::runs::PreparedRun) {
        use wabbit_common::authorization::{Authorization, PathRuleKey};

        {
            let mut authorizations: HashMap<_, CgroupKey, Authorization> = match self
                .ebpf
                .map_mut("AUTHORIZATIONS")
                .context("finding AUTHORIZATIONS")
                .and_then(|map| map.try_into().context("opening AUTHORIZATIONS"))
            {
                Ok(map) => map,
                Err(error) => {
                    warn!("releasing the run's authorization: {error:#}");
                    return;
                }
            };
            // A classless run wrote no entry, so this is often just a
            // no-op (and a missing key deletes as ENOENT — debug, not a
            // warning, for exactly that reason).
            if let Err(error) = authorizations.remove(&CgroupKey {
                cgroup_id: run.cgroup_id,
            }) {
                debug!("removing the run's authorization: {error}");
            }
        }
        {
            let mut path_rules: HashMap<_, PathRuleKey, u32> = match self
                .ebpf
                .map_mut("PATH_RULES")
                .context("finding PATH_RULES")
                .and_then(|map| map.try_into().context("opening PATH_RULES"))
            {
                Ok(map) => map,
                Err(error) => {
                    warn!("releasing the run's path rules: {error:#}");
                    return;
                }
            };
            for hash in &run.rule_prefix_hashes {
                if let Err(error) = path_rules.remove(&PathRuleKey {
                    cgroup_id: run.cgroup_id,
                    path_hash: *hash,
                }) {
                    debug!("removing the run's path rule: {error}");
                }
            }
        }

        // The directory: a run's own descendants may still be alive
        // inside, and then rmdir fails with EBUSY — the cgroup stays,
        // walls and all. Over-strict, never a hole; the operator hears
        // it once instead of finding it in an audit.
        if let Err(error) = fs::remove_dir(&run.cgroup)
            && run.cgroup.exists()
        {
            warn!(
                "could not remove the run cgroup {} ({error}); its walls stay up",
                run.cgroup.display()
            );
        }
    }
}
