//! Ephemeral run cgroups: how a signed run command gets its own slice
//! of the hierarchy, scoped to the class it names.
//!
//! A run never executes in wabbit's own cgroup — that cgroup is
//! *trusted*, its processes exempt from every gate, so a program there
//! would outrank the whole model. Instead each run gets a fresh child
//! cgroup, `run-<command id>` (the anti-replay id, unique and strictly
//! increasing per boot, is also the cgroup name: no two runs share one
//! and no leftover can collide with a fresh one):
//!
//! * a **classed** run resolves the class — the policy crate compiled
//!   `[[class]]` blocks into authorization entries at
//!   `<wabbit-cgroup>/class/<name>`, and the server looks that exact
//!   path up in the *active* policy (so a reconfigure rotates classes
//!   without a reboot) — then creates the child under the class's
//!   cgroup and gives it exactly the class's authorization;
//! * a **classless** run gets the same child under wabbit's own cgroup
//!   with *no* authorization of its own — an unlisted cgroup, so the
//!   policy's `[default]` entry governs it when there is one, and the
//!   deny-by-default floor when there is not.
//!
//! The cgroup dies with the run: its map entries are removed and the
//! directory deleted, best-effort — a lingering cgroup is over-strict
//! (its walls stay up), never a hole. Everything a run cgroup holds is
//! under wabbit's own cgroup, whose hash is in `PROTECTED_PATHS`, so
//! the migration wall covers all of it by prefix: nothing outside may
//! move a process into a run cgroup, or freeze or kill one through the
//! cgroupfs. The signature on the command is what authorizes the
//! class; the class's compiled entry is what the signature buys.

use std::{
    fs,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
};

use anyhow::{Context, Result, bail};
use wabbit_common::cgroup_types::{CLASS_SEGMENT, RUN_PREFIX, class_cgroup_fits};
use wabbit_policy::authorization::AuthorizationEntry;

use crate::policy::Policy;

/// One prepared run cgroup: everything needed to undo it.
#[derive(Debug, Clone)]
pub struct PreparedRun {
    /// The created cgroup directory.
    pub cgroup: PathBuf,
    /// Its kernfs id — the `AUTHORIZATIONS`/`PATH_RULES` key, the same
    /// id `bpf_get_current_cgroup_id` reports for a process inside it.
    pub cgroup_id: u64,
    /// The hashes of the path-rule prefixes written for it, so the
    /// release can remove exactly those keys.
    pub rule_prefix_hashes: Vec<u64>,
}

/// What the IPC server needs from the guard to run a command in an
/// ephemeral cgroup: create it, authorize it, undo it.
///
/// A trait so the server's half (the class resolution, the process
/// migration, the response) is testable without a live eBPF object —
/// `Guard` is the only real implementation; the tests bring their own.
pub trait RunAuthorizer: Send + Sync {
    /// wabbit's own cgroup path — the subtree the class entries
    /// compile under and run cgroups are created in.
    fn own_cgroup(&self) -> String;

    /// Create the ephemeral cgroup for run `command_id`: under the
    /// named class's cgroup (already resolved from the active policy)
    /// when `class` is given, else a bare child of wabbit's own. The
    /// child receives exactly the class's authorization; a classless
    /// run receives none.
    fn prepare_run(
        &self,
        class: Option<&AuthorizationEntry>,
        command_id: u64,
    ) -> Result<PreparedRun>;

    /// Undo one prepared run: remove its authorization from the maps
    /// and, best-effort, the directory. Never fails the caller — the
    /// command's outcome is already decided; a leftover cgroup is
    /// over-strict, never a hole.
    fn release_run(&self, run: &PreparedRun);
}

/// The compiled entry path of class `name` under wabbit's cgroup —
/// the one convention the policy crate compiles to and the runtime
/// resolves (`wabbit_common::cgroup_types` spells the shared rules).
pub fn class_cgroup_path(own: &str, name: &str) -> Result<String> {
    if !class_cgroup_fits(own, name) {
        bail!(
            "the class name {name:?} is invalid, or {own:?} is too deep for the class \
             path to fit the eBPF walk cap"
        );
    }
    Ok(format!("{own}/{CLASS_SEGMENT}/{name}"))
}

/// Resolve a class name to its compiled entry in `policy`: the convention
/// path ([`class_cgroup_path`]) against wabbit's own cgroup, looked up in
/// the policy's authorization section. Shared by the IPC server's
/// classed runs and the boot's `[[startup]]` entries — one lookup, no
/// class concept anywhere else in the runtime.
///
/// `own` is the authorizer's own cgroup (the subtree the class entries
/// compile under); the caller supplies the policy to resolve against.
pub fn class_entry(policy: &Policy, own: &str, name: &str) -> Result<AuthorizationEntry> {
    let path = class_cgroup_path(own, name)?;
    policy
        .authorization
        .as_ref()
        .and_then(|config| {
            config
                .entries
                .iter()
                .find(|entry| entry.cgroup == Path::new(&path))
        })
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the active policy defines no class {name:?}: classes compile to \
                 <wabbit-cgroup>/{}/<name> entries, and no entry sits at {path:?}",
                CLASS_SEGMENT
            )
        })
}

/// The ephemeral run cgroup under `parent`: `run-<command id>`.
pub fn run_cgroup_path(parent: &Path, command_id: u64) -> PathBuf {
    parent.join(format!("{RUN_PREFIX}{command_id}"))
}

/// Create the ephemeral run cgroup under `parent` and report its
/// kernfs id. The class directory may not exist yet — a class that
/// arrived by reconfigure was never materialized at load — so the
/// parent is created too (wabbit owns its subtree; kernfs has no
/// symlinks, so the directories cannot escape it).
///
/// The spawned process puts *itself* in (see `migrate_command`'s
/// self-migration): the child writes its own pid to the cgroup's
/// `cgroup.procs` between fork and exec, so the program's first syscall
/// after exec already runs inside the run cgroup — no window in which
/// run code executes with wabbit's own trust.
pub fn create_run_cgroup(parent: &Path, command_id: u64) -> Result<(PathBuf, u64)> {
    fs::create_dir_all(parent)
        .with_context(|| format!("ensuring the run parent {}", parent.display()))?;
    let cgroup = run_cgroup_path(parent, command_id);
    fs::create_dir(&cgroup)
        .with_context(|| format!("creating the run cgroup {}", cgroup.display()))?;
    let id = fs::metadata(&cgroup)
        .with_context(|| format!("stat(2) on the run cgroup {}", cgroup.display()))?
        .ino();
    Ok((cgroup, id))
}

/// A `Command` that migrates the child *itself* into `run`'s cgroup: the
/// `pre_exec` closure runs between fork and exec, so the program's
/// first instruction after exec already runs inside the run cgroup —
/// no window in which run code executes with wabbit's own trust. The
/// closure runs after fork in a multithreaded process: only
/// async-signal-safe calls (open, write, close, getpid) and no
/// allocation — the `cgroup.procs` path is a ready `CString` built
/// before the fork, the pid formats into a stack buffer.
///
/// Stdin/stdout/stderr are piped; the caller drops the child's stdin
/// when the rendezvous is over (an `EOF` releases a program reading
/// stdin) and reads the rest.
pub fn migrate_command(program: &str, args: &[String], run: &PreparedRun) -> Result<StdCommand> {
    let procs = std::ffi::CString::new(
        run.cgroup
            .join("cgroup.procs")
            .to_str()
            .context("the run cgroup path is UTF-8")?,
    )
    .map_err(|_| anyhow::anyhow!("the cgroup.procs path is not C-stringable"))?;
    let mut command = StdCommand::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut digits = [0u8; 20];
            let pid = libc::getpid() as u64;
            let mut length = digits.len();
            let mut rest = pid;
            loop {
                length -= 1;
                digits[length] = b'0' + (rest % 10) as u8;
                rest /= 10;
                if rest == 0 {
                    break;
                }
            }
            let written = libc::write(
                fd,
                digits[length..].as_ptr().cast::<libc::c_void>(),
                digits.len() - length,
            );
            let written = if written < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            };
            libc::close(fd);
            written
        });
    }
    Ok(command)
}

/// [`migrate_command`], spawned on the plain std runtime — for callers
/// outside a tokio runtime (the initrd-point startup entries, which run
/// before the runtime exists).
pub fn spawn_migrated_blocking(
    program: &str,
    args: &[String],
    run: &PreparedRun,
) -> Result<std::process::Child> {
    migrate_command(program, args, run)?
        .spawn()
        .with_context(|| format!("running {program}"))
}

/// [`migrate_command`], spawned on the tokio runtime — for callers
/// already inside it (the IPC runs, the post-crossing startup points).
pub fn spawn_migrated(
    program: &str,
    args: &[String],
    run: &PreparedRun,
) -> Result<tokio::process::Child> {
    tokio::process::Command::from(migrate_command(program, args, run)?)
        .spawn()
        .with_context(|| format!("running {program}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_class_path_is_the_shared_convention() {
        assert_eq!(
            class_cgroup_path("/sys/fs/cgroup/wabbit", "shell").unwrap(),
            "/sys/fs/cgroup/wabbit/class/shell"
        );
        // The name is a security boundary: nothing that could
        // reinterpret as a path resolves at all.
        assert!(class_cgroup_path("/sys/fs/cgroup/wabbit", "../escape").is_err());
        assert!(class_cgroup_path("/sys/fs/cgroup/wabbit", "sh/ell").is_err());
        assert!(class_cgroup_path("/sys/fs/cgroup/wabbit", "").is_err());
    }

    #[test]
    fn run_cgroups_are_named_by_the_command_id() {
        assert_eq!(
            run_cgroup_path(Path::new("/sys/fs/cgroup/wabbit/class/shell"), 42),
            PathBuf::from("/sys/fs/cgroup/wabbit/class/shell/run-42")
        );
    }

    /// The filesystem half, against real cgroupfs when the test host
    /// has it (the tests run as root): the created directory gets a
    /// fresh kernfs id and a working `cgroup.procs`, and the naming is
    /// collision-free across ids.
    #[test]
    fn the_run_cgroup_is_real_on_a_cgroupfs_host() {
        let root = Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.procs").exists() {
            eprintln!("skipping: {} is not a cgroup v2 mount", root.display());
            return;
        }
        let parent = root.join(format!(
            "{}-runs-test-{}",
            env!("CARGO_PKG_NAME"),
            std::process::id()
        ));
        let _ = fs::remove_dir(&parent);
        // Creating cgroups needs root — the suite's runner has it; a
        // bare dev run skips rather than fails.
        if let Err(error) = fs::create_dir(&parent) {
            eprintln!("skipping: no write access to {}: {error}", root.display());
            return;
        }
        let (first, first_id) = create_run_cgroup(&parent, 1).unwrap();
        let (second, second_id) = create_run_cgroup(&parent, 2).unwrap();
        assert_ne!(
            first_id, second_id,
            "each run cgroup gets a fresh kernfs id"
        );
        assert!(first.join("cgroup.procs").exists());
        fs::remove_dir(&first).unwrap();
        fs::remove_dir(&second).unwrap();
        fs::remove_dir(&parent).unwrap();
    }
}
