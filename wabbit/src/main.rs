use anyhow::Context;
use aya::Btf;
#[rustfmt::skip]
use log::{debug, info, warn};
use std::{env, io::Write as _, os::fd::AsRawFd as _, sync::Arc};

use tokio::signal;
use wabbit::{
    filesystem, guard, handoff, ipc,
    policy::{self, Policy},
    runs, runtime, startup,
};
use wabbit_common::brand;

/// The environment variable carrying the IPC socket path.
fn ipc_socket_var() -> String {
    format!("{}_IPC_SOCKET", brand::ENV_PREFIX)
}

fn main() -> anyhow::Result<()> {
    // Self-test workers re-execute this binary and must exit before any of
    // the real startup runs: they touch no mounts, no maps, no logger.
    if let Some(code) = guard::worker_main() {
        std::process::exit(code);
    }

    // The brand, not the crate's module path, prefixes console output.
    env_logger::Builder::from_env(env_logger::Env::default())
        .format(|buf, record| {
            // Wall-clock epoch milliseconds: std-only (the `humantime`
            // feature that backs env_logger's own timestamps drags a
            // datetime crate into a static initrd binary), and enough to
            // order two processes' interleaved console lines — the trust
            // rendezvous race was diagnosed on exactly that ordering.
            let millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis())
                .unwrap_or_default();
            writeln!(
                buf,
                "[{} {} {:5.5}] {}",
                brand::NAME,
                millis,
                record.level(),
                record.args()
            )
        })
        .init();

    // The startup diagram's first `wabbit` step: open descriptors on the
    // runtime filesystems before anything moves under `/sysroot` — and
    // fail fast, before the first mount is touched, if the environment
    // cannot hand out the real procfs and sysfs. Everything below runs in
    // this process, the PID wabbit-initrd vouched for in bnuuy's
    // trusted-PID map, so every `bpf(2)` call — the eBPF loads below, the
    // map operations behind them — happens under that trust. The moment
    // wabbit forks an untrusted child is the moment that stops being true,
    // which is why it does not.
    let fds = runtime::RuntimeFds::capture()?;

    // The initrd's handoff socket (None when no initrd launched this
    // process). Held whole-life: the trust rendezvous below and the
    // readiness exchange later share it.
    let mut handoff = handoff::Handoff::from_env()?;

    // The trust rendezvous: bnuuy's `bpf(2)` grant lands in
    // `TRUSTED_BPF_PIDS` microseconds after the fork that started this
    // process, and this process's own first `bpf(2)` call — the guard
    // object's first map create — races it. Wait for the grant before
    // anything touches `bpf(2)`; a lost race read the trust map without
    // this PID and denied the creates, nondeterministically across boots.
    handoff.await_trust()?;

    let policy = configured_policy()?;
    let rootfs = policy.rootfs.clone().unwrap_or_default();

    // The outer policy, in the namespace this process was launched into:
    // what everyone else sees. Overrides apply in ascending priority
    // order; the same operation is reusable later, on the IPC's signed
    // reconfiguration, with `inner = true`.
    filesystem::apply_rootfs_config(&rootfs, false)?;

    // A private mount namespace for the inner policy. Namespace creation
    // is thread-local, so it must happen before the Tokio runtime and its
    // worker threads exist; the eBPF loads below sit on the other side of
    // that line, in this thread but still in this PID.
    filesystem::create_namespace()?;
    filesystem::make_mount_tree_private()?;
    filesystem::apply_rootfs_config(&rootfs, true)?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let btf = Btf::from_sys_fs().context("loading kernel BTF from /sys/kernel/btf/vmlinux")?;

    // The startup diagram's `wabbit` steps: load the guard (maps created
    // from the policy, wabbit trusted, every gate attached observing),
    // then the self-test loops and the enforcing flip. All of it runs
    // before the handoff: "ready" is only true once the guard enforces.
    let mut guard = guard::Guard::load(&btf, &policy).context("loading the guard")?;

    // The eBPF logger's sink: initialized here, drained by a runtime task
    // below — the events the guard logs before the runtime exists (the
    // self-test's decisions among them) sit in the log buffer until then.
    let logger = match aya_log::EbpfLogger::init(guard.ebpf_mut()) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
            None
        }
        Ok(logger) => Some(logger),
    };

    guard.self_test().context("the guard self-test")?;

    // The initrd handoff: announce enforcement, wait out the initrd's
    // pre-shutdown self-test, then wait out `switch_root` and join the
    // booted system. The namespace *join* is as thread-local as the
    // namespace creation above (`setns(CLONE_NEWNS)` refuses a shared
    // `fs_struct`), and the handoff blocks for the initrd's worker round —
    // so both run here, on the main thread, before the runtime's threads
    // exist.
    handoff.ready()?;

    // From here on the guard serves more than one caller: each IPC run
    // command writes the authorization maps while preparing its
    // ephemeral cgroup, and commands may arrive concurrently. The
    // self-test above needed `&mut`; the runtime gets its `&mut` through
    // a mutex instead. Nothing about enforcement changes — the links
    // still live exactly as long as the guard object does.
    let guard = Arc::new(std::sync::Mutex::new(guard));
    let authorizer: Arc<dyn runs::RunAuthorizer> = Arc::clone(&guard) as _;

    // The initrd-point `[[startup]]` entries: launched here — the guard
    // enforcing, the process still in the initramfs, before the crossing
    // (the tokio runtime does not exist yet, so the launches are
    // blocking; a long-running entry delays the crossing, which is the
    // honest cost of an entry that does not exit before
    // `switch_root`). Per-entry fail-open.
    startup::launch_initrd(&policy, &authorizer);

    handoff::join_root(&fds)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(fds, policy, logger, guard))
}

async fn run(
    fds: runtime::RuntimeFds,
    policy: Policy,
    logger: Option<aya_log::EbpfLogger<&'static dyn log::Log>>,
    guard: Arc<std::sync::Mutex<guard::Guard>>,
) -> anyhow::Result<()> {
    // "keep those for later" (the startup diagram): the descriptors are
    // held for this process's lifetime and inherited by everything it
    // spawns (opened without CLOEXEC). The systemd poll and the chroot
    // into the real root have already read through them (the handoff
    // above); the shutdown watch below reads through them too, and they
    // stay open — and inheritable — for whatever comes next.
    info!(
        "holding runtime fds: /proc fd {}, /sys fd {}, /dev fd {}, /run fd {}",
        fds.procfs.as_raw_fd(),
        fds.sysfs.as_raw_fd(),
        fds.dev.as_raw_fd(),
        fds.run.as_raw_fd(),
    );
    let held = fds;

    // The eBPF logger's drain: a ring buffer in the kernel this task
    // empties. The logger was initialized on the main thread; only the
    // drain needs the runtime.
    if let Some(logger) = logger {
        let mut logger =
            tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
        tokio::task::spawn(async move {
            loop {
                let mut log = logger.readable_mut().await.unwrap();
                log.get_inner_mut().flush();
                log.clear_ready();
            }
        });
    }

    // The IPC server is optional: only the socket path's presence decides
    // whether one exists. It binds after the handoff's crossing, so the
    // socket lands in the booted system's root, where its callers are.
    // Every command it will act on is signed and anti-replayed; the
    // server's state anchors both (this boot's id, the burned command
    // ids, the compiled-in verification keys) and carries the guard's
    // run authorizer — the half that gives each run its own ephemeral
    // cgroup — and the stop signal below, which a signed `stop` command
    // raises — so a socket path without that state is no server at all.
    let stop = Arc::new(tokio::sync::Notify::new());
    let socket_path = env::var_os(ipc_socket_var()).map(std::path::PathBuf::from);
    let ipc_task = match socket_path {
        Some(path) => {
            let authorizer: Arc<dyn wabbit::runs::RunAuthorizer> = Arc::clone(&guard) as _;
            match ipc::server_state(policy.clone(), authorizer, Arc::clone(&stop)) {
                Ok(state) => Some(tokio::spawn(ipc::run_server(path, state))),
                Err(error) => {
                    warn!("IPC unavailable: {error:#}");
                    None
                }
            }
        }
        None => None,
    };

    // The post-crossing `[[startup]]` entries — the `systemd` point at
    // once, the `unit` point as its unit reaches active — in their own
    // task: an entry may launch a program that outlives this function
    // (a daemon is a legitimate `[[startup]]` argv), so the task, like
    // the IPC server's, is never awaited; it dies with the process. The
    // entries resolve their classes against this boot's policy — a
    // later reconfigure rotates classes for *runs*, never for entries
    // already launched.
    {
        let authorizer: Arc<dyn runs::RunAuthorizer> = Arc::clone(&guard) as _;
        let policy = policy.clone();
        tokio::spawn(async move {
            startup::launch_post_crossing(&policy, &authorizer).await;
        });
    }

    // The park. Under enforcement the operator's stop channel is the
    // signed `stop` IPC command — the signal gate's self-guard denies
    // every signal aimed at this process, `SIGINT` included, outside
    // shutdown, so a graceful exit is *asked for*, by the deployment's
    // key, not sent by whatever process feels like it. `Ctrl-C` still
    // ends a pre-enforcement (dev) run and anything the shutdown watch
    // below has relaxed. That watch is everything else the loop does:
    // the one condition under which the self-guard lets outside
    // processes signal wabbit again. PID 1's own sweep is exempt by
    // sender already; the relaxation covers the rest of a shutdown (a
    // SysV-style `killall5` sweep runs from a non-PID-1 sender) and is
    // observed, never assumed: PID 1 gone, PID 1 *being* the shutdown
    // process, or a delivered SIGTERM — which, once the guard enforces,
    // only an exempt sender can land.
    println!("Waiting for Ctrl-C...");
    if ipc_task.is_some() {
        // The honest stop instruction for an enforcing run: the marker
        // above names the pre-enforcement/dev channel, this one names
        // the one that works under enforcement.
        info!(
            "under enforcement the stop channel is the signed stop command \
             ({} stop) — this process accepts no signals",
            brand::CLIENT_NAME
        );
    }
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM watch")?;
    let mut shutdown_seen = false;
    let mut shutdown_watch = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        let shutting_down = tokio::select! {
            _ = &mut ctrl_c => break,
            // A signed `stop`: the server answered its client already;
            // this process takes the same graceful exit `Ctrl-C` does.
            _ = stop.notified() => break,
            _ = sigterm.recv() => true,
            _ = shutdown_watch.tick() => system_shutting_down(&held.procfs),
        };
        if shutting_down && !shutdown_seen {
            shutdown_seen = true;
            if let Ok(mut guard) = guard.lock() {
                guard.note_shutdown();
            }
        }
    }
    println!("Exiting...");
    // Dropping this handle (and the server's clone with it, as the
    // abort above winds the server down) detaches the guard's links:
    // enforcement ends with the process that owned it.
    drop(guard);

    if let Some(ipc_task) = ipc_task {
        ipc_task.abort();
    }
    if let Some(socket_path) = env::var_os(ipc_socket_var()) {
        let _ = std::fs::remove_file(socket_path);
    }
    Ok(())
}

/// The signed policy baked into this binary at build time, if any.
///
/// Set `WABBIT_EMBED_POLICY=<path to a signed .wspf>` at build time and
/// build.rs copies the file into `OUT_DIR`, **verifies it against this
/// build's compiled-in policy keys**, and flips the `embedded_policy` cfg
/// on. Because wabbit rides inside `wabbit-initrd` inside the initramfs
/// image, a baked policy needs no filesystem footprint at all — the
/// first-install path: `scp` one binary, install, boot.
///
/// Precedence in [`configured_policy`]: the env-var file (the installer's
/// `--policy` and the IPC rotation path) overrides this, which overrides
/// `Policy::default()`. The runtime re-verifies the embedded bytes — the
/// build-time check is for *our* mistakes, this one is for a tampered
/// binary's.
#[cfg(embedded_policy)]
const EMBEDDED_POLICY: Option<&[u8]> = Some(include_bytes!(concat!(env!("WABBIT_EMBED_POLICY"))));
#[cfg(not(embedded_policy))]
const EMBEDDED_POLICY: Option<&[u8]> = None;

/// Load the configured policy: the file named by
/// `<prefix>_FILESYSTEM_CONFIGURATION_FILE` if set (the installer's
/// `--policy`, the IPC rotation path), else the policy baked into this
/// binary at build time, else the empty default.
fn configured_policy() -> anyhow::Result<Policy> {
    let variable = format!("{}_FILESYSTEM_CONFIGURATION_FILE", brand::ENV_PREFIX);
    if let Some(path) = env::var_os(&variable) {
        return policy::read_file(path);
    }
    if let Some(bytes) = EMBEDDED_POLICY {
        return policy::from_bytes(bytes).context("the policy baked into this binary");
    }
    Ok(Policy::default())
}

/// Is the system shutting down? Read through the held procfs descriptor
/// — wabbit may be chrooted into PID 1's view of the root by now, and
/// the descriptor refers to the live procfs whatever the root looks
/// like — so the watch survives the crossing. Two observations count,
/// both of them the *end* of the boot's own lifecycle:
///
/// * **PID 1 is gone** (`1/comm` no longer opens): an init exiting is
///   the machine's last act, not an ordinary event;
/// * **PID 1 *is* the shutdown process**: systemd re-executes into
///   `systemd-shutdown` for its final sweep, and `comm` carries only
///   the first 15 bytes of the name — so the prefixes below are what a
///   16-byte name leaves. A bare `shutdown` covers the non-systemd
///   inits that exec their own shutdown helper as PID 1.
///
/// An unreadable `comm` for any other reason decides nothing: the watch
/// keeps polling, and the protection stays up — the `self_guard`'s
/// relaxation is the *exception* to prove, never the default.
fn system_shutting_down(procfs: &std::os::fd::OwnedFd) -> bool {
    let fd = match rustix::fs::openat(
        procfs,
        "1/comm",
        rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return true,
        Err(_) => return false,
    };
    let mut buffer = [0u8; 32];
    let read = rustix::io::read(&fd, &mut buffer).unwrap_or(0);
    let comm = &buffer[..read];
    let end = comm
        .iter()
        .position(|&byte| byte == b'\n')
        .unwrap_or(comm.len());
    let name = &comm[..end];
    name.starts_with(b"shutdown") || name.starts_with(b"systemd-shutdow")
}
