use anyhow::Context;
use aya::Btf;
#[rustfmt::skip]
use log::{debug, info, warn};
use std::{env, io::Write as _, os::fd::AsRawFd as _};

use tokio::signal;
use wabbit::{
    filesystem, guard, handoff, ipc,
    policy::{self, Policy},
    runtime,
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
    guard: guard::Guard,
) -> anyhow::Result<()> {
    // "keep those for later" (the startup diagram): the descriptors are
    // held for this process's lifetime and inherited by everything it
    // spawns (opened without CLOEXEC). The systemd poll and the chroot
    // into the real root have already read through them (the handoff
    // above); they stay open — and inheritable — for whatever comes next.
    info!(
        "holding runtime fds: /proc fd {}, /sys fd {}, /dev fd {}, /run fd {}",
        fds.procfs.as_raw_fd(),
        fds.sysfs.as_raw_fd(),
        fds.dev.as_raw_fd(),
        fds.run.as_raw_fd(),
    );
    let _held = fds;

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
    // ids, the compiled-in verification keys), so a socket path without
    // that state is no server at all.
    let socket_path = env::var_os(ipc_socket_var()).map(std::path::PathBuf::from);
    let ipc_task = match socket_path {
        Some(path) => match ipc::server_state(policy.clone()) {
            Ok(state) => Some(tokio::spawn(ipc::run_server(path, state))),
            Err(error) => {
                warn!("IPC unavailable: {error:#}");
                None
            }
        },
        None => None,
    };

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
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
