use anyhow::Context;
use aya::Btf;
#[rustfmt::skip]
use log::{debug, info, warn};
use std::{env, io::Write as _, os::fd::AsRawFd as _};

use tokio::signal;
use wabbit::{
    filesystem, guard, ipc,
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
            writeln!(
                buf,
                "[{} {}] {}",
                brand::NAME,
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
    // that line, in the runtime's threads but still in this PID.
    filesystem::create_namespace()?;
    filesystem::make_mount_tree_private()?;
    filesystem::apply_rootfs_config(&rootfs, true)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(fds, policy))
}

async fn run(fds: runtime::RuntimeFds, policy: Policy) -> anyhow::Result<()> {
    // "keep those for later" (the startup diagram): the descriptors are
    // held for this process's lifetime and inherited by everything it
    // spawns (opened without CLOEXEC). The later steps — the systemd poll,
    // `/proc/1/root`, the chroot into the real root — read through them;
    // none exists yet, so this logs what it holds.
    info!(
        "holding runtime fds: /proc fd {}, /sys fd {}, /dev fd {}, /run fd {}",
        fds.procfs.as_raw_fd(),
        fds.sysfs.as_raw_fd(),
        fds.dev.as_raw_fd(),
        fds.run.as_raw_fd(),
    );
    let _held = fds;

    // The IPC server is optional: only the socket path's presence decides
    // whether one exists.
    let socket_path = env::var_os(ipc_socket_var()).map(std::path::PathBuf::from);
    let ipc_task = socket_path.map(|path| tokio::spawn(ipc::run_server(path, policy.clone())));

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

    // The startup diagram's `wabbit` steps: load the guard (maps created,
    // wabbit trusted, every gate attached observing), then the self-test
    // loops and the enforcing flip. The `Guard` handle is held for this
    // process's whole lifetime — the attachment's lifetime *is* the
    // enforcement, and its links detach the moment it drops.
    let mut guard = guard::Guard::load(&btf, &policy).context("loading the guard")?;

    // The eBPF logger's sink: a ring buffer in the kernel this task drains.
    match aya_log::EbpfLogger::init(guard.ebpf_mut()) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
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
    }

    guard.self_test().context("the guard self-test")?;

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

/// Load the signed policy file named by `<prefix>_FILESYSTEM_CONFIGURATION_FILE`, if any.
fn configured_policy() -> anyhow::Result<Policy> {
    let variable = format!("{}_FILESYSTEM_CONFIGURATION_FILE", brand::ENV_PREFIX);
    match env::var_os(variable) {
        Some(path) => policy::read_file(path),
        None => Ok(Policy::default()),
    }
}
