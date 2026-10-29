use anyhow::Context;
use aya::{Btf, EbpfLoader, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, info, warn};
use std::{env, io::Write as _, os::fd::AsRawFd as _};

use tokio::signal;
use wabbit::{
    filesystem, ipc,
    policy::{self, Policy},
    runtime,
};
use wabbit_common::brand;

/// The environment variable carrying the IPC socket path.
fn ipc_socket_var() -> String {
    format!("{}_IPC_SOCKET", brand::ENV_PREFIX)
}

fn main() -> anyhow::Result<()> {
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
    let ipc_task = socket_path.map(|path| tokio::spawn(ipc::run_server(path, policy)));

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF object at runtime rather than compile-time, you can
    // reach for `Bpf::load_file` instead.
    let btf = Btf::from_sys_fs().context("loading kernel BTF from /sys/kernel/btf/vmlinux")?;
    let mut loader = EbpfLoader::new();
    loader.btf(Some(&btf));
    let mut ebpf = loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/guard"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    // The guard's programs are `tracepoint/`-sectioned, so they load as
    // `aya::programs::TracePoint` — a `tp_btf/` section loads as
    // `BtfTracePoint`, and the two types do not convert into each other.
    // The category is the kernel's own (`raw_syscalls`), which aya resolves
    // against `<tracefs>/events/<category>/<event>/id`.
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_trace").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

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
