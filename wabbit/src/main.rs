use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use std::{
    env,
    process::{Command, ExitStatus},
};
use tokio::signal;
use wabbit::{filesystem, ipc};

const NAMESPACE_MODE: &str = "--wabbit-namespace";

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let configuration = configured_configuration()?;
    filesystem::apply_rootfs_config(&configuration, false)?;
    if is_namespace_mode() {
        filesystem::create_namespace()?;
        filesystem::make_mount_tree_private()?;
        filesystem::apply_rootfs_config(&configuration, true)?;
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_in_namespace());
    }

    relaunch_in_namespace()
}

fn is_namespace_mode() -> bool {
    env::args().any(|arg| arg == NAMESPACE_MODE)
}

fn relaunch_in_namespace() -> anyhow::Result<()> {
    let executable = env::current_exe()?;
    let socket_path = env::temp_dir().join(format!("wabbit-{}.sock", std::process::id()));
    let mut child = Command::new(executable);
    child.args(env::args_os().skip(1));
    child.arg(NAMESPACE_MODE);
    child.env("WABBIT_IPC_SOCKET", socket_path);
    let status = child.status()?;
    exit_status_result(status)
}

fn exit_status_result(status: ExitStatus) -> anyhow::Result<()> {
    if status.success() {
        Ok(())
    } else if let Some(code) = status.code() {
        std::process::exit(code)
    } else {
        anyhow::bail!("namespace process terminated by signal")
    }
}

async fn run_in_namespace() -> anyhow::Result<()> {
    let socket_path = env::var_os("WABBIT_IPC_SOCKET").map(std::path::PathBuf::from);
    let configuration = configured_configuration()?;
    let ipc_task =
        socket_path.map(|path| tokio::spawn(ipc::run_server(path, configuration.clone())));

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
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/wabbit"
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
    let program: &mut TracePoint = ebpf.program_mut("wabbit").unwrap().try_into()?;
    program.load()?;
    program.attach("sys", "sys_enter")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    if let Some(ipc_task) = ipc_task {
        ipc_task.abort();
    }
    if let Some(socket_path) = env::var_os("WABBIT_IPC_SOCKET") {
        let _ = std::fs::remove_file(socket_path);
    }
    Ok(())
}

fn configured_configuration() -> anyhow::Result<filesystem::RootFSConfig> {
    match env::var("WABBIT_FILESYSTEM_CONFIGURATION") {
        Ok(configuration) => Ok(serde_json::from_str(&configuration)?),
        Err(env::VarError::NotPresent) => Ok(filesystem::RootFSConfig {
            writable: true,
            executable: true,
            overrides: Vec::new(),
        }),
        Err(error) => Err(error.into()),
    }
}
