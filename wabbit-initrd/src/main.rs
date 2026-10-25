use std::env;

use anyhow::{Context, Result, bail};
use wabbit::{
    filesystem,
    policy::{self, Policy},
};

fn main() -> Result<()> {
    env_logger::init();

    let (inner, create_namespace) = parse_args()?;
    let rootfs = load_policy()?.rootfs.unwrap_or_default();

    if create_namespace {
        filesystem::create_namespace().context("creating mount namespace")?;
        filesystem::make_mount_tree_private().context("making mount tree private")?;
    }
    filesystem::apply_rootfs_config(&rootfs, inner)
        .context("applying initrd root filesystem configuration")?;
    Ok(())
}

fn parse_args() -> Result<(bool, bool)> {
    let mut inner = false;
    let mut create_namespace = false;
    for argument in env::args().skip(1) {
        match argument.as_str() {
            "--inner" => inner = true,
            "--outer" => inner = false,
            "--namespace" => create_namespace = true,
            "-h" | "--help" => {
                println!(
                    "Usage: wabbit-initrd [--outer|--inner] [--namespace]\n\
                     Apply the signed policy file named by WABBIT_FILESYSTEM_CONFIGURATION_FILE \
                     in the current mount namespace."
                );
                std::process::exit(0);
            }
            _ => bail!("unknown argument {argument}"),
        }
    }
    Ok((inner, create_namespace))
}

fn load_policy() -> Result<Policy> {
    match env::var_os("WABBIT_FILESYSTEM_CONFIGURATION_FILE") {
        Some(path) => policy::read_file(path),
        None => Ok(Policy::default()),
    }
}
