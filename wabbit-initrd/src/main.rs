use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use wabbit::{
    filesystem::{self, RootFSConfig},
    policy,
};

fn main() -> Result<()> {
    env_logger::init();

    let (inner, create_namespace) = parse_args()?;
    let configuration = load_configuration()?;

    if create_namespace {
        filesystem::create_namespace().context("creating mount namespace")?;
        filesystem::make_mount_tree_private().context("making mount tree private")?;
    }
    filesystem::apply_rootfs_config(&configuration, inner)
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
                     Apply WABBIT_FILESYSTEM_CONFIGURATION in the current mount namespace."
                );
                std::process::exit(0);
            }
            _ => bail!("unknown argument {argument}"),
        }
    }
    Ok((inner, create_namespace))
}

fn load_configuration() -> Result<RootFSConfig> {
    if let Some(path) = env::var_os("WABBIT_FILESYSTEM_CONFIGURATION_FILE") {
        let path = PathBuf::from(path);
        let bytes =
            fs::read(&path).with_context(|| format!("reading configuration {}", path.display()))?;
        if bytes.starts_with(wabbit::policy::MAGIC) {
            return policy::from_bytes(&bytes)
                .with_context(|| format!("parsing binary configuration {}", path.display()));
        }
        let contents = std::str::from_utf8(&bytes)
            .with_context(|| format!("configuration {} is not UTF-8", path.display()))?;
        return serde_json::from_str(contents)
            .with_context(|| format!("parsing configuration {}", path.display()));
    }

    match env::var("WABBIT_FILESYSTEM_CONFIGURATION") {
        Ok(contents) => {
            serde_json::from_str(&contents).context("parsing WABBIT_FILESYSTEM_CONFIGURATION")
        }
        Err(env::VarError::NotPresent) => Ok(RootFSConfig::default()),
        Err(error) => Err(error.into()),
    }
}
