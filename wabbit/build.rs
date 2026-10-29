use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // The white-label knobs: the embedded wabbit-ebpf object is compiled
    // by a nested cargo (which inherits the environment), so a change
    // must rerun this build script to re-invoke it.
    for var in [
        "WABBIT_BRAND_NAME",
        "WABBIT_BRAND_ENV_PREFIX",
        "WABBIT_BRAND_SIGN_NAME",
        "WABBIT_BRAND_SIGN_MAGIC",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "wabbit-ebpf")
        .ok_or_else(|| anyhow!("wabbit-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
