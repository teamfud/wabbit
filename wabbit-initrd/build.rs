use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "bnuuy")
        .ok_or_else(|| anyhow!("bnuuy package not found"))?;
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
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    build_wabbit_blob()
}

/// The target the embedded wabbit is built for: static musl, so the blob
/// runs in any initramfs (which has no glibc) and on any distro (whose
/// glibc may be older than the build host's). Overridable with
/// `WABBIT_BLOB_TARGET` for unusual hosts.
fn blob_target() -> String {
    if let Some(target) = env::var_os("WABBIT_BLOB_TARGET") {
        return target.to_string_lossy().into_owned();
    }
    match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "aarch64-unknown-linux-musl",
        _ => "x86_64-unknown-linux-musl",
    }
    .to_owned()
}

/// Compile the `wabbit` userspace binary and expose it as a blob for
/// `include_bytes!`.
///
/// A build script cannot use the parent cargo's target directory (its lock is
/// held for the whole outer build), so this builds in a private one under
/// `OUT_DIR` — the same arrangement `aya-build` uses for the eBPF object.
/// The `wabbit` package's own build script runs inside this nested build too,
/// embedding `wabbit-ebpf`, so the blob is a complete, self-contained wabbit
/// executable, statically linked so no glibc has to exist wherever it runs.
///
/// The nested build's stdout is discarded: build script stdout is cargo's
/// directive channel, and a nested cargo must not pollute it. Its diagnostics
/// go to stderr and flow through to the outer build's log.
fn build_wabbit_blob() -> anyhow::Result<()> {
    let target = blob_target();
    // Best effort: the nested cargo uses the toolchain this workspace pins,
    // so make sure its target is installed.
    let _ = Command::new("rustup")
        .arg("target")
        .arg("add")
        .arg(&target)
        .stdout(Stdio::null())
        .status();

    let out_dir = PathBuf::from(env::var("OUT_DIR").context("reading OUT_DIR")?);
    let target_dir = out_dir.join("wabbit-host-build");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .arg("build")
        .arg("--package=wabbit")
        .arg("--release")
        .arg("--target")
        .arg(&target)
        .arg(format!("--target-dir={}", target_dir.display()))
        .stdout(Stdio::null())
        .status()
        .context("spawning cargo for the embedded wabbit binary")?;
    if !status.success() {
        anyhow::bail!("building the embedded wabbit binary failed: {status}");
    }

    // The bnuuy eBPF object is embedded as OUT_DIR/wabbit, so the blob gets
    // its own name.
    let built = target_dir.join(&target).join("release").join("wabbit");
    let blob = out_dir.join("wabbit-blob");
    fs::copy(&built, &blob).context("copying the wabbit binary into OUT_DIR")?;
    println!("cargo:rustc-env=WABBIT_BLOB={}", blob.display());

    // Rerun when anything that feeds the two embedded blobs changes. The
    // moment any rerun-if-changed is emitted, cargo's default (rerun on any
    // change within this package) stops applying, so the packages behind
    // both blobs and the shared manifests are covered explicitly.
    for path in [
        "src",
        "../Cargo.toml",
        "../Cargo.lock",
        "../bnuuy/src",
        "../bnuuy/build.rs",
        "../bnuuy/Cargo.toml",
        "../wabbit/src",
        "../wabbit/build.rs",
        "../wabbit/Cargo.toml",
        "../wabbit-common/src",
        "../wabbit-common/Cargo.toml",
        "../wabbit-ebpf/src",
        "../wabbit-ebpf/Cargo.toml",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    Ok(())
}
