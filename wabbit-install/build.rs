//! Bundle the wabbit-initrd artifact into the installer at build time —
//! the same arrangement wabbit-initrd uses to embed wabbit, so the
//! installer carries its artifact and needs no checkout on the target
//! system. `--artifact` overrides the bundle for custom builds.
//!
//! A build script cannot use the parent cargo's target directory (its
//! lock is held for the whole outer build), so this builds in a private
//! one under `OUT_DIR`. Building wabbit-initrd runs its own build script
//! inside the nested build too, embedding bnuuy and the wabbit blob, so
//! the bundle is the complete, self-contained musl artifact.

use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Stdio},
};

fn main() {
    // The white-label knobs: they change both this crate's strings and the
    // nested wabbit-initrd build (which inherits the environment), so a
    // change must rebuild the bundle.
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_NAME");
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_ENV_PREFIX");
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_SIGN_NAME");
    println!("cargo:rerun-if-env-changed=WABBIT_BRAND_SIGN_MAGIC");
    if let Err(error) = bundle() {
        panic!("building the bundled wabbit-initrd failed: {error}");
    }
}

/// The target the bundled wabbit-initrd is built for: static musl, so the
/// artifact runs in any initramfs (which has no glibc) and on any distro
/// (whose glibc may be older than the build host's). Overridable with
/// `WABBIT_INSTALL_TARGET` for unusual hosts.
fn bundle_target() -> String {
    if let Some(target) = env::var_os("WABBIT_INSTALL_TARGET") {
        return target.to_string_lossy().into_owned();
    }
    match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "aarch64-unknown-linux-musl",
        _ => "x86_64-unknown-linux-musl",
    }
    .to_owned()
}

fn bundle() -> Result<(), String> {
    let target = bundle_target();
    // Best effort: the nested cargo uses the toolchain this workspace
    // pins, so make sure its target is installed.
    let _ = Command::new("rustup")
        .arg("target")
        .arg("add")
        .arg(&target)
        .stdout(Stdio::null())
        .status();

    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|error| error.to_string())?);
    let target_dir = out_dir.join("wabbit-initrd-bundle-build");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .arg("build")
        .arg("--package=wabbit-initrd")
        .arg("--release")
        .arg("--target")
        .arg(&target)
        .arg(format!("--target-dir={}", target_dir.display()))
        // Build script stdout is cargo's directive channel; a nested cargo
        // must not pollute it. Its diagnostics go to stderr and flow
        // through to the outer build's log.
        .stdout(Stdio::null())
        .status()
        .map_err(|error| format!("spawning cargo: {error}"))?;
    if !status.success() {
        return Err(format!("the nested wabbit-initrd build failed: {status}"));
    }

    let built = target_dir
        .join(&target)
        .join("release")
        .join("wabbit-initrd");
    let blob = out_dir.join("wabbit-initrd-blob");
    fs::copy(&built, &blob)
        .map_err(|error| format!("copying the artifact into OUT_DIR: {error}"))?;

    // Rerun when anything that feeds the bundled binary changes. The
    // moment any rerun-if-changed is emitted, cargo's default (rerun on
    // any change within this package) stops applying, so the packages
    // behind the artifact and the shared manifests are covered
    // explicitly.
    for path in [
        "build.rs",
        "../Cargo.toml",
        "../Cargo.lock",
        "../wabbit-initrd/src",
        "../wabbit-initrd/build.rs",
        "../wabbit-initrd/Cargo.toml",
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
