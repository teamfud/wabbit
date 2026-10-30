//! Bundle two artifacts into the installer at build time, so it carries
//! everything it places and needs no checkout on the target system:
//!
//! * **wabbit-initrd** — the protector artifact (the same arrangement
//!   wabbit-initrd itself uses to embed wabbit: a nested musl build that
//!   ends up embedding bnuuy and the wabbit blob too). `--artifact`
//!   overrides the bundle for custom builds.
//! * **wabbit-ipc** — the signed-command client. The installer writes it
//!   to the root filesystem's local bin folder, so operators get a
//!   working client on the box without a second upload; `--client`
//!   overrides it.
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
    // The policy knobs feed the bundled wabbit-initrd through its own nested
    // build (the chain: this script's nested wabbit-initrd build embeds
    // wabbit, which compiles its compiled-in key from
    // `WABBIT_POLICY_PUBLIC_KEY` and bakes `WABBIT_EMBED_POLICY`), so a
    // change of either must rerun this script to re-invoke it — otherwise
    // cargo considers this script fresh, the nested build never re-runs,
    // and the installer silently bundles a stale artifact. The policy file
    // itself can also change in place under an unchanged path.
    println!("cargo:rerun-if-env-changed=WABBIT_POLICY_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=WABBIT_EMBED_POLICY");
    if let Some(path) = env::var_os("WABBIT_EMBED_POLICY") {
        println!("cargo:rerun-if-changed={}", path.to_string_lossy());
    }
    if let Err(error) = bundle() {
        panic!("building the bundled wabbit-initrd failed: {error}");
    }
    if let Err(error) = bundle_client() {
        panic!("building the bundled wabbit-ipc failed: {error}");
    }
    // This build's stamp: the mtime every file the installer writes
    // will carry (see main.rs's `stamp_installed_files` — the dpkg/rpm
    // convention: installed files show their *build* time, not the
    // install moment, so `ls -l` is consistent with the distro-packaged
    // files around them, and one build's files are identical no matter
    // how many times it is installed). The value changes on every run of
    // this script, and cargo fingerprints rustc-env values, so a fresh
    // bundle always compiles with its own stamp.
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    println!("cargo:rustc-env=WABBIT_INSTALL_BUILD_TIME={seconds}");
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
        "../wabbit-ipc/src",
        "../wabbit-ipc/Cargo.toml",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    Ok(())
}

/// Build the `wabbit-ipc` client the same way as the wabbit-initrd
/// bundle: a private nested musl build, the binary copied into `OUT_DIR`
/// for `include_bytes!`. The client is a leaf crate (wabbit-common plus
/// small std dependencies), so its nested build is quick — and it
/// inherits the environment, so a branded or key-rotated build bundles a
/// client to match.
fn bundle_client() -> Result<(), String> {
    let target = bundle_target();
    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|error| error.to_string())?);
    let target_dir = out_dir.join("wabbit-ipc-bundle-build");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .arg("build")
        .arg("--package=wabbit-ipc")
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
        return Err(format!("the nested wabbit-ipc build failed: {status}"));
    }

    let built = target_dir.join(&target).join("release").join("wabbit-ipc");
    let blob = out_dir.join("wabbit-ipc-blob");
    fs::copy(&built, &blob).map_err(|error| format!("copying the client into OUT_DIR: {error}"))?;
    Ok(())
}
