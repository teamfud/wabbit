use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // The white-label knobs: the embedded bnuuy object and wabbit binary
    // are compiled by nested cargo runs (which inherit the environment),
    // so a change must rerun this build script to re-invoke them. The
    // policy knobs are in the same position: the embedded wabbit compiles
    // its compiled-in key and bakes its policy from the environment, so a
    // changed `WABBIT_POLICY_PUBLIC_KEY` or `WABBIT_EMBED_POLICY` must
    // rerun the script too — otherwise cargo considers the script fresh,
    // the nested `cargo build --package=wabbit` never re-runs, and the
    // chain silently ships a stale embed from the previous deployment.
    for var in [
        "WABBIT_BRAND_NAME",
        "WABBIT_BRAND_ENV_PREFIX",
        "WABBIT_BRAND_SIGN_NAME",
        "WABBIT_BRAND_SIGN_MAGIC",
        "WABBIT_POLICY_PUBLIC_KEY",
        "WABBIT_EMBED_POLICY",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    // The baked policy file itself can also change *in place* — a
    // deployment re-signs the same path — without its env-var value (the
    // path string) changing at all. The script's output (the nested wabbit
    // it embeds here) depends on that file's content, so declare it.
    if let Some(path) = env::var_os("WABBIT_EMBED_POLICY") {
        println!("cargo:rerun-if-changed={}", path.to_string_lossy());
    }
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
        targets,
        ..
    } = ebpf_package;
    // aya-build copies each of the package's binary targets into OUT_DIR
    // under its own name, and `include_bytes!` embeds that copy — so those
    // are the objects to strip.
    let bins: Vec<&str> = targets
        .iter()
        .filter(|target| target.is_bin())
        .map(|target| target.name.as_str())
        .collect();
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    set_ebpf_remaps()?;
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;
    strip_debug(&bins)?;

    build_wabbit_blob()
}

/// Hand `--remap-path-prefix` flags for this build host to the vendored
/// aya-build fork, so the paths that identify the host never reach the eBPF
/// objects: they land in the `.BTF` string tables through the line info
/// bpf-linker derives from the DWARF of every crate in the nested build —
/// including `core`, compiled locally from rust-src by `-Z build-std`.
///
/// The flags cannot come from cargo: aya-build constructs
/// `CARGO_ENCODED_RUSTFLAGS` for the nested cargo itself, and cargo resolves
/// that variable ahead of both `RUSTFLAGS` and every config rustflags section
/// — verified empirically — so this env var through the fork is the one
/// route in. The userspace builds take their (static) copy from
/// `.cargo/config.toml`.
///
/// Each root is remapped in both spellings this host produces: as the
/// environment spells it (`$HOME`-derived, preserving the `/home` symlink)
/// and as `canonicalize` reports it. The prefixes are disjoint, so the order
/// of the flags does not matter.
fn set_ebpf_remaps() -> anyhow::Result<()> {
    // No threads have been spawned yet: `aya_build::build_ebpf` (which pumps
    // stderr from a thread) has not been called, so mutating the environment
    // cannot race anything.
    unsafe {
        env::set_var("AYA_BUILD_EXTRA_RUSTFLAGS", remap_flags()?.join("\x1f"));
    }
    Ok(())
}

/// The `--remap-path-prefix` flags for the paths that identify this host:
/// the workspace root, the cargo home, and the rustup home.
fn remap_flags() -> anyhow::Result<Vec<String>> {
    const TARGETS: [&str; 3] = ["/build", "/cargo", "/rustup"];

    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .context("reading HOME for the remap prefixes")?;
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .context("reading CARGO_MANIFEST_DIR for the remap prefixes")?,
    );
    let roots = [
        // The workspace root: this build script lives one package deep.
        manifest
            .parent()
            .context("CARGO_MANIFEST_DIR has no parent")?
            .to_owned(),
        env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cargo")),
        env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".rustup")),
    ];

    let mut flags = Vec::new();
    for (root, target) in roots.iter().zip(TARGETS) {
        // Both spellings, deduplicated when they coincide.
        let mut spellings = vec![root.clone()];
        if let Ok(canonical) = root.canonicalize()
            && &canonical != root
        {
            spellings.push(canonical);
        }
        for from in spellings {
            flags.push(format!("--remap-path-prefix={}={target}", from.display()));
        }
    }
    Ok(flags)
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

    // The bnuuy eBPF object is embedded as OUT_DIR/early, so the blob gets
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
        "../wabbit-policy/src",
        "../wabbit-policy/Cargo.toml",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    Ok(())
}

/// Strip the DWARF out of the embedded eBPF objects, after `aya-build`
/// copies them into `OUT_DIR` and before `include_bytes!` embeds them.
///
/// bpf-linker derives `.BTF` — the definitions behind every `#[map]` — and
/// `.BTF.ext` — func/line info, and CO-RE relocations where they exist —
/// from DWARF types, so the `debug = 2` the eBPF profiles pin stays
/// load-bearing at link time. But past the link nothing reads the DWARF:
/// aya-obj parses `.BTF`, `.BTF.ext`, and the symbol table (CO-RE
/// relocations live in `.BTF.ext`, never in DWARF), and the kernel consumes
/// BTF and instructions alone. `llvm-strip --strip-debug` drops only the
/// `.debug_*` sections — the bulk of each object — and leaves `.BTF`,
/// `.BTF.ext`, their relocations, the symbol table, and every instruction
/// byte for byte identical. The `inject` module's relocation machinery —
/// and the unit test that exercises it against this real embedded object —
/// runs on the stripped bytes.
///
/// A missing or failing `llvm-strip` is a warning, never a build failure:
/// an unstripped object loads identically and is merely larger.
fn strip_debug(bins: &[&str]) -> anyhow::Result<()> {
    // aya-build's skip: nothing was copied into OUT_DIR, so there is
    // nothing to strip.
    if let Some(skip) = env::var_os("AYA_BUILD_SKIP")
        && (skip == "1" || skip.eq_ignore_ascii_case("true"))
    {
        return Ok(());
    }
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").context("reading OUT_DIR")?);
    for bin in bins {
        let object = out_dir.join(bin);
        match Command::new("llvm-strip")
            .arg("--strip-debug")
            .arg(&object)
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => println!(
                "cargo:warning=llvm-strip exited {status} on {}; the embedded object keeps its DWARF",
                object.display()
            ),
            Err(err) => {
                println!("cargo:warning=llvm-strip: {err}; the embedded object keeps its DWARF")
            }
        }
    }
    Ok(())
}
