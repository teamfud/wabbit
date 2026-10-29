use std::{env, path::PathBuf, process::Command};

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
    strip_debug(&bins)
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
    unsafe { env::set_var("AYA_BUILD_EXTRA_RUSTFLAGS", remap_flags()?.join("\x1f")) };
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
/// byte for byte identical.
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
