# Vendored `aya-build` (fork)

`aya-build` builds the eBPF objects this workspace embeds: `wabbit/build.rs`
and `wabbit-initrd/build.rs` call `aya_build::build_ebpf` to compile
`wabbit-ebpf` and `bnuuy` for `bpfel-unknown-none`, and it copies the finished
objects into `OUT_DIR` for `include_bytes!`.

This is a verbatim copy of [`aya-build`][crates] 0.2.0
(<https://github.com/aya-rs/aya>, MIT OR Apache-2.0, © Aya Contributors) with
one patch, marked `PATCH(wabbit)` in the source, in two hunks:

1. `build_ebpf` reads `AYA_BUILD_EXTRA_RUSTFLAGS` (\x1f-separated, same
   encoding as `CARGO_ENCODED_RUSTFLAGS`) and appends its entries to the
   `CARGO_ENCODED_RUSTFLAGS` it constructs for the nested eBPF cargo.
2. The matching `rerun-if-env-changed` for that variable.

## Why a fork, and why this shape

The build host's paths reach the eBPF objects' `.BTF` string tables through the
line info bpf-linker derives from the DWARF rustc emits — `debug = 2` is
load-bearing there, and the objects are embedded in the distributed binaries.
The natural fix is `--remap-path-prefix` on the rustc invocations that produce
that DWARF.

But this crate is the *only* thing that controls those invocations: it
constructs `CARGO_ENCODED_RUSTFLAGS` itself, and cargo resolves
`CARGO_ENCODED_RUSTFLAGS` ahead of both `RUSTFLAGS` and every config rustflags
section — verified empirically on this toolchain — so nothing set outside this
crate can add a flag to the nested build. The fork keeps the flag construction
in aya's own source (loud failure, visible diff against upstream) instead of
rewriting `.BTF` bytes post-link or duplicating the nested-cargo logic.

The callers (the two `build.rs` scripts) set the env var to a computed list of
`--remap-path-prefix` flags derived from the actual build host
(`CARGO_MANIFEST_DIR`, `CARGO_HOME`/`HOME`, `RUSTUP_HOME`, each in both its
`$HOME`-spelled and canonical forms), so the fork itself stays free of
wabbit-specific paths.

Upgrades: re-vendor from crates.io, re-apply the patch, and diff against
upstream — the vendored `Cargo.toml` is kept identical to the registry one.

[crates]: https://crates.io/crates/aya-build