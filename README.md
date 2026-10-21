# wabbit

the stupidest blue team rootkit ever

THIS IS FOR EDUCATIONAL USE BY BLUE TEAMS IN REGULATED CTFs ONLY. DO NOT USE THIS TO COMMIT CRIMES. IT WILL BE REALLY BAD AT IT.

NOT an edr




## Prerequisites

1. nightly rust toolchain: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

The workspace Cargo configuration enables rustc's nightly `-Z randomize-layout` option. It
randomizes layouts of ordinary `repr(Rust)` types; explicitly represented FFI layouts such as
`repr(C)` remain stable.

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

The `wabbit-initrd` binary is a small initrd entry point for applying the same
`RootFSConfig` policy without starting the main tracer or IPC server:

```sh
WABBIT_FILESYSTEM_CONFIGURATION_FILE=/etc/wabbit/rootfs.json \
  wabbit-initrd --outer
wabbit-initrd --namespace --inner
```

Use `--outer` before entering a private namespace and `--inner` after entering one. The
`--namespace` option creates and privatizes a mount namespace before applying the inner policy.

Policies can also be stored as a versioned binary file. Set
`WABBIT_FILESYSTEM_CONFIGURATION_FILE` to the file path; files beginning with the `WSPF` magic
are decoded by `wabbit::policy`, while other files retain the JSON fallback. Binary policies
contain an Ed25519 signature over the policy header and payload and are verified against the
compiled-in `policy::POLICY_PUBLIC_KEY`; unsigned policies are rejected. The policy module exposes
`to_signed_bytes`, `from_bytes`, `read_file`, and `write_new_signed` for callers that need to
generate or validate policy files.

When running with `WABBIT_READ_ONLY_PATHS` and `WABBIT_WRITABLE_PATHS` (both JSON arrays of
paths), wabbit exposes a Unix-domain IPC socket to the namespace process. A client can use
`wabbit::ipc::NamespaceIpc::connect(socket_path)` and call `reconfigure_filesystems` with one of
the `RootFSConfig` fields and `PathOverride` entries to describe writable and executable
mounts. `apply_rootfs_config(&config, false)` applies the outer policy, while
`apply_rootfs_config(&config, true)` applies the inner policy after entering a private namespace.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
cargo build --package wabbit --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/wabbit` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, wabbit is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
