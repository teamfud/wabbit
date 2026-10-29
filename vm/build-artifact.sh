#!/usr/bin/env bash
# Build the host artifact the VM lab consumes: the wabbit-initrd executable,
# statically linked for musl so it runs on every target distro (whose glibc
# may be older than the build host's) and in any initramfs (which has no
# glibc at all). It is self-contained: it embeds the wabbit binary and the
# bnuuy eBPF object at build time.
set -euo pipefail

case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-musl ;;
  aarch64|arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac

if ! command -v cargo >/dev/null || ! command -v bpf-linker >/dev/null; then
  echo "cargo and bpf-linker are required on the build host" >&2
  exit 1
fi

rustup target add "$target"
# Both artifacts: `test` consumes the wabbit-initrd executable directly,
# `deploy` consumes the wabbit-install installer (which bundles its own
# wabbit-initrd). One command refreshes the whole chain — wabbit-initrd
# embeds the wabbit binary (guard included) and the bnuuy eBPF object, and
# wabbit-install bundles wabbit-initrd.
cargo build --locked --release --target "$target" -p wabbit-initrd
cargo build --locked --release --target "$target" -p wabbit-install

artifact="target/$target/release/wabbit-initrd"
installer="target/$target/release/wabbit-install"
echo "built $artifact (test flow)"
echo "built $installer (deploy flow)"
file "$artifact" | head -1
file "$installer" | head -1