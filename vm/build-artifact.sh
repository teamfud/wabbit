#!/usr/bin/env bash
set -euo pipefail

case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-gnu ;;
  aarch64|arm64) target=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac

if ! command -v cargo >/dev/null || ! command -v bpf-linker >/dev/null; then
  echo "cargo and bpf-linker are required on the build host" >&2
  exit 1
fi

rustup target add "$target"
cargo build --locked --release --target "$target" -p wabbit
echo "built target/$target/release/wabbit"
