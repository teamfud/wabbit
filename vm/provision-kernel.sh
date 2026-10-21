#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

export DEBIAN_FRONTEND=noninteractive

case "$(uname -s)" in
  Linux) ;;
  *) echo "wabbit kernel VMs require Linux" >&2; exit 1 ;;
esac

install_debian() {
  apt-get update -qq
  apt-get install -y -qq \
    bpftool bpftrace build-essential clang llvm \
    linux-headers-"$(uname -r)" linux-tools-"$(uname -r)" \
    pkg-config sudo >/dev/null || {
      apt-get install -y -qq \
        bpftool bpftrace build-essential clang llvm \
        linux-headers-generic linux-tools-generic \
        pkg-config sudo >/dev/null
    }
}

install_rhel() {
  dnf install -y \
      bpftool bpftrace clang elfutils-libelf-devel llvm \
      kernel-devel-"$(uname -r)" kernel-headers \
      pkgconf-pkg-config sudo >/dev/null || {
      dnf install -y \
        bpftool bpftrace clang elfutils-libelf-devel llvm \
        kernel-devel kernel-headers \
        pkgconf-pkg-config sudo >/dev/null
    }
}

if command -v apt-get >/dev/null; then
  install_debian
elif command -v dnf >/dev/null; then
  install_rhel
else
  echo "unsupported Linux distribution: package manager not found" >&2
  exit 1
fi

if [[ ! -s /sys/kernel/btf/vmlinux ]]; then
  echo "kernel BTF is unavailable at /sys/kernel/btf/vmlinux" >&2
  echo "use a box kernel built with CONFIG_DEBUG_INFO_BTF=y" >&2
  exit 1
fi

install -m 0755 /tmp/wabbit /usr/local/bin/wabbit
rm -f /tmp/wabbit

echo
echo "wabbit kernel VM ready"
echo "  artifact: /usr/local/bin/wabbit"
echo "  kernel: $(uname -r)"
echo "  BTF: /sys/kernel/btf/vmlinux"
echo "  bpftrace: $(bpftrace --version 2>/dev/null || echo unavailable)"
