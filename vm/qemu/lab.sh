#!/usr/bin/env bash
# wabbit kernel VM lab — QEMU with KVM, no root required.
#
# The host runs everything unprivileged: cloud images are cached once, each
# run boots a throwable overlay (the cached image is never modified), the
# artifact reaches the guest over ssh, and wabbit-initrd's sign is copied
# back over ssh before the VM is destroyed. (An earlier design carried both
# through a 9p share — elegant, because qemu drains it even while the guest
# world is frozen — but RHEL-family kernels ship no 9p modules at all, so
# the share could never work on rocky. ssh works everywhere; while the guest
# world is frozen the polls just fail fast on ConnectTimeout, which the
# host-side deadline already tolerates.)
#
# usage: lab.sh <command> [args]
#   fetch <distro>   download the cloud image into the cache (once)
#   up <distro>      boot a fresh VM (KVM) and wait for ssh
#   ssh <distro>     open a shell in the running VM
#   down <distro>    stop the VM and delete its throwaway disks
#   test <distro>    up → lsm=bpf → reboot → run wabbit-initrd → 
#                    decode the bnuuy sign → down
#   sign <file>      decode a bnuuy sign file
#   clean            delete all run state (cached images are kept)
#
# distros: noble (Ubuntu 24.04), jammy (Ubuntu 22.04),
#          bookworm (Debian 12), rocky (Rocky 9)
#
# Disk frugality: images are cached sparse (~0.3–1 GB each, downloaded only
# on first use); overlays are deleted on `down`. Boot one VM at a time.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache="${WABBIT_LAB_CACHE:-$repo/vm/qemu/cache}"
state="${WABBIT_LAB_STATE:-/tmp/opencode/wabbit-lab}"
keep="${WABBIT_LAB_KEEP:-0}"
ssh_key="${WABBIT_LAB_SSH_KEY:-$HOME/.ssh/id_ed25519.pub}"

# distro → image url | ssh user | ssh port
noble_url="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
jammy_url="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
bookworm_url="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
rocky_url="https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"

image_url() {
  case "$1" in
    noble) echo "$noble_url" ;;
    jammy) echo "$jammy_url" ;;
    bookworm) echo "$bookworm_url" ;;
    rocky) echo "$rocky_url" ;;
    *) echo "unknown distro '$1' (noble, jammy, bookworm, rocky)" >&2; return 1 ;;
  esac
}

image_user() {
  case "$1" in
    noble|jammy) echo ubuntu ;;
    bookworm) echo debian ;;
    rocky) echo rocky ;;
  esac
}

image_port() {
  case "$1" in
    noble) echo 2221 ;;
    jammy) echo 2222 ;;
    bookworm) echo 2223 ;;
    rocky) echo 2224 ;;
  esac
}

image_file() { echo "$cache/images/$1.qcow2"; }
run_dir() { echo "$state/$1"; }
vm_ssh() {
  local distro="$1"; shift
  ssh -o StrictHostKeyChecking=accept-new \
      -o "UserKnownHostsFile=$(run_dir "$distro")/known_hosts" \
      -o ConnectTimeout=5 \
      -p "$(image_port "$distro")" "$(image_user "$distro")@127.0.0.1" "$@"
}

artifact="${WABBIT_LAB_ARTIFACT:-$repo/target/x86_64-unknown-linux-musl/release/wabbit-initrd}"

require_artifact() {
  if [[ ! -x "$artifact" ]]; then
    echo "missing $artifact" >&2
    echo "run ./vm/build-artifact.sh first" >&2
    exit 1
  fi
}

fetch() {
  local distro="$1" url file
  url="$(image_url "$distro")"
  file="$(image_file "$distro")"
  mkdir -p "$(dirname "$file")"
  if [[ -f "$file" ]]; then
    echo "$distro image already cached: $file"
    return
  fi
  echo "downloading $distro cloud image (cached once; later runs are offline)"
  curl --fail --continue-at - --location --progress-bar --output "$file.partial" "$url"
  mv "$file.partial" "$file"
  qemu-img info "$file" | head -3
}

make_seed() {
  # cloud-init NoCloud seed: a vfat volume labeled "cidata" holding
  # user-data and meta-data. Injecting into a filesystem image without
  # mounting takes mtools — host-installed if available, rootless podman
  # otherwise.
  local distro="$1" dir
  dir="$(run_dir "$distro")"
  mkdir -p "$dir"
  {
    echo "#cloud-config"
    echo "ssh_pwauth: false"
    echo "ssh_authorized_keys:"
    echo "  - $(cat "$ssh_key")"
  } >"$dir/user-data"
  {
    echo "instance-id: wabbit-$distro-1"
    echo "local-hostname: wabbit-$distro"
  } >"$dir/meta-data"

  if command -v mcopy >/dev/null 2>&1; then
    rm -f "$dir/seed.vfat"
    dd if=/dev/zero of="$dir/seed.vfat" bs=1M count=1 status=none
    mformat -i "$dir/seed.vfat" -v cidata ::
    mcopy -i "$dir/seed.vfat" "$dir/user-data" ::user-data
    mcopy -i "$dir/seed.vfat" "$dir/meta-data" ::meta-data
    echo "seed ok (host mtools):"
    mdir -i "$dir/seed.vfat" ::
  else
    podman run --rm \
      --volume "$dir:/seed:Z" \
      docker.io/library/alpine:latest \
      sh -c 'set -e
             apk add --quiet mtools
             rm -f /seed/seed.vfat
             dd if=/dev/zero of=/seed/seed.vfat bs=1M count=1 status=none
             mformat -i /seed/seed.vfat -v cidata ::
             mcopy -i /seed/seed.vfat /seed/user-data ::user-data
             mcopy -i /seed/seed.vfat /seed/meta-data ::meta-data
             echo "seed ok (podman mtools):"
             mdir -i /seed/seed.vfat ::'
  fi
}

up() {
  local distro="$1" dir image port
  require_artifact
  fetch "$distro"
  dir="$(run_dir "$distro")"
  image="$(image_file "$distro")"
  port="$(image_port "$distro")"
  if [[ -f "$dir/qemu.pid" ]] && kill -0 "$(cat "$dir/qemu.pid")" 2>/dev/null; then
    echo "$distro VM already running (pid $(cat "$dir/qemu.pid"))"
    return
  fi
  mkdir -p "$dir"
  # Every fresh overlay boots a machine with brand-new host keys, so the
  # known-hosts entry of the previous run must go with it: `accept-new`
  # tolerates an unknown key but rejects a changed one.
  rm -f "$dir/console.log" "$dir/qemu.pid" "$dir/known_hosts" "$dir/overlay.qcow2"

  # Throwaway overlay: the cached image is never written to.
  qemu-img create -f qcow2 -F qcow2 -b "$image" "$dir/overlay.qcow2" >/dev/null
  make_seed "$distro"

  # KVM on a bare-metal host; fall back to TCG if /dev/kvm is absent.
  local accel=kvm
  [[ -w /dev/kvm ]] || accel=tcg

  qemu-system-x86_64 \
    -machine "accel=$accel" -cpu host -smp 2 -m 2048 \
    -drive file="$dir/overlay.qcow2",if=virtio,format=qcow2,cache=writeback \
    -drive file="$dir/seed.vfat",if=virtio,format=raw,readonly=on \
    -device virtio-rng-pci \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none -monitor none -serial "file:$dir/console.log" \
    -pidfile "$dir/qemu.pid" -daemonize
  echo "$distro VM booting (accel=$accel, ssh port $port); console: $dir/console.log"

  wait_ssh "$distro"
}

wait_ssh() {
  local distro="$1" tries=0
  echo "waiting for ssh..."
  until vm_ssh "$distro" true 2>/dev/null; do
    tries=$((tries + 1))
    if [[ $tries -ge 60 ]]; then
      echo "ssh never came up; check $(run_dir "$distro")/console.log" >&2
      exit 1
    fi
    sleep 5
  done
  vm_ssh "$distro" 'uname -r && cat /etc/os-release | head -2'
}

down() {
  local distro="$1" dir
  dir="$(run_dir "$distro")"
  if [[ -f "$dir/qemu.pid" ]]; then
    kill "$(cat "$dir/qemu.pid")" 2>/dev/null || true
    rm -f "$dir/qemu.pid"
  fi
  if [[ "$keep" == 1 ]]; then
    echo "keeping $dir (WABBIT_LAB_KEEP=1); delete it with 'lab.sh clean'"
    return
  fi
  rm -rf "$dir"
  echo "$distro VM stopped and its disks deleted (cached image kept)"
}

enable_bpf_lsm() {
  # The BPF LSM must be in the kernel's LSM boot list or no LSM hook — and
  # therefore none of bnuuy — can attach. No target distro enables it by
  # default.
  #
  # The command line is set three ways in the wild: BLS kernels via grubby
  # (Rocky), and grub-mkconfig via /etc/default/grub — where cloud images
  # keep their arguments in a numbered drop-in that overrides the main
  # file's value. A LATER drop-in appending to the variable wins over
  # 50-cloudimg-settings.cfg without having to know what it says.
  vm_ssh "$distro" 'set -e
    if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
      echo "bpf LSM already active"
      exit 0
    fi
    if command -v grubby >/dev/null 2>&1; then
      sudo grubby --update-kernel=ALL --args="lsm=bpf"
    elif [ -d /etc/default/grub.d ]; then
      printf "%s\n" \
        "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT lsm=bpf\"" \
        "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX lsm=bpf\"" \
        | sudo tee /etc/default/grub.d/99-wabbit-lsm.cfg >/dev/null
      sudo update-grub
    else
      sudo sed -i '\''s/^GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="lsm=bpf /'\'' /etc/default/grub
      sudo update-grub
    fi
    echo "rebooting for lsm=bpf"'
  vm_ssh "$distro" 'sudo reboot' 2>/dev/null || true
  sleep 30
  wait_ssh "$distro"
  vm_ssh "$distro" 'if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
      echo "bpf LSM active: $(cat /sys/kernel/security/lsm)"
    else
      echo "lsm=bpf did not take effect:" >&2
      echo "  cmdline: $(cat /proc/cmdline)" >&2
      echo "  lsm list: $(cat /sys/kernel/security/lsm 2>&1)" >&2
      exit 1
    fi'
}

run_test() {
  # Run wabbit-initrd in a booted system, with nothing about the harness
  # depending on the session it freezes.
  #
  # The world freezes during bnuuy setup and thaws right after; the sysroot
  # poll then blocks forever (nothing mounts /sysroot in a booted system),
  # so the run is bounded by timeout(1) — exit 124 is the expected outcome,
  # not a failure. The freeze takes the ssh session that started the run
  # with it, so the process must be detached (setsid) with its output going
  # to a guest-local file, and the host polls for the exit marker over ssh.
  # While the guest world is frozen, sshd is frozen too, so a poll just
  # fails fast (ConnectTimeout) until the world thaws — the freeze is
  # brief, and a winit that never thaws is caught by the host-side deadline
  # below, after which the VM is destroyed (a truly hung run leaves its
  # evidence in console.log; every other outcome's sign is copied out
  # first).
  #
  # The window must also stay short: from the moment verification passes
  # until the timeout kills the process, bnuuy denies every bpf(2) call in
  # the system except wabbit-initrd's own — by design — and a live systemd
  # host only tolerates that for so long (udevd's watchdog limit is three
  # minutes). Verification completes in a couple of seconds, so the default
  # leaves ample margin.
  local seconds="${WABBIT_LAB_TEST_TIMEOUT:-30}"
  local dir deadline
  dir="$(run_dir "$distro")"
  deadline=$((seconds + 90))

  # Artifact in (over ssh; /root is never mounted noexec, unlike some /tmp).
  vm_ssh "$distro" 'sudo tee /root/wabbit-initrd >/dev/null' <"$artifact"
  vm_ssh "$distro" 'sudo chmod 700 /root/wabbit-initrd && test -x /root/wabbit-initrd'

  # The runner is detached (setsid) so the freeze of the launching session
  # cannot take it with it, and writes the exit marker to guest tmpfs after
  # winit exits and the Drop backstop thaws whatever it froze. The sign goes
  # to /run, which needs no setup and dies with the VM — the host copies it
  # out below.
  vm_ssh "$distro" 'sudo tee /root/run-winit.sh >/dev/null' <<EOF
#!/bin/sh
mkdir -p /run/wabbit
RUST_LOG=debug timeout --signal=TERM --kill-after=10 $seconds /root/wabbit-initrd \\
  > /run/wabbit/winit.log 2>&1
echo \$? > /run/wabbit/exit-status
EOF
  vm_ssh "$distro" \
    'sudo setsid sh /root/run-winit.sh >/dev/null 2>&1 & echo launched'

  local status=""
  while :; do
    if status=$(vm_ssh "$distro" \
        'test -f /run/wabbit/exit-status && cat /run/wabbit/exit-status' \
        2>/dev/null); then
      break
    fi
    sleep 3
    deadline=$((deadline - 3))
    if [ "$deadline" -le 0 ]; then
      echo "wabbit-initrd did not finish within its window; hung without resuming?"
      echo "log so far (empty if the world is still frozen):"
      vm_ssh "$distro" 'sudo cat /run/wabbit/winit.log 2>/dev/null' || true
      return 1
    fi
  done

  vm_ssh "$distro" 'sudo cat /run/wabbit/winit.log' >"$dir/winit.log" || true
  vm_ssh "$distro" 'sudo cat /run/bnuuy.bin' >"$dir/bnuuy.bin" || true
  cat "$dir/winit.log"
  echo "wabbit-initrd exit code: $status (124 = timed out in the sysroot poll, expected)"
}

test_distros=(noble jammy bookworm rocky)
[[ $(uname -m) == x86_64 ]] || { echo "the lab is x86_64-only for now" >&2; exit 1; }

command="${1:-}"; shift || true
case "$command" in
  fetch) fetch "${1:?distro}" ;;
  up) up "${1:?distro}" ;;
  ssh)
    distro="${1:?distro}"
    exec ssh -o StrictHostKeyChecking=accept-new \
      -o "UserKnownHostsFile=$(run_dir "$distro")/known_hosts" \
      -t -p "$(image_port "$distro")" "$(image_user "$distro")@127.0.0.1"
    ;;
  down) down "${1:?distro}" ;;
  clean) rm -rf "$state"; echo "run state deleted; cached images kept in $cache" ;;
  sign) python3 - "$@" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
assert data[:4] == b'BNUY', 'not a bnuuy sign'
kinds = {0: 'doc', 1: 'phase', 2: 'failure', 3: 'watchdog', 4: 'panic'}
off = 6
while off < len(data):
    ts, kind, length = struct.unpack_from('<QBI', data, off); off += 13
    print(f'[{ts:>8} ms] {kinds.get(kind, kind):>8}: {data[off:off+length].decode()}')
    off += length
PY
  ;;
  test)
    distro="${1:?distro}"
    up "$distro"
    trap 'down "$distro"' EXIT
    enable_bpf_lsm "$distro"
    # (The artifact upload and sign retrieval both live inside run_test.)
    echo "=== running wabbit-initrd in the VM (bounded by a ${WABBIT_LAB_TEST_TIMEOUT:-30}s window, killed at its end by design) ==="
    # Ground truth for the tracepoint record layout the fork watcher reads:
    # the kernel's own field offsets for sched_process_fork (tracefs is
    # root-only, so the read itself needs sudo too).
    vm_ssh "$distro" 'sudo mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true
      sudo cat /sys/kernel/tracing/events/sched/sched_process_fork/format' || true
    run_test "$distro" || true
    echo "=== the bnuuy sign, as read by the host ==="
    if [ ! -s "$(run_dir "$distro")/bnuuy.bin" ]; then
      echo "(no sign was retrieved: wabbit-initrd hung before writing one, or exited clean)"
    else
    python3 - "$(run_dir "$distro")/bnuuy.bin" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
assert data[:4] == b'BNUY', 'not a bnuuy sign'
kinds = {0: 'doc', 1: 'phase', 2: 'failure', 3: 'watchdog', 4: 'panic'}
off = 6
while off < len(data):
    ts, kind, length = struct.unpack_from('<QBI', data, off); off += 13
    print(f'[{ts:>8} ms] {kinds.get(kind, kind):>8}: {data[off:off+length].decode()}')
    off += length
PY
    fi
    echo "=== verdict ==="
    if grep -q "bnuuy protections attached and verified" "$(run_dir "$distro")/bnuuy.bin" 2>/dev/null; then
      echo "PASS: bnuuy attached and verified on $distro"
    else
      echo "FAIL: see the sign above and $(run_dir "$distro")/console.log"
      # A real assignment, not a command prefix: the EXIT trap's `down` must
      # also see it, or the state meant for inspection gets deleted.
      keep=1
      down "$distro" || true
      exit 1
    fi
    ;;
  *) echo "usage: lab.sh {fetch|up|ssh|down|test|sign|clean} <distro>" >&2; exit 1 ;;
esac