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
#   test <distro>    up → lsm=bpf → reboot → run wabbit-initrd → wabbit
#                    → decode the bnuuy sign → down
#   deploy <distro>  up → wabbit-install (hooks, lsm=bpf, initramfs rebuild)
#                    → reboot into the real boot chain → watch the console
#                    for wabbit → down
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
# The installer: musl as well — the lab's build host glibc is newer than
# every guest's, and a glibc-linked binary would refuse to run there. Its
# build script bundles the whole chain (the musl wabbit-initrd artifact,
# which embeds wabbit and bnuuy), so building it refreshes everything.
installer="${WABBIT_LAB_INSTALLER:-$repo/target/x86_64-unknown-linux-musl/release/wabbit-install}"

require_artifact() {
  if [[ ! -x "$artifact" ]]; then
    echo "missing $artifact" >&2
    echo "run ./vm/build-artifact.sh first" >&2
    exit 1
  fi
}

require_installer() {
  # Build (or refresh) the installer: cargo's own freshness check decides
  # whether anything needs rebuilding — the build script watches every
  # source that feeds the bundle, so an unconditional build is a no-op when
  # fresh and a rebuild when not. A stale-but-present binary must never be
  # uploaded just because it exists.
  echo "building $installer (its build script bundles the whole chain)"
  cargo build --locked --release --target x86_64-unknown-linux-musl -p wabbit-install
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
  # poll then blocks — nothing mounts /sysroot in a booted system — unless
  # the harness presents the live root there, which it does: a bind of /
  # at /sysroot satisfies the poll's own rules (a root at a known mount
  # point, then the nested mounts its fstab announces, then a few quiet
  # polls), so the run proceeds through the real launch path — the second
  # freeze, cgroup2, the memfd wabbit — and wabbit itself gets tested on
  # every distro, not just its protector.
  #
  # The success state has no ssh in it: a started wabbit parks waiting for
  # Ctrl-C, wabbit-initrd babysits it with the world FROZEN (the documented
  # design until the handoff step exists), and the freeze stops the guest's
  # timeout(1) and sshd with it. Nothing guest-side can end the run, so the
  # runner sends wabbit-initrd's output to /dev/console and the host
  # follows the qemu serial console, which drains no matter what the guest
  # does. PASS = the console shows wabbit-initrd's phases and wabbit's
  # parking marker; the teardown destroys the VM (and with it the frozen
  # world — nothing else can).
  #
  # The failure paths thaw (the Drop backstop or the watchdog resume the
  # world when wabbit-initrd exits), so the host polls for the exit marker
  # over ssh too and pulls the sign and the full log out for the verdict.
  local seconds="${WABBIT_LAB_TEST_TIMEOUT:-30}"
  local distro="$1" dir console deadline status
  dir="$(run_dir "$distro")"
  console="$dir/console.log"
  deadline=$((seconds + 120))

  # Artifact in (over ssh; /root is never mounted noexec, unlike some /tmp).
  vm_ssh "$distro" 'sudo tee /root/wabbit-initrd >/dev/null' <"$artifact"
  vm_ssh "$distro" 'sudo chmod 700 /root/wabbit-initrd && test -x /root/wabbit-initrd'

  # Present the live root at /sysroot so the sysroot poll completes (see
  # above). The bind exposes the fstab the poll reads for its nested-mount
  # expectations, so nothing else is needed.
  vm_ssh "$distro" 'sudo mkdir -p /sysroot && sudo mount --bind / /sysroot'

  # The runner is detached (setsid) so the freeze of the launching session
  # cannot take it with it. wabbit-initrd's output goes to the console —
  # the one channel the host can still read once the world freezes — and
  # the exit marker to guest tmpfs, for the thawed failure paths.
  # RUST_LOG=info, not debug: wabbit inherits it, and its guard tracepoint
  # logs per-syscall at debug — a 30-second window at debug floods the log
  # with every syscall on every cpu.
  vm_ssh "$distro" 'sudo tee /root/run-winit.sh >/dev/null' <<EOF
#!/bin/sh
mkdir -p /run/wabbit
RUST_LOG=info timeout --signal=TERM --kill-after=10 $seconds /root/wabbit-initrd \\
  >/dev/console 2>&1
echo \$? > /run/wabbit/exit-status
EOF
  vm_ssh "$distro" \
    'sudo setsid sh /root/run-winit.sh >/dev/null 2>&1 & echo launched'

  while :; do
    if grep -q "Waiting for Ctrl-C" "$console" 2>/dev/null; then
      echo "=== the run as seen on the serial console ==="
      grep -nE "\[wabbit |Waiting for Ctrl-C" "$console" | tail -30 || true
      echo "PASS: wabbit started and parked (world frozen by design until teardown)"
      return 0
    fi
    if status=$(vm_ssh "$distro" \
        'test -f /run/wabbit/exit-status && cat /run/wabbit/exit-status' \
        2>/dev/null); then
      break
    fi
    sleep 3
    deadline=$((deadline - 3))
    if [ "$deadline" -le 0 ]; then
      echo "the run reached neither a parked wabbit nor an exit within its window; console said:"
      grep -nE "\[wabbit |failed|Waiting for Ctrl-C" "$console" | tail -25 || true
      return 1
    fi
  done

  # Thawed exit: wabbit did not park (or never started). Pull everything
  # the ssh path can reach — the sign explains every failure — and fail.
  vm_ssh "$distro" 'sudo cat /run/bnuuy.bin' >"$dir/bnuuy.bin" || true
  echo "=== the bnuuy sign, as read by the host ==="
  if [ -s "$dir/bnuuy.bin" ]; then
    decode_sign "$dir/bnuuy.bin"
  else
    echo "(no sign was left: wabbit-initrd exited clean, or hung before writing one)"
  fi
  echo "=== the run as seen on the serial console ==="
  grep -nE "\[wabbit |failed" "$console" | tail -30 || true
  echo "wabbit-initrd exit code: $status"
  echo "FAIL: wabbit never parked; see the sign and console above"
  return 1
}

# Decode a bnuuy sign file: magic "BNUY", u16 LE version, then records of
# {u64 LE ms since boot, u8 kind, u32 LE length, UTF-8 text}.
decode_sign() {
  python3 - "$1" <<'PY'
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
}

test_distros=(noble jammy bookworm rocky)
[[ $(uname -m) == x86_64 ]] || { echo "the lab is x86_64-only for now" >&2; exit 1; }

# The real deployment flow: install through wabbit-install — the distro's
# own initramfs extension points, the lsm=bpf enrollment, the initramfs
# rebuild — then reboot and watch the boot chain run for real.
#
# The second boot never finishes: wabbit-initrd babysits wabbit with the
# world frozen and the pre-switch wait holds the init there, which is the
# documented choreography until the handoff step exists. So the guest
# answers no ssh during the test (sshd is frozen; the boot never reaches
# it anyway) — the host follows the serial console instead, which qemu
# drains into a host-side file no matter what the guest does. winit's log
# lines and wabbit's printlns land there; the bnuuy sign itself lives in
# the initramfs /run and cannot be retrieved, but every phase it records
# is also logged at info.
deploy() {
  # The EXIT trap fires at script exit — long after this function has
  # returned and its locals have died — so `distro` must be the global,
  # or `down "$distro"` fails as "unbound variable" and the VM is never
  # torn down (the frozen world leaks until the qemu process is killed by
  # hand).
  distro="$1"
  local dir console
  dir="$(run_dir "$distro")"
  require_installer

  up "$distro"
  trap 'down "$distro"' EXIT

  # The installer places everything through the distro's own tooling —
  # this is the flow a real deployment uses, which is the point: `test`
  # proves the protections, this proves the placement.
  vm_ssh "$distro" 'cat > /tmp/wabbit-install' <"$installer"
  vm_ssh "$distro" 'chmod 700 /tmp/wabbit-install'
  vm_ssh "$distro" 'sudo /tmp/wabbit-install'

  # The test boot. The connection drops mid-reboot; the qemu process and
  # its serial file persist across the guest reboot.
  vm_ssh "$distro" 'sudo reboot' 2>/dev/null || true
  echo "rebooted into the protected boot chain; watching the console"

  console="$dir/console.log"
  local deadline="${WABBIT_LAB_DEPLOY_TIMEOUT:-300}" waited=0
  while :; do
    if grep -q "wabbit-initrd failed:" "$console" 2>/dev/null; then
      echo "=== the boot chain as seen on the console ==="
      grep -nE "\[wabbit |wabbit-initrd failed" "$console" | tail -25 || true
      echo "FAIL: wabbit-initrd failed during the boot chain on $distro"
      keep=1
      down "$distro" || true
      exit 1
    fi
    if grep -q "Waiting for Ctrl-C" "$console" 2>/dev/null; then
      echo "=== the boot chain as seen on the console ==="
      grep -nE "\[wabbit |Waiting for Ctrl-C" "$console" | tail -25 || true
      echo "PASS: $distro booted installer → initramfs hooks → wabbit-initrd → wabbit (running, world frozen by design)"
      break
    fi
    if [ "$waited" -ge "$deadline" ]; then
      echo "the boot chain never reached wabbit within ${deadline}s; the console said:"
      grep -nE "\[wabbit |bnuuy|failed|Waiting for Ctrl-C" "$console" | tail -25 || true
      echo "FAIL: the protected boot chain did not reach wabbit on $distro"
      keep=1
      down "$distro" || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

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
  sign) decode_sign "${1:?sign file}" ;;
  test)
    distro="${1:?distro}"
    require_artifact
    up "$distro"
    trap 'down "$distro"' EXIT
    enable_bpf_lsm "$distro"
    echo "=== running wabbit-initrd and wabbit in the VM (wabbit parks with the world frozen; teardown ends it) ==="
    # Ground truth for the tracepoint record layout the fork watcher reads:
    # the kernel's own field offsets for sched_process_fork (tracefs is
    # root-only, so the read itself needs sudo too). wabbit's guard
    # tracepoint needs tracefs mounted as well — aya reads the event id
    # from there when attaching.
    vm_ssh "$distro" 'sudo mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true
      sudo cat /sys/kernel/tracing/events/sched/sched_process_fork/format' || true
    if run_test "$distro"; then
      echo "PASS: $distro — bnuuy attached and verified, wabbit started and parked"
    else
      # A real assignment, not a command prefix: the EXIT trap's `down` must
      # also see it, or the state meant for inspection gets deleted.
      keep=1
      down "$distro" || true
      exit 1
    fi
    ;;
  deploy) deploy "${1:?distro}" ;;
  *) echo "usage: lab.sh {fetch|up|ssh|down|test|deploy|sign|clean} <distro>" >&2; exit 1 ;;
esac