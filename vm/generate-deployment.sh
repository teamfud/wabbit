#!/usr/bin/env bash
# generate-deployment.sh — build a complete wabbit deployment.
#
# Non-interactive: flags in, artifacts out. Builds the CLI, makes or reuses
# a signing keypair, signs the TOML policy source into a WSPF file, builds
# the musl chain with this deployment's public key compiled in, and copies
# the results into one directory:
#
#   policy.key, policy.key.pub   the signing keypair (the SECRET stays here,
#                                never on a target box)
#   policy.toml                  the committed, reviewable policy source
#   policy.wspf                  the signed policy the box loads at boot
#   wabbit-policy                the static musl signing + inspection CLI
#                                (gen-key/build/inspect; runs anywhere)
#   wabbit-initrd                the static musl artifact (embeds wabbit and
#                                bnuuy, verifies against policy.key.pub)
#   wabbit-install               the installer that places the chain through
#                                the distro's own initramfs tooling, and
#                                writes the client tool to the box's bin
#   wabbit-ipc                   the signed-command client for a running
#                                wabbit (run, policy, send)
#
# With --bake the signed policy is additionally baked into the wabbit binary
# (and so into wabbit-initrd and the initramfs image): the first-install
# path, no filesystem footprint on the box. The env-var file
# (<prefix>_FILESYSTEM_CONFIGURATION_FILE, set by `wabbit-install --policy`)
# overrides the baked policy at runtime.
#
# The only file the box needs is `wabbit-install` (plus `policy.wspf` when
# not baked): the installer carries the protector and the client tool inside
# itself, and writes wabbit-ipc to /usr/local/bin during install. Everything
# else — the key, the signing CLI, the client copy for tunneled use —
# belongs on the management host.
#
# Branding: the --brand-* flags set the compile-time white-label knobs of
# wabbit-common/src/brand.rs (WABBIT_BRAND_NAME, _ENV_PREFIX, _SIGN_NAME,
# _SIGN_MAGIC) and export them for this whole build, so the CLI, the musl
# chain, and every nested bundle — the artifact inside the installer, the
# wabbit inside the artifact — come out branded together. The wabbit
# cgroup follows the brand name (and the starter policy's class root with
# it), and so do the box-side names: the /usr/local/bin/<name>-ipc client,
# the <name>-initrd hook, the <prefix>_* environment variables. The
# artifact file names above are the cargo bin names; the --name-* flags
# rename the deployment directory's copies.
#
# usage: vm/generate-deployment.sh [options] [output-dir]
#
#   --source PATH   TOML policy source (default: <out>/policy.toml)
#                   signed into <out>/policy.wspf when it exists
#   --bake          bake the signed policy into the wabbit binary
#   --key PATH      reuse this private key (default: <out>/policy.key,
#                   generated when missing; its .pub must sit beside it)
#   --brand-name NAME         the product name (default: wabbit) — argv[0],
#                             the cgroup, the IPC socket, the in-image paths
#   --brand-env-prefix PREFIX the env var prefix (default: WABBIT)
#   --brand-sign-name NAME    the boot sign file name (default: bnuuy)
#   --brand-sign-magic MAGIC  the boot sign magic, exactly four printable
#                             bytes (default: BNUY)
#   --name-policy NAME  the signing CLI's file name in <out> (default:
#                       wabbit-policy)
#   --name-initrd NAME  the artifact's file name in <out> (default:
#                       wabbit-initrd)
#   --name-install NAME the installer's file name in <out> (default:
#                       wabbit-install)
#   --name-ipc NAME     the client's file name in <out> (default: wabbit-ipc)
#
#   The --name-* renames govern the deployment directory's copies only: the
#   musl builds under target/release/ keep their cargo bin names, and every
#   box-side path comes from the brand.
#
# example:
#   vm/generate-deployment.sh --bake deployments/foo
#   # writes deployments/foo/{policy.key,policy.key.pub,policy.toml→wspf,
#   #                        wabbit-policy,wabbit-initrd,wabbit-install,
#   #                        wabbit-ipc}
#   vm/generate-deployment.sh --bake --brand-name corvid deployments/corvid
#   # a white-label deployment: every box-side name (the cgroup, the
#   # <name>-initrd hook, the /usr/local/bin/<name>-ipc client) says corvid
#
# Requires gum (devenv ships it), cargo, and bpf-linker for the eBPF builds.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="x86_64-unknown-linux-musl"
policy_cli="$repo/target/release/wabbit-policy"

out="deployments/wabbit"
source=""
bake=no
key=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) source=$2; shift 2 ;;
    --bake) bake=yes; shift ;;
    --key) key=$2; shift 2 ;;
    --brand-name) brand_name=$2; shift 2 ;;
    --brand-env-prefix) brand_env_prefix=$2; shift 2 ;;
    --brand-sign-name) brand_sign_name=$2; shift 2 ;;
    --brand-sign-magic) brand_sign_magic=$2; shift 2 ;;
    --name-policy) name_policy=$2; shift 2 ;;
    --name-initrd) name_initrd=$2; shift 2 ;;
    --name-install) name_install=$2; shift 2 ;;
    --name-ipc) name_ipc=$2; shift 2 ;;
    -h|--help) sed -n '2,80p' "$0"; exit 0 ;;
    *) out=$1; shift ;;
  esac
done

die() { printf '%s\n' "$(gum style --foreground 203 "✗ $*")" >&2; exit 1; }
say() { printf '%s\n' "$(gum style --bold --foreground 212 "▸ $*")"; }

mkdir -p "$out"
out=$(cd "$out" && pwd)
source="${source:-$out/policy.toml}"
key="${key:-$out/policy.key}"

# Branding: the white-label knobs of wabbit-common/src/brand.rs, as flags.
# The values are validated here the way brand.rs validates them at compile
# time — each one path- and shell-safe component, the magic exactly four
# printable bytes — so a typo dies with a clear message instead of failing
# a nested build halfway down the chain. Exported, they ride every build
# below: the CLI here on the host, and the whole musl chain through
# build-artifact.sh, whose nested builds (the installer's bundles, the
# artifact's embedded wabbit) inherit the environment.

brand_name=${brand_name:-wabbit}
brand_env_prefix=${brand_env_prefix:-WABBIT}
brand_sign_name=${brand_sign_name:-bnuuy}
brand_sign_magic=${brand_sign_magic:-BNUY}

safe_component() { # <label> <value>
  local label=$1 value=$2 pattern='^[A-Za-z0-9._-]+$'
  [[ -n $value ]] || die "$label must not be empty"
  [[ $value != . && $value != .. ]] || die "$label must not be '.' or '..'"
  [[ $value =~ $pattern ]] || die "$label must be one path- and shell-safe component (ASCII alphanumerics, '-', '_', '.') — got '$value'"
}
safe_component "WABBIT_BRAND_NAME (--brand-name)" "$brand_name"
safe_component "WABBIT_BRAND_ENV_PREFIX (--brand-env-prefix)" "$brand_env_prefix"
safe_component "WABBIT_BRAND_SIGN_NAME (--brand-sign-name)" "$brand_sign_name"
safe_component "WABBIT_BRAND_SIGN_MAGIC (--brand-sign-magic)" "$brand_sign_magic"
[[ ${#brand_sign_magic} -eq 4 ]] ||
  die "WABBIT_BRAND_SIGN_MAGIC (--brand-sign-magic) must be exactly four bytes — got '$brand_sign_magic'"

export WABBIT_BRAND_NAME="$brand_name"
export WABBIT_BRAND_ENV_PREFIX="$brand_env_prefix"
export WABBIT_BRAND_SIGN_NAME="$brand_sign_name"
export WABBIT_BRAND_SIGN_MAGIC="$brand_sign_magic"
if [[ $brand_name != wabbit || $brand_env_prefix != WABBIT ||
      $brand_sign_name != bnuuy || $brand_sign_magic != BNUY ]]; then
  echo "  brand: $brand_name (env prefix $brand_env_prefix, sign $brand_sign_name, magic $brand_sign_magic)"
fi

# The deployment directory's file names. The musl builds under
# target/release/ keep their cargo bin names (Cargo.toml fixes them), but
# nothing keys off the deployment copy's name — no binary reads its own
# argv[0] as a path, the installer bundles its artifact and client inside
# itself, and every box-side path comes from the brand — so the four
# copies in <out> are free to name.

name_policy=${name_policy:-wabbit-policy}
name_initrd=${name_initrd:-wabbit-initrd}
name_install=${name_install:-wabbit-install}
name_ipc=${name_ipc:-wabbit-ipc}

safe_component "--name-policy (the signing CLI's file name)" "$name_policy"
safe_component "--name-initrd (the artifact's file name)" "$name_initrd"
safe_component "--name-install (the installer's file name)" "$name_install"
safe_component "--name-ipc (the client's file name)" "$name_ipc"

declare -A name_seen=()
for n in "$name_policy" "$name_initrd" "$name_install" "$name_ipc"; do
  [[ -z ${name_seen[$n]:-} ]] ||
    die "the --name-* values must be distinct — '$n' is named twice"
  name_seen[$n]=x
  case $n in
    policy.key|policy.key.pub|policy.toml|policy.wspf)
      die "--name-* must not shadow the policy files — '$n' is reserved" ;;
  esac
done
if [[ $name_policy != wabbit-policy || $name_initrd != wabbit-initrd ||
      $name_install != wabbit-install || $name_ipc != wabbit-ipc ]]; then
  echo "  file names: $name_policy, $name_initrd, $name_install, $name_ipc"
fi

# 1. The keypair (or reuse).

if [[ ! -e $key ]]; then
  say "generating the signing keypair"
  # Build then run the binary directly (cargo `run` would go through the
  # workspace's test runner config). gen-key signs nothing, so whatever key
  # this first build compiles in is irrelevant: the export below and the
  # CLI build under it rebuild the CLI with this deployment's key.
  mkdir -p "$(dirname "$key")"
  gum spin --title "building wabbit-policy (cli)" -- \
    cargo build --release -p wabbit-policy --features cli
  gum spin --title "wabbit-policy gen-key" -- \
    "$policy_cli" gen-key --key "$key" >/dev/null
fi
[[ -e "$key.pub" ]] || die "$key.pub is missing — gen-key writes the pair"
pub=$(tr -d '[:space:]' <"$key.pub")
[[ ${#pub} -eq 64 ]] || die "$key.pub does not hold a 32-byte hex public key"
echo "  public key: $pub"

# This deployment's compiled-in key: exported for everything below, so the
# CLI and build-artifact.sh's chain both compile it in. The runtime
# `--public-key` flag covers verifying *foreign* deployments; this
# deployment's tools must trust this deployment's key natively.
export WABBIT_POLICY_PUBLIC_KEY="$pub"

# 2. The CLI. Cargo fingerprints `option_env!` *values* (rustc tracks the
#    vars a crate reads), so the build above with an older or absent key and
#    the export having changed it recompiles wabbit-common and relinks —
#    cargo's own freshness does the gating, no stamp file needed.

gum spin --title "building wabbit-policy (cli)" -- \
  cargo build --release -p wabbit-policy --features cli

# 3. Sign the TOML source into the WSPF file.

policy="$out/policy.wspf"

# Under a non-wabbit brand the cgroup wabbit creates is
# /sys/fs/cgroup/<brand> (brand::NAME), and the class convention path is
# resolved against wabbit's own cgroup — so a stock `wabbit` cgroup path in
# the policy being shipped names a cgroup that will never exist, and the
# class grants behind it land nowhere. Best-effort warning only: the
# source is operator-owned, and the generator rewrites just the starter
# policy it wrote itself.
if [[ $brand_name != wabbit ]]; then
  for f in "$source" "$policy"; do
    if [[ -f $f ]] && grep -aq -- '/sys/fs/cgroup/wabbit' "$f"; then
      echo "  $(gum style --foreground 203 "⚠ $f names the stock /sys/fs/cgroup/wabbit cgroup, but brand '$brand_name' creates /sys/fs/cgroup/$brand_name — its class grants will not resolve")"
    fi
  done
fi

if [[ -e $source ]]; then
  say "signing $source"
  rm -f "$policy"
  gum spin --title "wabbit-policy build (validate + sign)" -- \
    "$policy_cli" build "$source" "$policy" --key "$key" --key-id 0
elif [[ -e $policy ]]; then
  say "keeping the existing $(basename "$policy") (no $source)"
else
  say "no policy source: writing the starter policy (a spawnable class)"
  cat >"$source" <<'EOF'
# The starter policy, signed into policy.wspf by this generator.
# Edit and re-run the generator to rotate; everything not granted here
# is denied by default.

# A spawnable class: a signed run command may name it,
#   wabbit-ipc --key policy.key --class shell run bash
# and the run executes in its own throwaway cgroup with exactly these
# rules — nothing else. A run that names no class gets a cgroup with no
# rules at all (deny-by-default is the floor). This class grants no
# action bits at all: a shell that may read /usr, /bin and /dev and do
# nothing privileged is the least-privilege shape that still works —
# though a *usable* shell wants `actions = ["signal"]` for job control
# (Ctrl-C interrupts, `kill %1`): the task_kill gate exempts only
# self-signals, so without the bit the shell cannot stop its own
# children.
[[class]]
name         = "shell"
cgroup       = "/sys/fs/cgroup/wabbit"
default_deny = true
protect      = true

# The allow-list: a run in this class may open only these prefixes.
[[class.path_rules]]
prefix  = "/usr"
verdict = "allow"
[[class.path_rules]]
prefix  = "/bin"
verdict = "allow"
[[class.path_rules]]
prefix  = "/dev"
verdict = "allow"

# Verdicts are per-operation: read, write, and exec each carry their own,
# falling back to the rule's `verdict` shorthand. A prefix like
#   [[class.path_rules]]
#   prefix  = "/var/www"
#   verdict = "allow"
#   write   = "deny"
#   exec    = "deny"
# keeps reads open while blocking writes and execution under it.

# The boot-hardware class: what systemd legitimately needs to load
# modules at boot. PID 1 mounts /boot/efi, and filesystem drivers ask
# the kernel to autoload their helper modules *in PID 1's context* —
# without the grant those mounts fail and the boot degrades. These two
# entries are the minimum a distro boot needs; add more (multipathd, a
# package manager's cgroup) as your boxes require.
[[class]]
name = "boot-hardware"
actions = ["kmods"]

# PID 1 bootstraps into init.scope from outside every wall — it starts
# in the root cgroup and migrates itself before any authorization can
# apply — so init.scope must opt out of the wall its bits would give it
# (protect = false) or it would refuse its own PID 1 and kill the boot.
# It also holds cgroupfs-write: that is what lets PID 1 spawn services
# INTO cgroups that are walled (every unit cgroup holding a grant) —
# and signal: the task_kill gate exempts only self-signals (and
# SIGCONT, the thaw channel), and unit management is nothing but
# signals (SIGTERM on stop, SIGKILL on final kill, SIGHUP on reload).
# Without the grant systemd cannot manage a single unit.
[[authorization]]
cgroup = "/sys/fs/cgroup/init.scope"
class  = "boot-hardware"
actions = ["cgroupfs-write", "signal"]
protect = false

[[authorization]]
cgroup = "/sys/fs/cgroup/system.slice/systemd-modules-load.service"
class  = "boot-hardware"

# udev's worker pool: udevd forks workers and SIGTERMs the idle ones —
# self-exempt signals cover the workers' own exits, but the parent's
# worker management is cross-task signaling. Without the grant the
# pool never shrinks.
[[authorization]]
cgroup = "/sys/fs/cgroup/system.slice/systemd-udevd.service"
class  = "boot-hardware"
actions = ["signal"]

# Kernel module AUTOloads run in the root cgroup: request_module spawns
# a kernel usermode helper there, so no per-cgroup grant can cover
# them — and the boot needs them (a vfat ESP mount autoloads its NLS
# charset). Post-boot nothing but kernel threads and helpers live in
# the root cgroup, so this preserves the stock kernel's autoload
# behavior; *direct* modprobe stays per-cgroup. The signal grant rides
# the same transient-population logic: usermode helpers signal, and
# nobody else lives here to abuse it.
[[authorization]]
cgroup = "/sys/fs/cgroup"
actions = ["kmods", "signal"]

# Plain cgroup grants work the same way; entries can also inherit a
# class and add to it (never subtract):
# [[authorization]]
# cgroup  = "/sys/fs/cgroup/system.slice/blue-team-tools.service"
# class   = "shell"
# actions = ["kmods"]

# A cgroup may be migration-walled without holding any privileges:
# [[authorization]]
# cgroup  = "/sys/fs/cgroup/system.slice/precious.service"
# protect = true
EOF
  # The branded wabbit names its cgroup after the brand, so the starter
  # class must root there, and the example must name the branded client
  # the installer writes (/usr/local/bin/<name>-ipc).
  if [[ $brand_name != wabbit ]]; then
    sed -i -e "s|/sys/fs/cgroup/wabbit|/sys/fs/cgroup/$brand_name|g" \
           -e "s|wabbit-ipc|${brand_name}-ipc|g" "$source"
  fi
  gum spin --title "wabbit-policy build (validate + sign)" -- \
    "$policy_cli" build "$source" "$policy" --key "$key" --key-id 0
fi

# 4. Prove this deployment's key verifies this deployment's policy —
#    the same check the box will run, against the key compiled in below.

if [[ -e $policy ]]; then
  verify=$("$policy_cli" inspect "$policy" --public-key "$pub")
  printf '%s\n' "$verify" | head -n1 | grep -q "^# verified:" ||
    die "$policy does not verify against $key.pub"
  echo "  verified: $(gum style --foreground 240 "$name_policy inspect $(basename "$policy") --public-key …")"
fi

# 5. The musl chain: the exported public key compiles into every wabbit
#    binary, so the artifact verifies exactly this deployment's policies.
#    --bake embeds the signed policy too (verified at build time against
#    the same key, so a chain that would refuse its own policy never
#    ships).

say "building the chain$( [[ "$bake" == yes ]] && printf ' with the policy baked in' )"
bake_env=()
if [[ "$bake" == yes ]]; then
  [[ -e $policy ]] || die "--bake needs a policy (no $policy: sign a source first)"
  bake_env=(WABBIT_EMBED_POLICY="$policy")
fi
gum spin --title "build-artifact.sh" -- \
  env "${bake_env[@]}" "$repo/vm/build-artifact.sh" >/dev/null

# 6. The deployment directory. The musl CLI (built inside the chain with
#    this deployment's key compiled in) comes along: static, so the
#    signing and inspection flow works on any host, and `inspect` on any
#    box verifies against this deployment's key without the --public-key
#    flag.

cp "$repo/target/$target/release/wabbit-policy"  "$out/$name_policy"
cp "$repo/target/$target/release/wabbit-initrd"  "$out/$name_initrd"
cp "$repo/target/$target/release/wabbit-install" "$out/$name_install"
cp "$repo/target/$target/release/wabbit-ipc"      "$out/$name_ipc"

# 7. The summary.

summary=()
summary+=("$(gum style --bold "$out/")")
if [[ $brand_name != wabbit || $brand_env_prefix != WABBIT ||
      $brand_sign_name != bnuuy || $brand_sign_magic != BNUY ]]; then
  summary+=("  brand             $brand_name (env prefix $brand_env_prefix, sign $brand_sign_name, magic $brand_sign_magic)")
fi
summary+=("$(gum style --bold "stays here (the management host):")")
[[ -e $key ]] && summary+=("  policy.key        $(gum style --foreground 203 'keep off every box')")
[[ -e $key.pub ]] && summary+=("  policy.key.pub")
[[ -e $source ]] && summary+=("  policy.toml       the committed source (belongs in git)")
summary+=("$(printf '  %-18s the signing + inspection CLI (gen-key/build/inspect)' "$name_policy")")
summary+=("$(printf '  %-18s a client copy, for socket-tunneled use' "$name_ipc")")
summary+=("")
summary+=("$(gum style --bold "goes to the box:")")
[[ "$bake" != yes && -e $policy ]] && summary+=("  policy.wspf       the signed policy (verified against .pub)")
summary+=("$(printf '  %-18s the installer — carries the whole chain inside,' "$name_install")")
summary+=("                    and writes ${brand_name}-ipc to the box's /usr/local/bin")
[[ "$bake" == yes ]] && summary+=("  policy baked in   first-install: no filesystem footprint")
printf '%s\n' "${summary[@]}" | gum style --border rounded --padding "1 2"

echo "  scp $name_install$( [[ "$bake" != yes && -e $policy ]] && printf ' policy.wspf' ) up, then as root:"
echo "    ./$name_install$( [[ "$bake" != yes && -e $policy ]] && printf ' --policy ./policy.wspf' )"
echo "  reboot; the console shows: launch hook → ${brand_name}-initrd → $brand_name → guard enforcing"