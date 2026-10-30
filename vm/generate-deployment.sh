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
# usage: vm/generate-deployment.sh [options] [output-dir]
#
#   --source PATH   TOML policy source (default: <out>/policy.toml)
#                   signed into <out>/policy.wspf when it exists
#   --bake          bake the signed policy into the wabbit binary
#   --key PATH      reuse this private key (default: <out>/policy.key,
#                   generated when missing; its .pub must sit beside it)
#
# example:
#   vm/generate-deployment.sh --bake deployments/foo
#   # writes deployments/foo/{policy.key,policy.key.pub,policy.toml→wspf,
#   #                        wabbit-policy,wabbit-initrd,wabbit-install,
#   #                        wabbit-ipc}
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
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) out=$1; shift ;;
  esac
done

die() { printf '%s\n' "$(gum style --foreground 203 "✗ $*")" >&2; exit 1; }
say() { printf '%s\n' "$(gum style --bold --foreground 212 "▸ $*")"; }

mkdir -p "$out"
out=$(cd "$out" && pwd)
source="${source:-$out/policy.toml}"
key="${key:-$out/policy.key}"

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
if [[ -e $source ]]; then
  say "signing $source"
  rm -f "$policy"
  gum spin --title "wabbit-policy build (validate + sign)" -- \
    "$policy_cli" build "$source" "$policy" --key "$key" --key-id 0
elif [[ -e $policy ]]; then
  say "keeping the existing $(basename "$policy") (no $source)"
else
  say "no policy source (no $source): wabbit boots on Policy::default()"
fi

# 4. Prove this deployment's key verifies this deployment's policy —
#    the same check the box will run, against the key compiled in below.

if [[ -e $policy ]]; then
  verify=$("$policy_cli" inspect "$policy" --public-key "$pub")
  printf '%s\n' "$verify" | head -n1 | grep -q "^# verified:" ||
    die "$policy does not verify against $key.pub"
  echo "  verified: $(gum style --foreground 240 "wabbit-policy inspect $(basename "$policy") --public-key …")"
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

cp "$repo/target/$target/release/wabbit-policy" \
   "$repo/target/$target/release/wabbit-initrd" \
   "$repo/target/$target/release/wabbit-install" \
   "$repo/target/$target/release/wabbit-ipc" \
   "$out/"

# 7. The summary.

summary=()
summary+=("$(gum style --bold "$out/")")
summary+=("$(gum style --bold "stays here (the management host):")")
[[ -e $key ]] && summary+=("  policy.key        $(gum style --foreground 203 'keep off every box')")
[[ -e $key.pub ]] && summary+=("  policy.key.pub")
[[ -e $source ]] && summary+=("  policy.toml       the committed source (belongs in git)")
summary+=("  wabbit-policy     the signing + inspection CLI (gen-key/build/inspect)")
summary+=("  wabbit-ipc        a client copy, for socket-tunneled use")
summary+=("")
summary+=("$(gum style --bold "goes to the box:")")
[[ "$bake" != yes && -e $policy ]] && summary+=("  policy.wspf       the signed policy (verified against .pub)")
summary+=("  wabbit-install     the installer — carries the whole chain inside,")
summary+=("                    and writes wabbit-ipc to the box's /usr/local/bin")
[[ "$bake" == yes ]] && summary+=("  policy baked in   first-install: no filesystem footprint")
printf '%s\n' "${summary[@]}" | gum style --border rounded --padding "1 2"

echo "  scp wabbit-install$( [[ "$bake" != yes && -e $policy ]] && printf ' policy.wspf' ) up, then as root:"
echo "    ./wabbit-install$( [[ "$bake" != yes && -e $policy ]] && printf ' --policy ./policy.wspf' )"
echo "  reboot; the console shows: launch hook → wabbit-initrd → wabbit → guard enforcing"