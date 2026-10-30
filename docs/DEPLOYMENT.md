# Deploying and maintaining wabbit

This is the operator's guide: how to put wabbit on a machine, how to check
it's working, how to change its policy, and what to do when a boot goes
wrong. Internals live in `AGENTS.md`; the boot sequence in pictures is in
`docs/startup.mermaid`.

## What you are deploying

Wabbit is a boot-time protection for Linux servers. One installer places
two programs:

* **`wabbit-initrd`** runs early, from the initramfs, before the real
  system starts. It freezes every other process, attaches eBPF kernel
  hooks that (among other things) stop anything except itself from
  loading kernel modules or making eBPF calls, verifies those
  protections actually fire, then launches the second program and exits.
* **`wabbit`** takes over from there: it attaches its own, longer-lived
  eBPF protections, tests them, and then rides across the boot into the
  running system — where it keeps enforcing until the machine stops.

The handover between the two is deliberate and visible: when `wabbit`
reports it is enforcing, `wabbit-initrd` runs one last check, they
exchange a go-ahead, and `wabbit-initrd` exits — which is what lets the
boot continue past it. The console log of *every* boot shows this
conversation, so you can always tell how far a boot got.

If `wabbit-initrd` fails for any reason, the machine **boots anyway,
without protection**. A protection failure never becomes a failed boot;
the only trace it leaves is a small log file, described under
"Troubleshooting" below.

## Requirements

**The target machine** (where wabbit runs):

* x86_64 Linux, kernel **5.14 through 6.8** (verified: Ubuntu 22.04 and
  24.04, Debian 12, Rocky 9).
* A kernel with BPF LSM support — every mainstream server kernel of that
  era has it. The installer adds `lsm=bpf` to the kernel command line for
  you, unless the BPF LSM is already active.
* `root` on the box.
* Uses either **initramfs-tools** (Debian, Ubuntu) or **dracut**
  (RHEL-family, Fedora) — the installer detects which and works through
  the distro's own initramfs machinery.

**The build host** (where you build wabbit): any Linux box with Rust
(nightly), `bpf-linker`, and `llvm-strip` — a standard dev machine. The
produced binaries are static, so the target's libraries never matter.

## Quick start

Everything below runs from the repository root on the build host.

**1. Make a deployment directory.**

```sh
./vm/generate-deployment.sh --bake deployments/prod
```

This creates `deployments/prod/`:

| file | what it is | goes to the box? |
| --- | --- | --- |
| `policy.key` | the **signing key**. **Never leaves this machine.** | never |
| `policy.key.pub` | its public half; compiled into the binaries. | no |
| `policy.toml` | your policy, as readable text. Keep it in git. | no |
| `policy.wspf` | the same policy, signed, in the format wabbit reads. | only if not baked |
| `wabbit-policy` | the signing + inspection CLI (static; `gen-key`, `build`, `inspect`). | no — management host |
| `wabbit-initrd` | the early program (static, self-contained). | no — carried inside the installer |
| `wabbit-install` | the installer; carries the whole chain inside itself. | **yes — the only file the box needs** |
| `wabbit-ipc` | the signed-command client. A copy for tunneled use. | no — the installer writes one to the box |

If `deployments/prod/policy.toml` already exists, it is signed and reused;
otherwise the generator writes a **starter policy** — a signed, spawnable
`shell` class (an allow-list profile a `run --class shell` executes under)
plus commented examples of plain grants — and signs it. Edit it and re-run
the same command to rotate.

`--bake` compiles the policy into the binaries themselves, so the first
boot needs no policy file on disk. Without `--bake`, the policy travels
as a file and is installed to `/etc/wabbit/policy.wspf`.

**2. Copy the installer to the target box.**

```sh
scp deployments/prod/wabbit-install root@server:/root/
# plus policy.wspf if you did not use --bake
```

Do **not** copy `policy.key`. A box that holds the signing key can forge
policies; the key belongs on the build host (or an offline machine), and
nowhere else. Everything else the box needs is inside the installer.

**3. Install, as root, on the box.**

```sh
ssh root@server
cd /root
chmod +x wabbit-install
./wabbit-install            # add --policy ./policy.wspf if not baked,
                            # and --ipc-socket /run/wabbit/wabbit.sock to
                            # take commands after the boot
```

This prints what it does as it goes. It places the early program,
installs the distro's own initramfs hooks to start it, adds `lsm=bpf` to
the kernel command line, rebuilds the initramfs, and writes the
`wabbit-ipc` command client to `/usr/local/bin/wabbit-ipc` — in the PATH,
ready to use after the reboot. `--dry-run` shows the plan without
changing anything.

**4. Reboot.**

```sh
reboot
```

That's it. The protection is on when the machine comes back.

## What a good boot looks like

On the serial console (or `dmesg` on machines that mirror the console
there), a healthy protected boot shows this sequence:

```
[wabbit ... INFO ] bnuuy protections verified
[wabbit ... INFO ] started embedded wabbit ... waiting for its readiness
[wabbit ... INFO ] guard is enforcing
[wabbit ... INFO ] the pre-shutdown self-test passed ...
[wabbit ... INFO ] the handoff is complete ...
[wabbit ... INFO ] PID 1 has crossed to the real root: switch_root is done
[wabbit ... INFO ] joined the booted system: PID 1's mount namespace and root
[wabbit ... INFO ] systemd is up: /run/systemd/private exists
Waiting for Ctrl-C...
```

The last line means wabbit is parked and enforcing in the running system.

After logging in, a quick health check:

```sh
# wabbit is running (its name starts with '@'):
ps aux | grep '[@]wabbit'

# its cgroup exists:
ls /sys/fs/cgroup/wabbit

# a clean boot leaves NO diagnostic file:
ls /run/bnuuy.bin    # "No such file" is the GOOD answer
```

## Policies

The policy is a signed file: wabbit will not act on any policy it cannot
verify against the public key it was built with. Tampering with the file
on disk does nothing; re-signing requires `policy.key`.

**The full reference for `policy.toml` — every section, every action
name, the class system, the migration wall, and the boot-time grants
every distro needs — lives in [POLICY.md](POLICY.md).** The rest of this
section is the short version.

**The source format is TOML** (`policy.toml`) — readable, reviewable in
git. Two sections exist today:

```toml
# Which cgroups may do privileged things, and which things.
[[authorization]]
cgroup       = "/sys/fs/cgroup/wabbit"
actions      = ["mount", "kmods", "bpf-attach", "firewall"]
default_deny = false

# Per-cgroup path rules: allow or deny opens under a prefix — per
# operation class (read/write/exec; `verdict` is the all-three
# shorthand, `read = ...`/`write = ...`/`exec = ...` override it).
# Longest matching prefix wins; no match means default_deny decides.
[[authorization]]
cgroup       = "/sys/fs/cgroup/auditors"
actions      = ["exec"]
default_deny = true

[[authorization.path_rules]]
prefix  = "/etc/ssh"
verdict = "allow"

# `protect = true` puts the migration wall around a cgroup that holds no
# privileges at all — nothing outside may move processes into it
# (or freeze/kill it through the cgroupfs). Cgroups holding privileges
# are walled automatically.
[[authorization]]
cgroup  = "/sys/fs/cgroup/system.slice/precious.service"
protect = true
```

Action names, in the vocabulary the file accepts:
`setns`, `unshare`, `mount`, `exec`, `credentials`, `tag-control`,
`bpf-attach`, `kmods`, `cgroupfs-write`, `firewall`, `raw-capture`,
`bind-net`, `signal` — the last four are the newly enforced set:
packet capture and raw sockets, network `bind(2)` (local `AF_UNIX` and
netlink binds are ungated by design), and cross-task signaling —
default-allow: cgroups no policy names may signal freely; the gate
binds only cgroups an entry lists (grant `signal` there where process
management is legitimate — PID 1 and udev carry it in the starter
policy, and a usable shell class wants it for job control; self-signals
and `SIGCONT` are always exempt).

**Classes** define reusable, named privilege profiles — "the shell
class", "the ultra-privileged class" — and a `run` command can name one
(see "Sending commands"). A class with a `cgroup` compiles to its own
cgroup rule at `<cgroup>/class/<name>`; that compiled rule is what a
classed run executes under, so a class is exactly where you apply
least-privilege thinking:

```toml
# A shell that may read only what its rules allow, and do nothing
# privileged — no action bits at all: the least-privilege shape that
# still works.
[[class]]
name         = "shell"
cgroup       = "/sys/fs/cgroup/wabbit"   # → <cgroup>/class/shell
default_deny = true                      # unruled opens are denied
protect      = true

[[class.path_rules]]
prefix  = "/usr"
verdict = "allow"
[[class.path_rules]]
prefix  = "/bin"
verdict = "allow"

# Entries can also inherit a class's settings and add to them
# (never subtract): say `class = "..."` on an [[authorization]].
```

A run without a class gets its own cgroup with **no privileges at all**
— deny-by-default is the floor; the class is how you raise it, and only
as far as the class's rules say.

Everything not authorized is denied by default — an empty policy is
still a working protection posture, it just grants nothing.

**Changing the policy on a running box:** two ways. Reboot: edit
`policy.toml`, re-sign, replace `/etc/wabbit/policy.wspf`, reboot. Or,
without a reboot, send the signed policy through the IPC socket with
`wabbit-ipc` — see "Sending commands" below.

**Auditing a policy file** (any machine, no key needed):

```sh
./target/release/wabbit-policy inspect policy.wspf
# or, against a specific public key:
./target/release/wabbit-policy inspect policy.wspf --public-key <hex>
```

It verifies the signature and prints the policy back as TOML.

## Key management

* `policy.key` signs policies. `policy.key.pub` is baked into the
  binaries. Nothing on any target box can create a policy wabbit will
  accept.
* **If you lose the key:** you can no longer sign new policies for that
  deployment. Rebuild with a fresh keypair (the generator makes one) and
  reinstall wabbit — the new public key ships inside the new binaries.
* **Key rotation** is therefore: generate a new key, rebuild, reinstall,
  reboot. Plan it like any other maintenance reboot.
* Keep `policy.key` on the build host only. If the build host is
  compromised, treat the deployment as compromised and rotate.

## Updating and removing

**Update wabbit** (new code, same policy): rebuild on the dev machine
(`./vm/generate-deployment.sh --bake deployments/prod`), copy
`wabbit-install` up, run it as root again, reboot. The installer
overwrites its own placement.

**Update only the policy**: re-sign and replace
`/etc/wabbit/policy.wspf`, reboot (or use the IPC rotation once the CLI
helper exists).

**Remove everything:**

```sh
./wabbit-install --remove
reboot
```

`--remove` takes out the binary, the initramfs hooks, the kernel command
line change, and rebuilds a clean initramfs.

Other installer flags: `--dry-run` (plan only), `--flavor dracut|initramfs-tools`
(force the initramfs flavor), `--no-switch-wait` (omit the boot-ordering
hook — not recommended), `--no-lsm` (don't enroll `lsm=bpf` — only for
kernels that already have it).

## Sending commands to a running wabbit

Wabbit can take commands over a Unix socket — but only **signed** ones,
and each one **runs exactly once**. The installer already put the client
on the box (`/usr/local/bin/wabbit-ipc`, from its own bundle); a second
copy rides in the deployment directory for tunneled use from elsewhere.

**Enable the socket** (optional — wabbit only listens when told where).
The supported way is the installer flag, which makes the launch hook
export the variable in wabbit's environment (the hook is the one place
that environment comes from):

```sh
wabbit-install --ipc-socket /run/wabbit/wabbit.sock   # plus your other flags
# takes effect on the next boot
```

**Then, with the signing key (on the box, or through an ssh tunnel):**

```sh
# run a program in the protected namespace:
wabbit-ipc --key policy.key run sh -c 'uptime'

# run a shell under a class the policy defines:
wabbit-ipc --key policy.key --class shell run bash

# apply a signed policy without a reboot:
wabbit-ipc --key policy.key policy policy.wspf

# or send a prepared base64 command blob:
wabbit-ipc --key policy.key send "$(wabbit-ipc encode-run sh -c uptime)"
```

Every run — classed or not — gets its **own throwaway cgroup**, created
for that one command and removed when it ends. The class names the
privilege profile from the policy; without one, the run can do nothing
privileged at all. The class is inside the signature: whoever holds
`policy.key` chose what the command may do, and the same command can
never run twice (see the counter note below).

The defaults: the socket comes from `$WABBIT_IPC_SOCKET`, the boot id
from `/proc`, the counter from `~/.wabbit-ipc-counter`. Override with
`--socket`, `--boot-id`, `--counter` when scripting.

**Why the counter file?** Each command carries a number that must be
strictly larger than the last one the server accepted this boot, and
the server burns numbers on acceptance — so replaying a command
(byte-for-byte, even a captured one) is always rejected. The counter
file is how the client picks fresh numbers; it must be shared by
everything signing with a given key (the default path usually is). A
run's exit code becomes `wabbit-ipc`'s own, its output goes to yours.

The signature is Ed25519 against the deployment's compiled-in key —
the same root of trust as policy files — and each command names the
boot it was minted for, so commands cannot cross boots either.

## Troubleshooting

The core rule: **wabbit never blocks a boot.** If any part of it fails,
the machine boots normally, just unprotected. Two places tell you what
happened.

**1. The console.** The last `[wabbit ...]` line before things go quiet
names the phase that failed. Common ones:

| console says | meaning |
| --- | --- |
| `wabbit-initrd failed: ...` | it could not start or verify the early protections; the message names why |
| `wabbit exited before announcing readiness` | the second program died during startup — its `Error:` lines are just above |
| `resumed the world` but no `handoff is complete` | the exchange stalled after the early checks; look for the `Error:` block or the sign |
| no `[wabbit ...]` lines at all | the initramfs hooks didn't run — did the installer actually rebuild the initramfs? run `./wabbit-install --dry-run` |

**2. The boot sign, `/run/bnuuy.bin`.** If `wabbit-initrd` fails, it
leaves this file behind with the whole story, timestamped. A clean boot
deletes it. Decode it on any machine with the repository:

```sh
./vm/qemu/lab.sh sign /run/bnuuy.bin
```

It prints one line per recorded event, for example:

```
[   312 ms]  phase: started embedded wabbit as pid 196 ...
[  1200 ms] failure: wabbit exited before announcing readiness
```

**Checking protections are live on a running system:**

```sh
# wabbit present and enforcing:
ps aux | grep '[@]wabbit'

# the guard's eBPF programs are attached (if bpftool is installed):
sudo bpftool prog show | grep -c lsm         # > 0 means the hooks are up

# negative test — a bpf() call from an ordinary (untrusted) context must
# fail, even as root, while the guard is enforcing:
sudo bpftool map create /sys/fs/bpf/probe type hash key 4 value 4 entries 1
# expected: "Operation not permitted" — that failure is the protection
# working. (If it says "created", wabbit is not enforcing.)
```

## Maintenance checklist

After any deployment or change, two minutes:

1. `ls /run/bnuuy.bin` — absent means the boot was clean.
2. `ps aux | grep '[@]wabbit'` — wabbit is running, parked, enforcing.
3. `cat /proc/$(pgrep -f '[@]wabbit')/cgroup` — it is in the wabbit
   cgroup, which is what its own rules key on.
4. Confirm the negative test above fails closed.

And periodically: keep `policy.toml` in review (it *is* the security
policy), rotate the key if the build host is ever in doubt, and test
deploys in the VM lab before touching production:

```sh
./vm/qemu/lab.sh test noble    # boot-path proof on any of the 4 distros
./vm/qemu/lab.sh deploy rocky  # full installer-and-reboot proof
```

## Map

* `AGENTS.md` — how it all works, in depth.
* [POLICY.md](POLICY.md) — the policy file reference: sections, actions,
  classes, the migration wall, boot-time grants.
* `docs/startup.mermaid` — the boot sequence as a diagram.
* `wabbit-policy --help` — the policy CLI.
* `wabbit-install --help` — the installer.
* `vm/README.md` — the VM lab.
