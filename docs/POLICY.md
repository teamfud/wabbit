# The wabbit policy file

This is the reference for `policy.toml` — the file `wabbit-policy build`
compiles into the signed policy (`policy.wspf`) every wabbit boots and
rotates on. The quick operational path (generate a key, build, install)
lives in [DEPLOYMENT.md](DEPLOYMENT.md); this page documents every knob
the source format has, and what each one actually does at runtime.

Everything here is **signed**: wabbit never acts on a policy it cannot
verify against the public key compiled into it, and the private key
never lives on a target box. Tampering with a deployed file does nothing;
re-signing requires the key.

```sh
# the three commands you need
wabbit-policy gen-key --key policy.key      # once, per deployment
wabbit-policy build policy.toml policy.wspf --key policy.key
wabbit-policy inspect policy.wspf            # verify + decode, anywhere
```

## How the file is structured

Six sections exist today, all optional — an empty policy is a valid
posture (it grants nothing, and deny-by-default does the rest):

```toml
[rootfs]           # mount-time policy: what is writable, what is executable
[network]          # how far the bind and raw-capture gates reach
[default]          # what every cgroup no [[authorization]] entry names gets
[[class]]          # reusable, named privilege profiles
[[authorization]]  # per-cgroup grants: the actual rules
[[startup]]        # programs the boot itself launches, in a named class
```

The compile step (`wabbit-policy build`) validates everything and folds
the classes away — the signed file carries only cgroup rules. A class
you can read in the TOML is, by the time wabbit loads it, an
authorization entry like any other.

## `[[authorization]]` — one cgroup, one set of rules

Each entry names one cgroup by its **canonical cgroupfs path** (as it
appears under `/sys/fs/cgroup`), and everything that cgroup's processes
may do:

```toml
[[authorization]]
cgroup       = "/sys/fs/cgroup/wabbit"     # the cgroup being granted
class        = "profile"                   # optional: inherit (see below)
actions      = ["mount", "kmods"]          # what its processes may do
default_deny = false                       # path-rule mode (see below)
protect      = true                        # migration wall (see below)

[[authorization.path_rules]]
prefix  = "/etc/ssh"                       # this path and everything below
verdict = "allow"                          # "allow" or "deny"
```

### `actions` — the vocabulary

Each name is one action bit; a cgroup gets exactly what it lists and
nothing else. The **enforced** bits — the ones the loaded eBPF gates
consult on every relevant syscall, per cgroup:

| name | what it permits |
| --- | --- |
| `mount` | mounts over the cgroupfs root and protected cgroup paths |
| `bpf-attach` | the restricted `bpf(2)` set system daemons need — cgroup-family program loads/attaches, map creates and element ops, BTF loads. Never LSM/tracing programs, never fd-by-ID lookups; full `bpf(2)` stays wabbit-only |
| `bpf-full` | **unfiltered `bpf(2)`** — every command, every program type, every attach type, the fd-by-ID lookups included: what [`bpf-attach`](#bpf-attach) deliberately is not. A cgroup holding it can reach anything `bpf(2)` reaches, wabbit's own maps included; the bpffs *open* gate still holds (pins are path-shaped), so the fd-by-ID lookups are the sanctioned route. Grant it where a tool genuinely needs the full syscall — an observability agent loading its own tracing programs, a bpffs power-user — and nowhere else. The default entry may not carry it (see [`[default]`](#default--what-unlisted-cgroups-get)) |
| `kmods` | loading kernel modules (`finit_module`/`init_module`) — a cgroup without this bit may not load modules at all, autoloads aside (see the boot-time grants below) |
| `cgroupfs-write` | writing through the migration wall (`cgroup.procs`/`cgroup.freeze`/`cgroup.kill` under protected cgroup paths) — what lets PID 1 administer the hierarchy |
| `firewall` | modifying firewall rules, both the nftables netlink socket and the legacy xtables `setsockopt` paths |
| `raw-capture` | creating raw-capture sockets — `AF_PACKET` (tcpdump's channel) and `SOCK_RAW` at the IP families — packet capture and hand-crafted IP packets. Which of those are gated at all is the [`[network]`](#network--how-far-the-network-gates-reach) `raw_capture` posture |
| `bind-net` | `bind(2)` on `AF_INET`/`AF_INET6`: acquiring a network endpoint (a listener, a service port). Which binds are gated at all — every one, only those naming a port, or none — is the [`[network]`](#network--how-far-the-network-gates-reach) `bind` posture. Every other family — local `AF_UNIX` IPC, netlink — is ungated by design |
| `signal` | signaling any task other than the sender's own (`kill`/`tgkill`/`pidfd_send_signal`) — **self-signals and `SIGCONT` are always exempt** (`SIGCONT` is the thaw channel every boot-failure rescue broadcasts, and a frozen world must never outlive a failed boot). **Default-allow for unlisted cgroups**: a cgroup no policy names may signal freely; the gate binds only cgroups an entry lists — grant `signal` there where process management is legitimate (PID 1, udev's worker pool, a shell's job control), omit it where cross-task signaling is the thing to contain. The target's *cgroup* cannot be read without the unstable `task_struct` walks the design forbids, so the bit does not distinguish same-cgroup from cross-cgroup targets. **The bit never applies to wabbit itself**: the gate's self-guard denies every signal aimed at the wabbit process — this grant included — unless the system is shutting down (see the note below) |
| `path-bypass` | **path rules decide nothing for this cgroup** — the `file_open` path-rule resolution (its own rules and the `[default]` entry's alike, read/write/exec classes alike) is skipped entirely. The trusted-user grant: the operator's shell or admin session still gets to *edit* the very paths the policy walls off, without an `allow` rule per prefix kept in lockstep with the default section. It lifts path rules **only** — bpffs pins, the module trees (`kmods`), and the migration wall (`cgroupfs-write`) are structural protections, not path rules, and keep applying, as does every other gate. Refused in `[default]` (see below) |


The remaining names — `setns`, `unshare`, `exec`, `credentials`,
`tag-control` — are part of the wire vocabulary for the gates the
steady-state set does not host yet; granting them today costs nothing
and changes nothing, which is exactly why the starter policy does not
hand them out speculatively. A cgroup with no entry at all is
deny-by-default for every enforced bit — with one deliberate exception:
**the signal gate binds only cgroups an entry lists** (see the `signal`
row), so the unlisted world of a boot never loses `kill(2)` to a
boundary nobody drew.

One target is outside the `signal` bit's reach entirely: **wabbit
itself is not signalable by outside processes while the system is up**.
The signal gate carries a *self-guard* that outranks every
authorization — no class, no bit, no default grants a path to the
process that owns all the walls — and it yields only to the system
shutting down (PID 1's sweep, and the shutdown relaxation wabbit sets
when it observes the machine going down) and the thaw channel
(`SIGCONT`). `SIGINT` is denied like every other signal; the operator's
stop channel is the **signed `stop` IPC command** the client mints
with the deployment's key (see the IPC documentation). There is no
policy knob for the self-guard: an enforcement process that any process
on the box could kill would be a containment tool only by courtesy.

### `path_rules` and `default_deny` — the per-cgroup file profile

Path rules decide **opens** under a prefix, **per operation class**:
read (any open of the path at all), write (a writable open), and exec
(an `execve` of a binary under the prefix). Each class carries its own
verdict, so a rule can block writes and execution under a path while
its reads stay open — the other way around too:

```toml
[[authorization.path_rules]]
prefix  = "/var/www"
verdict = "allow"      # the shorthand: all three classes at once
write   = "deny"       # overrides the shorthand's write
exec    = "deny"       # …and its exec — reads alone stay open
```

The shorthand `verdict` and the per-operation keys (`read`, `write`,
`exec`, each `"allow"` or `"deny"`) union, a per-operation key winning
for its class. An operation a rule leaves out is **unspecified**: the
deepest rule that *does* decide it wins, and an operation no rule
decides follows the profile default —

* with `default_deny = false` (a *deny-list*), everything opens except
  what a rule denies;
* with `default_deny = true` (an *allow-list*), nothing opens except
  what a rule allows.

Resolution is per class, longest-deciding-prefix-wins: of all the rules
whose prefixes cover the path, the deepest one that *speaks for* the
open's class decides it. (So an allow-list entry wanting "reads fine,
but no writing under here" must say `verdict = "allow"` *and*
`write = "deny"` in one rule — a shallower allow does not cover the
class a deeper rule left out.)

**The whole profile is skippable**: an entry carrying the
[`path-bypass`](#actions--the-vocabulary) action resolves no path rules
at all — its cgroup's opens are governed by the structural protections
alone. That is the trusted-user form: one action instead of an `allow`
rule per walled prefix. Two loader contracts apply, enforced at
build (never silently truncated):

* **prefixes are canonical**: absolute, no trailing `/`;
* **64-byte walk cap**: a prefix (and the entry's cgroup path) may be at
  most 64 bytes — that is how deep the eBPF protection walk hashes, so a
  longer path could never be matched by any rule or wall.

The exec class rides the kernel's own marker: `execve` opens the binary
with the internal `__FMODE_EXEC` flag, which userspace `open(2)` cannot
counterfeit, so an `exec = "deny"` prefix blocks execution through
`file_open` no matter how the binary is invoked. A class entry
resolution inherits all of this — class rules and entry rules for one
prefix union per class, an entry adding what its class left
unspecified but never changing a class's decision.

### `protect` — the migration wall

The wall is what stops a rooted attacker from simply writing their PID
into a privileged cgroup's `cgroup.procs`: for every cgroup *outside* a
walled path, writable opens of `cgroup.procs`, `cgroup.freeze` and
`cgroup.kill` under it (and mounts over it) are denied.

* **absent** (the default): a cgroup holding any action bit is walled
  automatically — the walls around those bits are load-bearing;
* `protect = true`: wall this cgroup even if it holds no bits —
  migration-proof it for its own sake;
* `protect = false`: **opt out** of the implicit wall. The one
  legitimate need is `init.scope`: PID 1 starts in the root cgroup and
  migrates *itself* into `init.scope` before any authorization can
  apply, so a walled `init.scope` would refuse its own PID 1 and kill
  the boot. Setting `false` is the signed policy accepting that
  tradeoff; it cannot be combined with `true`.

### `class` — inheritance

An entry that names a class inherits all of its settings, merged by
**union**: actions join, `default_deny` and `protect` OR together
(`true` from either side wins, an explicit `false` carries only when
nothing says `true`), and path rules append (a prefix the entry and the
class rule differently is a build error). An entry may **add** to its
class, never subtract.

## `[[class]]` — named, reusable privilege profiles

A class is authoring sugar: define a profile once, grant it to many
cgroups — and, when it is *concrete*, let signed runs execute under it
by name:

```toml
# A concrete class: runs can name it. Its rules compile to an
# authorization entry at <cgroup>/class/<name> — that path is the one
# convention the runtime resolves (wabbit itself understands no classes).
[[class]]
name         = "shell"
cgroup       = "/sys/fs/cgroup/wabbit"     # → /sys/fs/cgroup/wabbit/class/shell
default_deny = true
protect      = true

[[class.path_rules]]
prefix  = "/usr"
verdict = "allow"

# An abstract class: settings other entries inherit; compiles to no
# entry of its own, and no run can name it.
[[class]]
name    = "boot-hardware"
actions = ["kmods"]
```

The rules:

* `name`: 1–24 bytes of `[a-z0-9-]`, no leading or trailing `-`. The
  charset is a security boundary — the runtime builds a cgroupfs path
  from the name a signed run carries, and the client, the server's
  decode, and the build all reject anything that could reinterpret as a
  path.
* `cgroup` present (**concrete**): the class compiles to its own entry
  at `<cgroup>/class/<name>`. That directory is created at boot (the
  loader creates missing authorized cgroups), and each run naming the
  class gets an **ephemeral child** `run-<command id>` under it —
  created for that one command, removed when it ends.
* `cgroup` absent (**abstract**): inheritance only.
* Everything else matches the `[[authorization]]` fields.

### How a run uses a class

```sh
wabbit-ipc --key policy.key --class shell run bash
```

The command is signed, and the class is inside the signature: whoever
holds the signing key chose the privileges, and the same command can
never run twice. At the server:

1. the class name is resolved to the compiled entry (the convention
   path, looked up in the **active** policy — so a signed reconfigure
   rotates classes without a reboot);
2. the run gets its ephemeral cgroup, carrying exactly that class's
   action bits, flags and path rules — keyed by the cgroup's fresh
   kernfs id, so the eBPF gates enforce them for the run's processes
   and nobody else's;
3. a run that names **no** class gets the same cgroup with *no*
   authorization at all — deny-by-default is the floor;
4. when the run ends, the authorization leaves the maps and the cgroup
   is deleted.

Runs never execute in wabbit's own cgroup (that cgroup is trusted, its
processes exempt from every gate). The spawned process migrates itself
into the run cgroup **between fork and exec**, so a run's first syscall
already runs under its class.

## `[[startup]]` — programs the boot itself launches

One block per program, launched by wabbit at its chosen point in system
startup — signed policy spending the same trust a signed run command
does, at boot instead of over the socket:

```toml
[[startup]]
point = "unit"                            # when to launch (see below)
unit  = "multi-user.target"              # the unit the "unit" point waits for
class = "network-daemon"                 # the class it runs under
timeout_secs = 300                       # unit point only, 0 = wait forever
argv  = ["/usr/local/bin/announce"]      # argv[0] is the program

[[startup]]
point = "initrd"
argv  = ["/bin/load-secrets"]
```

Each entry names the **point** it launches at:

| `point` | launches when | notes |
| --- | --- | --- |
| `initrd` | the guard is enforcing and the boot is still in the initramfs — before `switch_root` | short one-shots: a program still running at the crossing is killed by a systemd initrd's sweep and runs on a deleted ramfs under a busybox one. The entry runs *blocking*, so a hung program hangs the crossing — that is the honest cost |
| `systemd` | wabbit has crossed into the booted system and systemd is up | |
| `unit` | the named `unit` reaches **active** (`systemctl is-active`) | `timeout_secs` bounds the wait (default 300; `0` waits forever) |

* `unit` is the systemd unit name — `multi-user.target`,
  `systemd-networkd-wait-online.service` ("wait-online succeeded"), any
  unit a deployment waits on. Only the `unit` point takes it.
* `class` is the same named profile a signed run command resolves
  (`wabbit` resolves the convention path against this boot's policy), so
  a `[[startup]]` program runs under exactly the class the signer named
  — **including classes carrying `bpf-full` or any other
  wall-adjacent bit**: the signature is the authorization. Absent, the
  entry runs classless — the policy default when there is one, the
  deny-by-default floor otherwise.
* `argv` is the program and its arguments, launched like every run:
  its own ephemeral cgroup (`run-<id>`), migrated in **between fork and
  exec**, released when it ends, the migration wall covering it by
  prefix. Nothing a policy launches ever runs in wabbit's own cgroup.
* Entries launch **in policy order**, one at a time per point, and each
  runs exactly once per boot. A failed entry warns and the next one
  runs — a broken `[[startup]]` entry never takes the boot's
  enforcement or its IPC server down.
* A daemon is a legitimate `[[startup]]` argv: the launcher awaits each
  program, and a program that keeps running keeps its cgroup and its
  class until the process (or the boot) ends.

Like every section it is read at boot; a reconfigure stores a new
startup section but launches nothing from it — the entries already
launched this boot ran, and the next boot reads the new one.

## `[network]` — how far the network gates reach

The `bind-net` and `raw-capture` bits decide *who* may do a gated
thing; this section decides *what is gated at all*, separately for each
gate. It is global — it applies to every cgroup, listed or not:

```toml
[network]
bind        = "ports"    # "all" | "ports" | "off"
raw_capture = "icmp"     # "all" | "icmp" | "off"
```

| `bind` | gated (needs `bind-net`) | passes |
| --- | --- | --- |
| `all` | every `AF_INET`/`AF_INET6` `bind(2)` | non-IP families |
| `ports` | a bind naming a specific port | port-0 binds (the kernel picks an ephemeral port — what clients do before connecting), non-IP families |
| `off` | nothing | everything |

| `raw_capture` | gated (needs `raw-capture`) | passes |
| --- | --- | --- |
| `all` | `AF_PACKET`, and `SOCK_RAW` at the IP families | every other socket |
| `icmp` | `AF_PACKET`, and `SOCK_RAW` at the IP families for every protocol but ICMP | raw `IPPROTO_ICMP` at `AF_INET` and raw `IPPROTO_ICMPV6` at `AF_INET6` (`ping`, `traceroute -I`, classic `traceroute`'s ICMP receive), every other socket |
| `off` | nothing | everything |

`all` is the strictest posture and the default: a policy without the
section, or a key left out of it, gates as much as the gate can.
Under `all`, any unlisted program that binds an IP socket — even to
port 0 on the way to an outbound connection — or opens a raw ICMP
socket is denied; `bind = "ports"` keeps outbound connectivity open
while still walling off listeners on chosen ports. The `ports`
residual: a port-0 bind (or `listen(2)` with no bind at all) still
yields a listener, on a port the kernel picks.

`raw_capture = "icmp"` exempts ICMP alone on purpose: a raw socket of
any other IP protocol (`IPPROTO_TCP`, `IPPROTO_UDP`) receives a copy of
every inbound packet of that protocol — tcpdump in all but name. Tools
that need those stay gated: `traceroute -T` (raw TCP) and the like need
`raw-capture`, or the UDP default (`traceroute` without flags) instead.
A raw ICMP socket still sees every inbound ICMP packet, which the
exception accepts.

The section is read at boot; a reconfigure carrying it replaces the
stored section but does not re-arm the gates until the next boot.

## `[default]` — what unlisted cgroups get

Rules apply to the exact cgroup they name — children never inherit, so
an entry for `/sys/fs/cgroup` covers only the processes sitting
directly in the root cgroup (kernel helpers), not the machine. To set
rules for *every process no entry names* — user sessions, services you
did not list, classless IPC runs — use `[default]`. It is an
`[[authorization]]` entry without a `cgroup`:

```toml
[default]
actions = ["bind-net"]          # optional

[[default.path_rules]]
prefix  = "/etc/shadow"
verdict = "deny"

[[default.path_rules]]
prefix  = "/root"
write   = "deny"
exec    = "deny"
```

- **Listed cgroups are unaffected.** A cgroup with its own entry gets
  exactly that entry — never the default's actions or rules on top. To
  give a listed cgroup the same rules, put them in an abstract
  `[[class]]` and have both inherit it.
- **Deny-list only.** There is no `default_deny`: the default reaches
  every service you did not name (journald, dbus, logind, getty, …),
  and an allow-list that forgot one of their paths makes the boot
  unusable. Path rules here can only block.
- **Allowed actions:** `kmods`, `firewall`, `raw-capture`, `bind-net`.
  `mount`, `cgroupfs-write`, `bpf-attach`, `bpf-full`, and `path-bypass`
  are refused — granted to every unlisted cgroup they would hand the
  whole machine the keys to the walls (`path-bypass` included: it
  dissolves the per-cgroup file profile machine-wide). `signal` is
  refused because it would mean nothing:
  unlisted cgroups may already signal, and the signal gate never reads
  the default.
- Like every section, it is read at boot; a reconfigure stores it but
  re-arms nothing until the next boot.

## `[rootfs]` — mount-time policy

What everyone sees of the filesystem, applied at wabbit's startup
(outer), in its private namespace (inner), and on signed
reconfigurations:

```toml
[rootfs]
executable = true          # may binaries run from the root
writable   = true           # may anything write to it

[[rootfs.overrides]]       # per-path exceptions, ascending priority
path             = "/etc"
inner_writable   = false    # inside the namespace
inner_executable = true
outer_writable   = false    # in the launch namespace
outer_executable = true
outer_readable   = true     # visibility/readability metadata
outer_visible    = true
priority         = 10
# inner_path = "/elsewhere"  # optional mapping target
```

`RDONLY` is added where a path is not writable, `NOEXEC` where it is
not executable, with recursive bind semantics on the root.

## The boot-time grants every distro needs

A default-deny boot needs three grants, and the starter policy carries
them; understanding them explains most of the format:

```toml
[[class]]
name    = "boot-hardware"
actions = ["kmods"]

# 1. PID 1 bootstraps into init.scope from outside every wall — it
#    starts in the root cgroup and migrates itself before any
#    authorization can apply — so init.scope must opt out of the wall
#    its bits would give it (protect = false), needs cgroupfs-write
#    to spawn services INTO cgroups that are walled, and needs signal:
#    unit management is nothing but signals (SIGTERM on stop, SIGKILL
#    on final kill, SIGHUP on reload) — without the grant systemd
#    cannot manage a single unit.
[[authorization]]
cgroup   = "/sys/fs/cgroup/init.scope"
class    = "boot-hardware"
actions  = ["cgroupfs-write", "signal"]
protect  = false

# 2. systemd-modules-load.service runs in its own cgroup.
[[authorization]]
cgroup = "/sys/fs/cgroup/system.slice/systemd-modules-load.service"
class  = "boot-hardware"

# 3. Kernel module AUTOloads: request_module spawns a kernel usermode
#    helper in the ROOT cgroup, so no per-cgroup grant can cover them —
#    and boots need them (a vfat /boot/efi mount autoloads its NLS
#    charset; without this grant the mount fails and local-fs.target
#    drags the boot to maintenance). Post-boot nothing but kernel
#    threads live in the root cgroup; direct modprobe stays
#    per-cgroup. The signal grant rides the same root-cgroup logic:
#    wabbit-initrd's boot-failure rescues (the drop backstop, the
#    watchdog) thaw from there, and while the signal gate exempts
#    SIGCONT outright and unlisted cgroups default-allow, a listed root
#    with the bit keeps the rescue covered belt-and-braces.
[[authorization]]
cgroup  = "/sys/fs/cgroup"
actions = ["kmods", "signal"]
```

Two properties make these safe to state this plainly:

* the loader **creates missing authorized cgroups** — these cgroups do
  not exist when the guard loads (the initramfs phase), systemd reuses
  the directories, so the kernfs ids the maps key on are the very ones
  the processes land in;
* the cgroupfs root may carry bits but is **never a protected path** —
  it is a prefix of every cgroupfs path, and walling it would deny
  every `cgroup.procs` write on the machine. The generator rejects
  `protect = true` on it.

Add more per-distro grants (a package manager's cgroup, multipathd) as
your boxes require; each is one more `[[authorization]]` entry.

## Validation — what `build` rejects, by name

The compile step is the one place bad policy is refused with names:

* non-canonical paths (not absolute, trailing `/`, not UTF-8), and any
  cgroup path or rule prefix past the 64-byte walk cap;
* unknown action names, unknown flag bits, `protect = true` on the
  cgroupfs root, `protect` set to both `true` and `false`;
* two entries naming the same cgroup (the loader keys its maps by
  cgroup; the second would silently overwrite the first);
* a class name that is not 1–24 bytes of `[a-z0-9-]`, a class defined
  twice, a class reference that does not exist, a class and an entry
  disagreeing about the same path prefix, and a concrete class whose
  compiled path would exceed the walk cap;
* a `[[startup]]` entry whose `point` is not one of the three, a `unit`
  on a point that takes none, a timeout on a point that launches
  immediately, a `unit` that is not a systemd unit name (1–255 bytes of
  `[A-Za-z0-9:.@_-]`, no leading `-` — the name reaches a poll command's
  argument list, so the charset is a boundary), a `class` that is not
  a class name, an empty `argv`, an `argv` entry with a NUL or past
  4096 bytes, and more than 64 entries or 64 `argv` slots;
* and the wire-level decoder additionally rejects unknown versions,
  unknown key ids, unknown section bits, truncated input, invalid
  UTF-8, and trailing bytes — a tampered or foreign-signed file is
  refused, not best-effort parsed.

## What the format deliberately does not have

The original design sketch carried a few permissions the current gate
set cannot enforce (debugging, systemd access, power management — each
needs an LSM hook the guard does not host, or an identity the design's
no-`task_struct`-walks rule forbids reading). They are **absent from
the vocabulary rather than present-but-unenforced**: an action bit
nothing denies would be a lie with a signature on it. The sketch's
raw network capture, network socket binding, and cross-cgroup signaling
fields are the opposite case — implemented as `raw-capture`,
`bind-net`, and `signal` above (with `signal` narrowed to cross-*task*
gating and a default-allow posture, since the target's cgroup is
unreadable without the unstable `task_struct` walks this design
forbids; and the sketch's local-bind half is deliberately **ungated** —
`AF_UNIX` is every daemon's connective tissue, and no `bind-local`
exists in the vocabulary at all).
`wabbit-common/src/cgroup_types.rs` carries the full mapping, sketch
field by sketch field, including what each unimplemented one would
need.

## Rotating a policy

* **at build**: edit `policy.toml`, re-run `wabbit-policy build` (and
  the deployment generator if you use it), redeploy, reboot;
* **at runtime**: `wabbit-ipc --key policy.key policy policy.wspf` —
  the server verifies the new file's signature *again*, applies its
  rootfs section, and merges it section-by-section; classed runs
  resolve against the merged policy immediately, so classes rotate
  without a reboot. (Boot-time cgroup grants, keyed by maps populated
  at load, take effect on the next boot.)
