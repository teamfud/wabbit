# Wabbit architecture

Wabbit is a Linux-only Rust workspace with two user-space binaries and one
eBPF program:

| Component | Role |
| --- | --- |
| `wabbit` | Main outer process. Captures runtime filesystem handles, loads and controls the eBPF protections, manages cgroups/maps, and serves signed IPC requests. |
| `wabbit-initrd` | Initrd entry point. Freezes and resumes the system, establishes early protections, waits for `/sysroot`, prepares runtime filesystems and the wabbit cgroup, then launches `wabbit`. |
| `wabbit-ebpf` | `no_std` eBPF LSM and tracepoint programs built into `wabbit` at compile time. |
| `wabbit-common` | Shared `no_std`/user-compatible types used by the process, eBPF program, maps, and authorization protocol. |

The project is intended for controlled blue-team and regulated CTF use. It
requires Linux mount and eBPF privileges and is not an EDR.

## Workspace and build flow

The root `Cargo.toml` defines the workspace. Building the `wabbit` package
also runs `wabbit/build.rs`, which invokes the Aya build tooling to compile
`wabbit-ebpf`. The resulting object is embedded in the user-space executable
with `aya::include_bytes_aligned!`; no eBPF object path is required at runtime.

Building the `wabbit-initrd` package runs `wabbit-initrd/build.rs`, which
compiles the `bnuuy` eBPF object the same way and additionally compiles the
`wabbit` userspace binary in a private target directory under `OUT_DIR`,
exposing it as `WABBIT_BLOB` for `include_bytes!`. The initrd executable
therefore embeds both its protections and the `wabbit` it is meant to start.
At runtime `wabbit-initrd/src/launch.rs` materializes the blob, preferring an
anonymous executable memfd (`memfd_create` with `MFD_EXEC`, then
`execveat(AT_EMPTY_PATH)`, with a pre-`MFD_EXEC` retry and an initrd-file
fallback for kernels that refuse either) and launching it with
`argv[0][0] == '@'`, which exempts the process from the killing spree PID 1
performs when switching out of the initrd.

`wabbit` exposes its `filesystem`, `ipc`, and `trust` modules through
`wabbit/src/lib.rs`. The binary target in `wabbit/src/main.rs` uses those
modules, while `wabbit-initrd` depends on the library so filesystem policy
behavior is shared rather than duplicated.

## Testing in VMs

The target matrix — Rocky 9, Debian 12, Ubuntu 22.04, Ubuntu 24.04 — is
exercised by `vm/qemu/lab.sh`, a QEMU + KVM lab that needs no host root:
it boots disposable overlay VMs over cached cloud images and sets `lsm=bpf`
on the kernel command line (no target distro enables the BPF LSM by
default, and without it nothing of bnuuy can attach). Two flows:

* `test <distro>` proves the launch path in a booted system: the musl
  artifact (from `./vm/build-artifact.sh`) is uploaded and run detached,
  with the live root bind-mounted at `/sysroot` so the sysroot poll
  completes and the real launch path — the second freeze, cgroup2, the
  memfd wabbit — actually runs, testing wabbit itself on every distro.
  The success state has no ssh in it (wabbit parks while wabbit-initrd
  babysits it with the world frozen, the documented design until the
  handoff step exists, and the freeze stops the guest's timeout and sshd
  too), so the runner sends wabbit-initrd's output to the console and
  the verdict watches the qemu serial console for the phase lines and
  wabbit's `Waiting for Ctrl-C` marker; teardown destroys the frozen
  world. The failure paths thaw (the Drop backstop or the watchdog),
  so the host pulls the bnuuy sign out over ssh as the forensic record.
* `deploy <distro>` proves the placement: `wabbit-install` (built musl —
  the host glibc is newer than every guest's) is uploaded and run as
  root, placing the artifact through the distro's own initramfs
  extension points, enrolling `lsm=bpf`, and rebuilding the initramfs;
  the reboot boots the real chain (init → launch hook → wabbit-initrd →
  sysroot poll → wabbit), which never finishes by design — wabbit is
  babysat frozen and the pre-switch wait holds the init — so the verdict
  watches the qemu serial console (the launch hook's `>/dev/console`
  redirect) for winit's info lines and wabbit's `Waiting for Ctrl-C`
  marker.

`vm/README.md` documents the flow and the per-distro
kernel-compatibility expectations; a Vagrantfile exists for VirtualBox
hosts. `./vm/build-artifact.sh` builds the artifact the `test` flow
consumes; the `deploy` flow builds its own installer.

## Startup lifecycle

The intended startup path begins in the initrd:

1. The initrd initializes hardware, verifies `wabbit-initrd`, and launches it.
2. `wabbit-initrd` stops the world by walking the process tree and sending
   `SIGSTOP`, then protects `/lib/modules` and `/sysroot/lib/modules` with BPF
   and denies module loading from outside those trees. It tests those
   protections, attaches standalone tracepoints for module loading and fork
   observation, and verifies that a dummy module load has no effect.
3. It creates maps for authorized BPF PIDs (and, for observability, recorded
   forks and module loads), temporarily restricts BPF syscalls, verifies the
   restriction with a separate process, pins the required objects in bpffs,
   and checks their expected locations.
4. It begins waiting for the real root to be mounted
   (`wabbit-initrd/src/sysroot.rs`), then resumes the world so the initrd can
   mount it. The poll
   watches `/proc/self/mountinfo` for a root at `/sysroot` (dracut and
   systemd initrds) or `/root` (initramfs-tools), and — per the mount order
   those initrds document — waits for the nested filesystems to follow: the
   mounts the root's own fstab announces (`/usr` and entries marked
   `x-initrd.mount`, the same set dracut's `initrd-parse-etc.service`
   mounts), plus a few unchanged polls of the mounts below the root. Once
   the root is settled, it stops the world again, mounts the runtime
   filesystems (cgroup2 at `/sys/fs/cgroup`, mounted or verified when a
   systemd initrd mounted it already), creates the wabbit cgroup inside it,
   and starts the embedded `wabbit` (materialized at runtime) with
   `argv[0][0]` set to `@` so systemd's switch-root kill spares it, moving
   it into the wabbit cgroup before it can fork and granting its PID
   `bpf(2)` trust in the bnuuy map. Until the handoff step exists, the
   initrd babysits wabbit with the world frozen and resumes it if wabbit
   exits or fails to start. `wabbit-initrd` exits before `switch_root`;
   only `wabbit` crosses the transition.
5. `wabbit` starts as the outer process. It opens and retains descriptors for
   `/proc`, `/sys`, `/dev`, and related filesystems before they move under
   `/sysroot`; reads and verifies the WSPF configuration; creates and checks
   the configured maps; and loads the eBPF programs in non-enforcing mode.
6. The outer process runs self-tests while eBPF logs allowed actions, confirms
   that all expected events were observed, and switches the protections to
   enforcing mode. It repeats denied-action tests, performs a final pre-shutdown
   test with `wabbit-initrd`, then allows the initrd process to exit.
7. After initrd handoff, `wabbit` waits for systemd, obtains systemd's view of
   the root through `/proc/1/root`, and chroots into the main root. Signed IPC
   requests can then create an authorized child cgroup, grant that cgroup
   permissions through the eBPF maps, and spawn an interactive process.

The eBPF protections cover kernel-module loading, BPF map and syscall access,
cgroup operations, firewall changes, and other actions selected by the
authorization maps. Unauthorized processes are denied by the kernel hooks.
The module trees are matched in every `d_path` spelling — on merged-/usr
distros `/lib` is a symlink to `usr/lib`, so a module image opened through
`/lib/modules/...` has the canonical path `/usr/lib/modules/...` — and the
`file_open` hook keeps a `FILE_OPEN_TRACE` decision map (hit-markers, not
counters: a read-modify-write tripped the 6.8 verifier's register-invariant
check) that the verification suite dumps into the sign whenever a
writable-open test fails.
The `bpf(2)` gate is classed, so the boot-time deny-all does not have to
starve a live systemd: full trust (wabbit, its trusted-PID maps) keeps
everything; the `ACTION_BPF_ATTACH` class (`wabbit-common`) grants cgroups
whose bpf use PID 1 orchestrates — init.scope, and udevd only if it proves
to need it — the restricted command set systemd actually uses, per
`ACTION_BPF_ATTACH`'s documentation; everyone else keeps the deny-all. The
critical denials never relax with class: the fd-by-ID lookup commands
(`BPF_MAP_GET_FD_BY_ID`, `BPF_PROG_GET_FD_BY_ID`) are the only route to
wabbit's maps that bypasses bpffs, so they stay wabbit-only; so do LSM and
tracing program types, which would shadow enforcement or read kernel
memory. `security_bpf`'s first two arguments (`cmd`, kernel-copied `attr`)
are stable across every target kernel's hook layout, so the gate can read
the command, program type, and attach type without layout variants. The
cgroup-migration protections are load-bearing for this design: a rooted
attacker must not be able to write itself into a trusted cgroup via
`cgroup.procs`. bnuuy itself stays deny-all — its window ends before
systemd runs — and the classed gate belongs to wabbit's own steady-state
eBPF, where `GlobalPerm`/`Authorization` live.
The bnuuy hook layouts follow `lsm_hook_defs.h`, verified against the target
matrix kernels (5.14, 5.15, 6.1, 6.8): `kernel_read_file` denies loads with
`READING_MODULE == 2`, the value on every target kernel. Two hooks are
deliberately layout-agnostic because their argument counts vary: the `bpf`
hook is context-free (mainline has a fourth `bool kernel` parameter that
≤6.8 kernels lack), and `path_rename` reads only its stable arguments (the
trailing `flags` argument appeared after Rocky 9's 5.14) — both trade the
prior-LSM errno pass-through for loading everywhere. The file-based hooks
(`file_open`, `kernel_read_file`) reach into `struct file`, which was
reordered mid-series — vanilla `f_path` sits at offset 16 in v5.14 and 152
in v6.8, with `f_mode` at 68 and 20 — so each exists as `_modern` and
`_legacy` program variants, tried in order at load time: the verifier
validates `bpf_d_path`'s argument against the running kernel's BTF, so the
variant with the wrong offsets fails to load loudly and the kernel itself
selects the right one, whatever a distro did to the struct.
wabbit-initrd records the winning variant per hook in the sign.

The `sched_process_fork` tracepoint record is also distro-patched, and a
wrong field offset there fails *silently* — tracepoint ctx reads are not
validated against BTF, so the program loads fine and records comm bytes as
PIDs. The vanilla layout puts `child_pid` at record offset 44; RHEL 9's
kernel pads the trace-entry header with `common_preempt_lazy_count`,
pushing it to 48. bnuuy therefore compiles both offset variants
(`fork_watcher_vanilla`, `fork_watcher_preempt_lazy`), and wabbit-initrd
selects between them by parsing `child_pid`'s offset from the running
kernel's own format file — ground truth, unit-tested against the verbatim
format text of both layouts — attaching both if the parsed offset matches
neither. The fork-event assertion in verification is the backstop: it
checks each worker's real PID against the map, so a wrong offset fails
loudly, never silently.

`bpf_d_path` may only be called from sleepable LSM hooks, which confines
path-resolving protections to the kernel's `sleepable_lsm_hooks` set — a
set that varies per kernel *and per distro*, measured empirically across
the target matrix: vanilla 5.15 (jammy) admits only `bpf`, `file_open`,
and `sb_mount`; 6.1 (bookworm) adds `kernel_read_file`; 6.8 (noble) adds
the whole `path_*` family; and RHEL 9's 5.14 (rocky) admits all of them —
RHEL backports expanded the set beyond vanilla 5.15, so kernel version
alone predicts nothing. The hooks:
`file_open` (the module-tree write gate at open time, through `f_mode`, and
the untrusted-bpffs open gate), `kernel_read_file` (the module-load gate),
`sb_mount` (the mount-target gate), and the `path_unlink`/`mkdir`/`rmdir`/
`symlink`/`link`/`rename` family (module-tree mutation hardening). Hooks
outside that set — `file_permission`, `move_mount`, `path_mknod` — cannot
resolve a path at all and carry no bnuuy protection. The first three
sleepable hooks are the required core: if one cannot load, wabbit-initrd
fails loudly — unless the kernel's own verdict is that the hook is not
sleepable at all ("bpf_lsm_<hook> is not sleepable"), in which case the
protection *cannot exist* on that kernel and refusing every boot on those
distros would protect nothing, so the gate degrades with a warning, a
distinct `not-sleepable` sign record, and its verification test is
skipped. The rest degrade with a warning and a sign record, so one
kernel's sleepable-set quirk cannot leave a distro entirely unprotected.

On kernels that lack the sleepable `kernel_read_file` (vanilla
5.14/5.15), the module-load gate does not degrade to nothing: it moves to
the syscall level through error injection. Those kernels annotate their
syscall wrappers injectable (the `finit_module`/`init_module`/
`delete_module`/`kexec_load` family is in
`/sys/kernel/debug/error_injection/list` with `CONFIG_BPF_KPROBE_OVERRIDE`
set — measured on Ubuntu 22.04's 5.15), and a `BPF_MODIFY_RETURN` program
returning `-EPERM` at one skips the syscall before the module loader
runs. The gate program is authored in bnuuy as Rust
(`module_syscall_gate`, in an `fentry/`-named section only so object
parsers recognize it) — no hand-assembled instructions anywhere — and
allows trusted PIDs plus the initrd's module loaders by `comm`
(`modprobe`, `kmod`, `insmod`): a syscall-entry gate has no path
knowledge — `bpf_d_path` is sleepable-LSM-only, and the naive
dentry-chain alternative is unsound (mount-agnostic parent walks read a
tmpfs root as `"/"`, so a process that mounts a tmpfs anywhere can
rehearse a `lib/modules` chain; closing that means reimplementing
`d_path`'s mount-aware walk across eight unstable structs, per kernel).
`comm` is deliberately not the security boundary: it is spoofable by any
process, but in deployment only initrd code can execute during the armed
window — the root's processes start after `switch_root`, past
wabbit-initrd's life — and code inside the initrd could simply have
removed wabbit-initrd. The allowance buys real-hardware boots (initrds
modprobe storage/crypto drivers mid-boot); the principled replacement,
PID trust learned post-switch, belongs to the steady-state work. aya cannot host `BPF_MODIFY_RETURN` programs (its own
source marks them "not supported yet in Aya"), so wabbit-initrd's
`inject` module loads the rustc-compiled instructions itself: parse the
embedded object with aya-obj, relocate the trust-map reference through
aya-obj's own public `relocate_maps` (the pinned fd must outlive the
program loads, or the kernel's map resolution fails with `EBADF`), then
`BPF_PROG_LOAD` and the `BPF_RAW_TRACEPOINT_OPEN` attach — the pre-link
path, since 5.15's `BPF_LINK_CREATE` carries no tracing case. A
host-side unit test runs the real compiled object through the real
relocation and asserts exactly one patched trust-map reference and
nothing but the three known helpers, so an outlined function (rustc emits
a `memset` for a zero-initialized comm buffer; the buffer is `MaybeUninit`
instead, the helper writes all 16 bytes) can never slip in silently. The
links are held by wabbit-initrd's fds and detach when it dies. Where the
LSM gate exists it stays preferred — it allows in-tree loads by anyone,
which the syscall gate cannot.
The residual gaps — writing through a file descriptor opened before wabbit
started, and `move_mount`-style mount shuffling — are accepted and
documented. The VM lab verifies each target kernel empirically.
Mount namespace creation remains thread-local, so any namespace setup must
occur before the Tokio runtime and its worker threads are created.

## Filesystem policy

`wabbit/src/policy/rootfs.rs` defines the filesystem policy types and
`wabbit/src/filesystem.rs` provides the mount-policy implementation that applies
them. A `RootFSConfig` contains root defaults:

```text
RootFSConfig {
    flags: RootFlags { executable, writable },
    overrides: Vec<PathOverride>,
}
```

Each `PathOverride` identifies one path and provides separate outer and inner
values for writable/executable behavior (in a `PathFlags` bitfield, built with
`bilge`), an optional `inner_path`, visibility and readability metadata, and a
priority. Overrides are processed in ascending
priority order. The current remount implementation applies the `path` field;
the additional path and visibility/readability fields are part of the policy
model for later integration with namespace mapping and eBPF filtering.

`apply_rootfs_config(config, inner)` is deliberately reusable. It can be called
before namespace creation with `inner = false`, after entering a private
namespace with `inner = true`, or again later to apply a new policy. Mount
changes are implemented with self-bind mounts followed by bind remounts:

- `RDONLY` is added when a path is not writable.
- `NOEXEC` is added when a path is not executable.
- The root remount uses recursive bind semantics.

`make_mount_tree_private` changes mount propagation to private recursively so
namespace-local changes do not propagate back to the parent. `generate_tmpfs`
mounts a `tmpfs` filesystem at a supplied mount point. These operations require
appropriate mount privileges, normally `CAP_SYS_ADMIN`.

## Initrd integration

`wabbit-initrd` brings up the bnuuy protections, verifies them from spawned
workers, waits for the real root, and starts the embedded wabbit. It is
launched detached from the initrd's main script so the script keeps running;
the only thing that ever pauses the script is wabbit-initrd's own freeze:

```sh
# /init, after /proc, /sys, and /dev are mounted, before any root mounting:
RUST_LOG=info setsid /wabbit-initrd </dev/null >/dev/console 2>&1 &
# if the script itself is PID 1 it cannot be SIGSTOPped; cooperate explicitly:
while [ ! -e /sys/fs/bpf/boot/bpf ]; do sleep 0.1; done
```

`setsid` keeps terminal and job-control signals away from wabbit-initrd and
everything it spawns; `RUST_LOG` matters because `env_logger` defaults to
error-only. After the script mounts the real root and its nested mounts, it
must not race to `switch_root`: the handoff choreography (and the second
freeze) belongs to wabbit-initrd.

The `wabbit-install` crate (a dependency-free workspace member;
`cargo build -p wabbit-install`, run as root) automates the whole
placement through each flavor's own extension points —
init-premount/init-bottom hooks for initramfs-tools, pre-mount/pre-pivot
hooks via a 90wabbit dracut module — plus the `lsm=bpf` kernel command
line (skipped where the BPF LSM is already active) and the initramfs
rebuild, with `--dry-run`, `--remove`, and `--no-switch-wait` (omit the
pre-switch_root wait) available. Its build script bundles the
`wabbit-initrd` artifact into the installer — a nested musl build in a
private target directory, the same arrangement `wabbit-initrd` uses to
embed wabbit — so the installer carries its artifact and needs no
checkout on the target system; `--artifact` overrides the bundle.

All of wabbit-initrd's mounts (bpffs at `/sys/fs/bpf`, tracefs at
`/sys/kernel/tracing`, cgroup2 at `/sys/fs/cgroup`) target mount points the
kernel pre-creates in sysfs, so nothing of the initrd's own is shadowed. They
are guarded by a sysfs check — if `/sys` is not the real sysfs yet, the
mounts would land on the initramfs ramfs and be buried by the init script's
own sysfs mount, so wabbit-initrd refuses to run — and verified by filesystem
magic after mounting, so an existing foreign mount can never be mistaken for
the right one (`EBUSY` alone proves nothing). As submounts of `/sys` they
travel with it into the booted system; the sysroot poll only counts mounts
below the real root, so they cannot confuse it.

Of the two common transitions, busybox/util-linux `switch_root` kills nothing
but deletes the initramfs rootfs (memfd-launched wabbit is unaffected), while
a systemd initrd's switch-root kills every leftover process except those
whose `argv[0][0]` is `@` — which wabbit gets from its launcher.

The bnuuy eBPF code follows three disciplines the VM lab proved load-bearing:

* **one shared `bpf_d_path` buffer per hook** (256 bytes, passed by `&mut`):
  two buffers in separate frames overflow the 512-byte eBPF stack limit once
  the code is too complex for the compiler to merge frames;
* **`#[inline(always)]` on the whole helper chain**: helpers that cross the
  compiler's inline-cost threshold get outlined into `.text`, and bpf-linker
  leaves their cross-section calls unresolved — the program loads as an
  empty stub the kernel rejects;
* **panic-free indexing (`get`, never slicing)**: a panicking slice index in
  a `no_std` eBPF program has its panic path outlined into `.text.unlikely.`
  with a relocation against a section symbol nothing resolves, which
  silently guts the program at load time — the symptom is a verifier report
  of zero processed instructions and "last insn is not an exit or jmp".

### Failure safety

A failed `wabbit-initrd` must never make the system unbootable; every failure
path is fail-open. The one state that could brick a boot is a frozen world
outliving its freezer, so it is guarded in depth:

* every ordinary error path resumes the world before propagating, and an
  environment check (`/sys` must be real sysfs, bpffs/cgroup2 verified by
  filesystem magic) fails fast *before* the first freeze;
* `FrozenWorld` carries a `Drop` backstop: a world abandoned by a panic
  unwinding through `main` or an early `?` is resumed on drop — a frozen
  system never outlives a failed `wabbit-initrd`;
* a watchdog child covers the paths that run no userspace code at all
  (`SIGKILL`, the OOM killer): spawned before the first freeze, exempt from
  every freeze, immune to the OOM killer (`oom_score_adj` = −1000), and
  blocking on a pipe whose only write-end is `FD_CLOEXEC` and held by
  `wabbit-initrd` itself — so it reads EOF exactly when the parent dies, by
  any cause, and then sends `SIGCONT` to every PID it can find (a no-op for
  anything already running);
* the bnuuy LSM links are held by `wabbit-initrd`'s own file descriptors, so
  they detach when it dies: no denial can outlive it. Pins in bpffs remain,
  but pins are inert data.

The honest residual: a simultaneous `SIGKILL` of both `wabbit-initrd` and the
watchdog (or a kernel panic) is beyond userspace to guard against — and if
`wabbit-initrd` dies after wabbit starts, the boot continues unprotected,
which is the intended trade: an unprotected boot beats a frozen one.

### The bnuuy sign

While it runs, `wabbit-initrd` keeps a small binary boot log — the *bnuuy
sign* — at `/run/bnuuy.bin`: an innocuous-looking runtime file that is
unmistakable once examined, because it begins with the magic `BNUY` and its
first record is a self-describing banner. It records every startup phase,
the full error chain of any failure, panics (through a panic hook that still
runs the default hook), and the watchdog's own record when it fires. A clean
boot removes the sign; every other exit — a propagated error, a panic, a
`SIGKILL` the watchdog cleaned up after, or a nonzero wabbit exit — leaves
it behind explaining why. The sign is best-effort end to end: a sign that
cannot be written never fails the boot. It makes no mounts; it uses `/run`
as the initrd provides it (tmpfs when the initrd mounted it, the initramfs
ramfs otherwise), so it is never persistent. `WABBIT_SIGN_DIR` overrides
its directory for testing.

```text
magic:    4 bytes, "BNUY"
version:  u16, little-endian (currently 1)
records:  any number of:
            u64  little-endian, milliseconds since boot (CLOCK_MONOTONIC)
            u8   kind: 0 = doc, 1 = phase, 2 = failure, 3 = watchdog, 4 = panic
            u32  little-endian, payload length
            payload bytes, UTF-8 text
```

The binary also verifies the bnuuy protections against itself by re-executing
as a worker: `wabbit-initrd --wabbit-verify-bpf`,
`--wabbit-verify-kmod <file>`, and `--wabbit-verify-modules-write <path>`
each perform exactly one syscall and report through the exit code (0 denied
as designed, 1 allowed, 2 wrong errno, 3 setup failure, 4 inconclusive).
The normal startup path spawns these workers while the world is frozen, so
the deny paths are exercised from a PID outside `TRUSTED_BPF_PIDS`; the
`FORK_EVENTS` map proves the `sched_process_fork` tracepoint saw each
worker's fork, and the `MODULE_LOADS` map must stay empty.

## IPC

The namespace process optionally exposes a Unix-domain socket named through
`WABBIT_IPC_SOCKET`. `wabbit/src/ipc.rs` uses a small length-prefixed binary
protocol:

- request `1`: execute a program and arguments in the namespace;
- request `2`: apply a signed `Policy`;
- response `1`: process output and exit status;
- response `2`: operation failure and message;
- response `3`: filesystem configuration applied.

`NamespaceIpc` is the client API. `run_task` returns captured stdout, stderr,
and the process exit code. `reconfigure_filesystems` sends a complete signed
policy file (the bytes produced by `policy::sign`). The server verifies the
signature and parses the policy before doing anything else, then applies each
section the policy contains (today, the rootfs section with `inner = true`)
while holding a mutex. It merges the new policy into its stored policy only
after that succeeds; sections the policy omits are left unchanged. Unsigned or
tampered policies are rejected without touching any mounts.

The socket otherwise has no application-level authentication or authorization,
and task execution requests are not signed. Task operations should therefore be
protected by socket ownership/permissions and by the surrounding service
isolation before exposing the socket to untrusted users.

## Trust helpers

`wabbit/src/trust.rs` provides independent Ed25519 helpers for signed text.
The signed-string format is:

```text
<standard-base64 Ed25519 signature>\n<payload>
```

`extract_signed_string` validates and returns the payload without verifying
the signer. `verify_signed_string` parses a 32-byte public key supplied as
standard base64 or hexadecimal, verifies the exact UTF-8 payload bytes, and
returns the payload only on success. The trust layer is not currently wired
into filesystem configuration loading or IPC authorization.

## Binary policy files

`wabbit/src/policy/` defines a versioned binary policy file, declared with
`binrw` with boolean flags packed into `bilge` bitfields. A `Policy` is a set of
optional sections, one per kind of configuration; the filesystem policy
(`RootFSConfig`) is the `rootfs` section, and further kinds such as initrd
modification or a kernel module allowlist are meant to be added as new sections.

- `policy/mod.rs`: the `Policy` container, the header, signing and verification,
  and file I/O. It documents the file layout and the steps for adding a section.
- `policy/rootfs.rs`: the `rootfs` section.
- `policy/wire.rs`: `binrw` helpers shared by sections, such as path encoding.

The file begins with the four-byte `WSPF` magic, a little-endian version
(currently 3) and the signature, followed by a byte with one bit per section
and then the sections that bit announces, in bit order. Each section appears at
most once, so a policy has a single encoding. The decoder rejects unknown
versions, section bits it does not know (rather than ignoring a section it cannot
enforce), reserved flag bits, invalid markers, oversized override counts,
truncated input, invalid UTF-8, and trailing bytes.

`to_signed_bytes`/`from_bytes` handle in-memory conversion; `read_file` and
`write_new_signed` provide file operations. `write_new_signed` uses exclusive creation so an existing
policy is not silently replaced. Binary policies are verified by the policy
loader with the compile-time `policy::POLICY_PUBLIC_KEY`. The signature covers the policy header and payload;
unsigned or tampered files are rejected. Policy generation requires the caller
to provide either a finished signature (`to_signed_bytes`) or a 32-byte Ed25519
private key (`sign`), so no private signing key is embedded in wabbit.

## eBPF component

`wabbit-ebpf` contains the LSM and tracepoint programs used during startup and
steady-state enforcement. The programs consult authorization maps keyed by
process/cgroup identity. They initially run in non-enforcing mode for
self-tests, then transition to enforcing mode; denied operations return the
action-specific kernel error while authorized child cgroups receive only the
permissions granted by the IPC request.

The user-space process loads the embedded object, initializes `aya_log`, loads
and attaches the required LSM and tracepoint programs, and consumes logger
events asynchronously. The program has a dual MIT/GPL license declaration and
a minimal panic handler suitable for eBPF.

## Configuration and operational boundaries

Both binaries obtain their policy from the signed policy file named by
`WABBIT_FILESYSTEM_CONFIGURATION_FILE`, and mount failures are returned as
errors rather than silently ignored.

The startup diagram describes the intended initrd/systemd integration and
protection phases. Components should not assume that those phases are
complete unless the corresponding implementation exists: mount-policy
persistence or rollback, complete use of `PathOverride::inner_path`,
`outer_readable`, or `outer_visible`, and full production coverage of every
listed eBPF enforcement hook remain integration points rather than implicit
guarantees.
