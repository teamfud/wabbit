# wabbit-initrd: the exact process, and everything that went wrong on the way

This document describes what `wabbit-initrd` actually does at boot, in
order, and then walks through every problem that had to be solved to make
it work on real distro kernels. Most of those problems were invisible from
a development machine — they surfaced in a QEMU lab booting Ubuntu, and the
symptoms, root causes, and fixes are recorded here so they never have to be
rediscovered.

wabbit is a blue-team tool for regulated CTF use. `wabbit-initrd` is the
initrd component: it freezes the system, installs early eBPF protections,
verifies them, waits for the real root filesystem, and starts `wabbit`
with the marking that lets it survive into the booted system.

---

## The boot sequence

### 0. Worker dispatch (instant)

`wabbit-initrd` re-executes itself for several purposes, and the very
first thing the binary does is check its arguments to see whether it *is*
one of those re-executions:

- `--wabbit-verify-bpf`, `--wabbit-verify-kmod <file>`,
  `--wabbit-verify-modules-write <path>` — verification workers (see
  "Self-verification" below). Each performs exactly one syscall and
  reports through its exit code, then the process exits.
- `--wabbit-watchdog <pipe-fd>` — the freeze watchdog (see "The freeze").

If the command line matches one of these, that role runs and the process
exits before touching anything else. This must come first: a worker must
never freeze the world, mount anything, or write a sign.

### 1. Preflight and the sign

Before anything is frozen or mounted, two cheap checks:

- `/sys` must be real sysfs (checked by filesystem magic). Every mount
  wabbit-initrd makes lives under `/sys`, at mount points the kernel
  pre-creates inside sysfs. If `/sys` were not yet mounted, those mounts
  would land on the initramfs ramfs and be buried — along with every bnuuy
  pin — the moment the init script mounts sysfs over them. Refusing early
  is the only safe behavior.
- The **bnuuy sign** is created at `/run/bnuuy.bin`: a small binary log
  with the magic `BNUY`, a format version, and records of
  `{u64 monotonic-ms, u8 kind, u32 length, UTF-8 text}`. Kinds are
  `0=doc, 1=phase, 2=failure, 3=watchdog, 4=panic`. The first record is a
  self-describing banner so that anyone who runs `strings` on the file
  immediately knows what they are looking at. A panic hook is installed so
  even a crash leaves a record. The sign is best-effort throughout — a
  sign that cannot be written never fails the boot — and it is
  **removed on a clean exit**, so its presence always means "something
  went wrong".

### 2. The watchdog, then the freeze

A watchdog child is spawned *before* any freeze, so no freeze can ever
catch it unprepared. It is re-exec of this binary under
`--wabbit-watchdog`, it marks itself unkillable by the OOM killer
(`oom_score_adj` = −1000), and it blocks reading a pipe whose only write
end is held by wabbit-initrd itself with `FD_CLOEXEC` — so no other re-exec
(including wabbit) can inherit it. When the parent dies by any cause,
including `SIGKILL`, the kernel closes the pipe, the read returns EOF, and
the watchdog sends `SIGCONT` to every PID it can find (a no-op for
anything already running).

Then `stop_the_world()`:

- The process tree is walked from PID 1 through
  `/proc/<pid>/task/<tid>/children`, sending `SIGSTOP` to every process
  except the protected list (ourselves and the watchdog).
- Because processes can fork while being frozen, and a `SIGSTOP` is only
  consumed once its victim is next scheduled, a settle loop rescans until a
  full pass finds nothing running. Each round enumerates through three
  independent sources — `readdir` over `/proc`, a direct sweep of every PID
  up to `ns_last_pid`/`pid_max` (catches processes hidden from directory
  listings, e.g. by `hidepid`), and `cgroup.procs` files (a view no
  `/proc` mount option can hide).
- Every process is classified: kernel threads (empty `cmdline`) and
  zombies are skipped; uninterruptible-sleep processes count as frozen (the
  `SIGSTOP` is pending and they cannot run userspace until it is consumed).
- Two exceptions are by kernel design, not choice: **PID 1 ignores
  `SIGSTOP`** (the kernel discards signals init has no handler for), and
  the watchdog is on the protected list. If an init script is PID 1 it
  must cooperate explicitly rather than rely on being frozen — poll for
  bnuuy's pins in bpffs before doing sensitive work.

The freeze is fail-safe by construction (see "Failure safety").

### 3. The bnuuy protections

With the world frozen, bpffs is mounted at `/sys/fs/bpf` (or an existing
mount is verified by its filesystem magic — `EBUSY` alone proves nothing)
and the bnuuy eBPF object is loaded. Each LSM hook tries its candidate
programs in order (more on why candidates exist in the problem log):

| Hook | What it enforces |
| --- | --- |
| `bpf` | `bpf(2)` denied for every PID outside the trusted-PID map |
| `kernel_read_file` | module loads denied unless the image's path is inside a module tree |
| `file_open` | writable opens under module trees denied; untrusted opens of bpffs files denied |
| `sb_mount` | mounting over the module trees / bpffs denied |
| `path_unlink`/`mkdir`/`rmdir`/`symlink`/`link`/`rename` | module-tree mutation hardening |

The first three are the core gates — if one cannot load, `wabbit-initrd`
fails loudly rather than boot with a hole in its core protections. One
exception is a kernel property, not a load failure: only hooks in the
running kernel's `sleepable_lsm_hooks` set may host a `bpf_d_path`
protection, and that set varies per kernel *and per distro* — vanilla 5.15
(jammy) admits only `bpf`, `file_open`, and `sb_mount`; 6.1 (bookworm) adds
`kernel_read_file`; 6.8 (noble) adds the whole `path_*` family; and RHEL
9's 5.14 (rocky) admits all of them, because RHEL's backports expanded the
set beyond what vanilla 5.15 had. When the kernel's own verdict is that a
hook is not sleepable, the protection *cannot exist* there, so refusing
every boot on those distros would protect nothing: the gate degrades with
a distinct `not-sleepable` sign record. For the module-load gate the
degradation is not empty — on those kernels it moves to the syscall level
(error injection on the whole module-loading family; see the problem
log), deny-by-default with trusted PIDs and the initrd's module loaders
allowed. The rest degrade with a warning and a sign record, so one
kernel's quirk cannot leave a distro entirely unprotected. The module
trees are matched
in every `d_path` spelling — on merged-/usr distros `/lib` is a symlink to
`usr/lib`, so a file opened through `/lib/modules/...` has the canonical
path `/usr/lib/modules/...` — plus the `/sysroot` spellings used before the
switch into the real root. A `FILE_OPEN_TRACE` map records which decision
points `file_open` reached, which the verification suite reads whenever a
test fails.

Two tracepoints attach: `sched_process_fork` (recording every child PID
from inside the kernel, independent of any `/proc` view — its `child_pid`
offset is read from the running kernel's own format file, because RHEL 9
pads the record header and shifts the field; see the problem log) and
`module_load` (recording who successfully loaded a module — which should
stay empty).

### 4. Self-verification

Still frozen, wabbit-initrd proves the protections work from *outside* its
own PID:

- A positive control first: the trusted initrd PID calls `bpf(2)` with a
  valid `BPF_MAP_CREATE` and expects success. Without this, a hook that
  denied everyone would make the denial tests meaningless.
- Then each worker re-executes this binary, performs exactly one syscall,
  and reports by exit code (0 = denied as designed, 1 = allowed, 2 =
  denied with the wrong errno, 3 = setup failed, 4 = inconclusive):
  - `finit_module(2)` on a garbage file → must be `EPERM` *before the
    module loader reads a byte* (a `ENOEXEC` would mean the hook did not
    fire);
  - `bpf(2)` from an untrusted PID → must be `EPERM`;
  - a writable `open(2)` under `/lib/modules` → must be `EPERM`.
- Each worker's fork must appear in the kernel-side `FORK_EVENTS` map,
  proving the tracepoint sees forks; `MODULE_LOADS` must stay empty.

The workers run while the world is frozen, so nothing else can fork or
load modules during the tests.

### 5. Resume, then wait for the real root

The world resumes and wabbit-initrd polls for the real root filesystem to
be mounted. Different initrd implementations mount it in different places
and in a specific order, so the poll accepts either:

- `/sysroot` — dracut and systemd initrds (per `dracut.bootup(7)` and
  systemd's initrd interface), where nested filesystems (`/usr`, and
  fstab entries marked `x-initrd.mount`) follow *after* the root itself,
  finishing at `initrd-fs.target`;
- `/root` — initramfs-tools (`rootmnt`, per `initramfs-tools(7)`), which
  has no fstab-driven nested-mount phase of its own.

Freezing before the nested filesystems are in place would hand wabbit an
incomplete root, so the poll waits for the root, then for the nested
mounts the root's own fstab announces, then for a few consecutive quiet
polls of the mount table. Fstab expectations are advisory (10 s of quiet
ends the wait with a warning rather than hanging the boot).

### 6. Second freeze, cgroup, and the handoff

Once the root is settled, the world freezes again so the handoff steps
cannot race anyone:

1. cgroup2 is mounted at `/sys/fs/cgroup` — or an existing mount is
   verified by magic, since a systemd initrd mounts it early. A cgroup v1
   hierarchy is refused; the authorization model is unified-hierarchy
   only. The wabbit cgroup is created (or reused only if empty) and an
   open descriptor is kept on it.
2. The embedded wabbit binary is materialized and started:
   - **preferred:** an anonymous executable memfd (`memfd_create` with
     `MFD_CLOEXEC|MFD_EXEC`, with a fallback retry for kernels predating
     `MFD_EXEC`), then `execveat(AT_EMPTY_PATH)` — nothing appears on any
     filesystem, and the `/proc/<pid>/exe` link reads
     `/memfd:wabbit (deleted)` forever after;
   - **fallback:** the blob is written to `/wabbit` on the initramfs
     ramfs and executed (bpffs can never serve this role — its inodes carry
     no execute permission).
3. wabbit runs with `argv[0] = "@wabbit"`. The leading `@` is what
   exempts a process from the killing spree a systemd initrd performs at
   switch-root; without it, wabbit dies at the transition.
4. wabbit's PID is written into its cgroup's `cgroup.procs` (before it can
   fork anything that would miss the migration) and granted `bpf(2)`
   trust in bnuuy's map.
5. wabbit-initrd babysits wabbit, holding the `Ebpf` handle — and with it
   every bnuuy attachment — alive for exactly as long as wabbit runs. When
   wabbit exits (or if the launch fails), the frozen world is resumed and
   the exit code is propagated.

wabbit-initrd exits before `switch_root` happens; only wabbit crosses the
transition, by way of its `@` marking.

### Failure safety

A failed `wabbit-initrd` must never make the system unbootable. The one
state that could brick a boot is a frozen world outliving its freezer, so
it is guarded in depth:

- every ordinary error path resumes the world before propagating, and the
  environment check fails fast *before* the first freeze;
- `FrozenWorld` carries a `Drop` backstop: a world abandoned by a panic
  unwinding through `main` or an early `?` is resumed on drop;
- the watchdog covers the paths that run no userspace code at all
  (`SIGKILL`, the OOM killer);
- bnuuy's LSM attachments are held by wabbit-initrd's own file
  descriptors, so they detach when it dies — no denial can outlive it.

The honest residual: a simultaneous kill of both wabbit-initrd *and* the
watchdog is beyond userspace to guard against, and dying after wabbit
starts means the boot continues unprotected — the intended trade: an
unprotected boot beats a frozen one.

---

## The problem log

Every entry below was hit for real, diagnosed with the lab's diagnostics
(the sign, verifier output, the trace map), and fixed. The last three
categories are traps that can silently produce eBPF programs that do
nothing, which is the worst failure mode a protection tool can have.

### Userspace and boot

**PID 1 ignores SIGSTOP.**
*Symptom:* the freeze loop would hang forever waiting for PID 1 to stop.
*Root cause:* the kernel discards signals init has no handler for, and no
handler can exist for `SIGSTOP`.
*Fix:* PID 1 is classified as "frozen" once the signal is sent (with a
warning), and documented: an init script that is PID 1 must cooperate by
polling bnuuy's bpffs pins instead of relying on being frozen.

**A crashed initrd could leave the system frozen.**
*Symptom:* any panic or `SIGKILL` between freeze and resume would leave
every process stopped forever — an unbootable machine.
*Fix:* three independent layers — explicit resume on every error path, a
`Drop` backstop on the frozen-world bookkeeping for panics, and a
detached watchdog child for `SIGKILL`/OOM. Each covers the paths the
others cannot reach.

**`lsm=bpf` is not enabled by default.**
*Symptom:* no bnuuy hook can attach; loading fails.
*Root cause:* whether the BPF LSM is active is a per-distro
`CONFIG_LSM` decision. Fedora-family kernels ship with `bpf` in the list;
Ubuntu, Debian, and RHEL-family do not — so a host where "it just works"
(Fedora) says nothing about the targets.
*Fix:* the lab's provisioning appends a numbered grub drop-in
(`99-wabbit-lsm.cfg`) that *appends* to the kernel command line — a plain
edit of `/etc/default/grub` loses to the cloud image's
`50-cloudimg-settings.cfg` drop-in — and reboots. The check is
idempotent: hosts that already have `bpf` active skip the whole dance.

**Module paths resolve through the `/lib` symlink.**
*Symptom:* `file_open` allowed a writable open under `/lib/modules`, and
the trace map showed the path check failing even though `d_path` succeeded.
*Root cause:* merged-/usr distros make `/lib` a symlink to `usr/lib`; the
path walk resolves it, so the file's canonical path — what `d_path`
returns — is `/usr/lib/modules/...`, which did not match the allowlist.
*Fix:* the module trees are matched in every spelling: `/lib/modules`,
`/usr/lib/modules`, and the `/sysroot` variants used before the switch.

**A live systemd starves under the deny-all `bpf(2)` gate.**
*Symptom:* with verification passing and the hooks live for the full
sysroot-poll window, the lab VM's systemd threw watchdog timeouts — its
device-control and per-unit firewall programs were being denied.
*Root cause:* the boot-time gate denies `bpf(2)` to everything except
trusted PIDs, and systemd — not just its services, but PID 1 itself —
legitimately uses `bpf(2)` to orchestrate every unit's cgroup programs.
*Fix (design):* a classed gate, not a blanket allow. The steady-state
design (wabbit's own eBPF, where the `Authorization` maps live) grants
cgroups whose `bpf(2)` use PID 1 orchestrates — `init.scope` — a
restricted command set: cgroup-family program loads/attaches and
map-element operations, while the dangerous commands never relax below
full trust. The fd-by-ID lookup commands (`BPF_MAP_GET_FD_BY_ID`,
`BPF_PROG_GET_FD_BY_ID`) are the only route to wabbit's maps that
bypasses bpffs, so they stay wabbit-only; so do LSM and tracing program
types, which would shadow enforcement or read kernel memory. The
cgroup-migration protections are load-bearing: a rooted attacker must not
be able to write itself into a trusted cgroup via `cgroup.procs`. bnuuy
itself stays deny-all — its window ends before systemd runs.

**RHEL-family kernels ship no 9p modules, and the lab died silently.**
*Symptom:* the Rocky 9 test printed its boot banner and then nothing — no
test, no verdict, no sign — and cleaned the VM up as if nothing had
happened.
*Diagnosis:* the lab's `set -e` aborted the whole `test` run the moment
the guest's 9p share mount failed, and the `|| true` on the test step
meant the outer loop rolled on to the next distro without a word. The
guest's kernel has no 9p modules at all (`modprobe 9p` → "Module not
found"; RHEL deliberately ships none) — and never will, so no fix on the
lab side could ever make the share work there.
*Fix:* one transport for every distro. The artifact goes in over ssh, the
detached runner writes its output to a guest-local file, the host polls
for the exit marker over ssh (while the guest world is frozen, sshd is
frozen too, so polls simply fail fast on `ConnectTimeout` until the world
thaws — the freeze is brief), the sign is copied out over ssh before the
VM is destroyed, and a harness step that fails now says so instead of
silently skipping the distro.

### Kernel compatibility

**`security_bpf` gained a fourth argument after 6.8.**
*Symptom:* the `bpf` hook failed to load on Ubuntu 24.04 with "func
'bpf_lsm_bpf' doesn't have 5-th argument".
*Root cause:* mainline's `security_bpf` has a trailing `bool kernel`
parameter; the 6.8 kernel does not. Reading the phony `retval` argument
bakes in one layout.
*Fix:* the `bpf` hook is deliberately context-free — it reads no argument
at all, so it loads on every layout. The cost: where an earlier LSM already
denied the call, our `-1` replaces its errno; the denial is identical.

**`path_rename` gained a `flags` argument after 5.14.**
*Symptom:* the same class of load failure, on Rocky 9's kernel.
*Fix:* `path_rename` reads only its four stable arguments; the same
errno-pass-through trade applies.

**`struct file` was reordered mid-series.**
*Symptom:* reading `file->f_path` at a fixed offset either loaded and
read garbage or failed to load, depending on the kernel.
*Root cause:* `f_path` moved from offset 16 (5.14) to 152 (6.8), and
`f_mode` from 68 to 20.
*Fix:* each file-based hook exists as `_modern` and `_legacy` program
variants, tried in order at load time. The verifier validates
`bpf_d_path`'s argument against the running kernel's BTF, so the variant
with the wrong offsets fails to load *loudly* and the kernel itself picks
the right one — immune to whatever a distro did to the struct. The
winning variant per hook is recorded in the sign.

**`bpf_d_path` is sleepable-hooks-only — and the set differs per distro.**
*Symptom:* programs for `file_permission`, `move_mount`, and `path_mknod`
failed to load on every kernel; later, on Ubuntu 22.04, `kernel_read_file`
failed with "bpf_lsm_kernel_read_file is not sleepable" and the run died —
a required hook, refusing to boot.
*Root cause:* LSM programs may only call `bpf_d_path` from hooks in the
kernel's `sleepable_lsm_hooks` set, and the set's *contents* vary by
kernel and by distro. `file_permission`, `move_mount`, and `path_mknod`
are in no version's set. Vanilla 5.15 (jammy) admits only `bpf`,
`file_open`, and `sb_mount` — so `kernel_read_file` and the whole
`path_*` family cannot exist there. Debian 12's 6.1 adds
`kernel_read_file`; Ubuntu 24.04's 6.8 adds the `path_*` family. And
Rocky 9 — a 5.14 base — admits all of them, because RHEL's backports
expanded the set *beyond what vanilla 5.15 had*: kernel version alone
predicts nothing; only the running kernel's verdict does.
*Fix:* two-part. Hooks in no kernel's set (`file_permission`,
`move_mount`, `path_mknod`) carry no protection: `file_open` carries the
module-tree write gate and the untrusted-bpffs open gate, `sb_mount`
(which *is* sleepable everywhere in the matrix) carries the mount-target
gate, and the residual gaps are documented and accepted. For a hook that
is merely not sleepable *on this kernel*, refusing every boot on those
distros would protect nothing — the protection cannot exist there — so
the kernel's "is not sleepable" verdict is recognized as a kernel
limitation: the gate degrades with a distinct `not-sleepable` sign
record, its verification test is skipped (nothing exists to test), and
the gates that can exist stay enforced.

**The module-load gate without `d_path`: syscall-level error injection.**
The degradation above is not the end of the story on jammy-class kernels.
Those kernels annotate their syscall wrappers as error-injectable (the
whole `finit_module`/`init_module`/`delete_module`/`kexec_load` family is
in `/sys/kernel/debug/error_injection/list`, `CONFIG_BPF_KPROBE_OVERRIDE`
set — measured on Ubuntu 22.04's 5.15), and a `BPF_MODIFY_RETURN` program
attached to a wrapper that returns `-EPERM` skips the syscall entirely —
before the module loader runs at all. So the gate moves to the syscall
level there: denied at entry for every caller outside the trust map and
outside the initrd's module loaders (`modprobe`, `kmod`, `insmod` by
`comm`).

Why `comm`, and not the module's path? Path knowledge is exactly what
the sleepable set takes away: `bpf_d_path` is sleepable-LSM-only (the
kernel's `bpf_d_path_allowed` admits sleepable LSM programs and — as
observation-only iterators — `BPF_TRACE_ITER`, never a modify-return
gate), the injection allowlist contains only syscall *wrappers* (no
deeper point of the load path where a `struct file *` is already an
argument), and the remaining route — `bpf_get_current_task_btf` →
`files` → `fdt` → `fd[regs->di]` → `f_path` → dentry chain — is
mechanically possible but *unsound* as a naive walk: `d_parent` chains
are mount-agnostic and never stop at mount roots, so a process that
mounts a tmpfs anywhere (bnuuy denies mounts over the trees, not mount
creation elsewhere) and builds `lib/modules/evil.ko` inside it presents
the tmpfs root dentry as `"/"` to a dentry-only check — the check passes
for a file `d_path` would correctly reject. Closing that means
replicating `d_path`'s mount-aware walk (`struct mount` parents in
lockstep), which under aya's compile-against-bindings model is per-kernel
offset variants across `task_struct`, `files_struct`, `fdtable`, `file`,
`path`, `mount`, `dentry`, and `qstr` — the struct-file variant problem
times eight, on the most churn-heavy structs in the kernel — to buy a
check the write gate already constrains (an attacker cannot *plant* into
the real trees; out-of-tree loads are exactly what the gate denies).

`comm` is trivially spoofable (`prctl(PR_SET_NAME)`) — deliberately not
the security boundary. The boundary is who can *execute* during the
armed window: in deployment that is initrd code only (the real root's
processes, where attacker persistence would live, start after
`switch_root` — past wabbit-initrd's life and its links), and anyone who
can run code inside the initrd could simply have removed wabbit-initrd
from it. The allowance exists so real initrds can load storage and
crypto drivers mid-boot; the principled replacement — PID trust learned
post-switch, with wabbit discovering loader PIDs and writing them into
the pinned `TRUSTED_BPF_PIDS` map — belongs to the steady-state work.

The program is authored in bnuuy as Rust (`module_syscall_gate`) and
compiled by the same toolchain as every other bnuuy program; nothing
hand-assembles instructions. aya cannot host `BPF_MODIFY_RETURN`
programs (its own source marks them "not supported yet in Aya"), so
wabbit-initrd loads the rustc-compiled instructions itself: parse the
embedded object with aya-obj, perform the trust-map relocation through
aya-obj's own public `relocate_maps` (the pinned map fd must outlive the
program loads — an fd dropped between relocation and load fails at the
kernel's map resolution with `EBADF`), then `BPF_PROG_LOAD` with the
modify-return attach type and `BPF_RAW_TRACEPOINT_OPEN` for the attach
(the pre-`bpf_link` path; 5.15's `BPF_LINK_CREATE` carries no tracing
case). A host-side unit test runs the real compiled object through the
real relocation and asserts the shape: exactly one patched trust-map
reference, and nothing but the three known helpers — so an outlined
function (rustc emits a `memset` call for a zero-initialized comm
buffer; the buffer is `MaybeUninit` instead, since the helper writes all
16 bytes) can never slip in silently. Where the LSM gate exists it stays
preferred: it allows in-tree loads by anyone, which the syscall gate
cannot. The kmod verification worker runs against whichever gate is
armed — the syscall gate returns `EPERM` at entry, exactly the verdict
the worker checks for.

**`bpf_d_path` requires trusted provenance.**
*Symptom:* "R1 type=fp expected=ptr_" — the helper rejected the program.
*Root cause:* the code copied `file->f_path` to the stack with
`bpf_probe_read_kernel` before calling the helper; a stack copy erases
the trusted-pointer provenance `bpf_d_path` demands.
*Fix:* pure pointer arithmetic — `&file->f_path` is `file + offset`, never
dereferenced — which preserves the `PTR_TO_BTF_ID` register type and lets
the verifier check the offset against BTF (the same property the layout
variants rely on).

**The 6.8 verifier has register-invariant bugs on re-read ctx slots.**
*Symptom:* "REG INVARIANTS VIOLATION" followed by an unprovable return
range, for four specific hooks.
*Root cause:* hooks that read the phony `retval` argument twice — once
per path-check helper — with the string-comparison loop refining scalar
ranges in between.
*Fix:* read `retval` once per program, before any path resolution, and
pass the value down. This is also why the trace map marks codes as hit
(`BPF_ANY` insert) instead of counting: a read-modify-write counter trips
the same invariant check.

**The `sched_process_fork` record layout is not what the header suggests —
and RHEL's differs from everyone else's.**
*Symptom:* the fork watcher ran but recorded the wrong values — the map
held `1650614647`, which is `"wabb"` in ASCII — on Ubuntu 24.04.
*Diagnosis:* that error message was only possible because the verification
dumped the map's contents on failure. The value being the first four
bytes of `wabbit-initrd`'s name proved the program was reading a `comm`
field, not a PID.
*Root cause:* the comm fields are 16-byte inline arrays on the target
kernels (mainline converts them to dynamic `__string` words only after
6.8, which shifts the layout). The vanilla `child_pid` offset is 44.
*Then, on Rocky 9:* the map held `100` — `"d"`, the *last* comm byte of
`"wabbit-initrd"` — the same failure mode at a different offset. Rocky's
kernel pads the trace-entry header with `common_preempt_lazy_count` (RHEL's
lazy-preempt backport), pushing every field up four bytes: `child_pid` at
48. The kernel's own format file said so all along, once the lab dumped it.
*Fix:* two compiled fork-watcher variants (offset 44, offset 48), with
`wabbit-initrd` parsing `child_pid`'s offset from the running kernel's
format file and attaching the matching one — attaching both if the parsed
offset is neither known value. This matters precisely because a wrong
tracepoint offset fails *silently* (tracepoint ctx reads are not validated
against BTF, unlike the LSM `struct file` variants): without the fork-event
assertion in verification, the wrong offset would never be noticed at all.

### Toolchain and codegen — the silent-empty-program traps

**The 512-byte eBPF stack limit.**
*Symptom:* "combined stack size of 3 calls is 608. Too large".
*Root cause:* the path-resolving code kept a 256-byte `d_path` buffer per
helper; once the module-tree list grew past a size where the compiler
merged frames, two buffers coexisted and overflowed the limit.
*Fix:* one shared buffer per hook, passed by `&mut` into every helper.
Half the limit, with the full 256-byte buffer retained.

**bpf-linker leaves outlined helpers unresolved.**
*Symptom:* programs loaded as zero instructions — "processed 0 insns",
"last insn is not an exit or jmp".
*Root cause:* helpers that crossed LLVM's inline-cost threshold were
outlined into `.text`, and bpf-linker left their cross-section calls as
`call -1`: the program body simply was not there.
*Fix:* `#[inline(always)]` on the whole helper chain, making each program
section self-contained again.

**Panicking slice indexes gut the program.**
*Symptom:* the same zero-instruction load failure, with the object file
looking healthy this time.
*Root cause — the nastiest one:* a panicking slice index (`buffer[..n]`)
in a `no_std` eBPF program has its panic path outlined into
`.text.unlikely.` with a relocation against a *section symbol*. Nothing
resolves it; the load collapses. The program looked correct in the
object file and only failed in the kernel.
*Fix:* panic-free indexing everywhere — `get()`, never slicing — which
removes the cold path from the object entirely. The three disciplines
this category taught (shared buffer, forced inlining, panic-free
indexing) are recorded in AGENTS.md so they are never violated again.

---

## Testing all of this

The QEMU + KVM lab in `vm/qemu/lab.sh` drives the whole flow on real
distro kernels — cached cloud images, disposable overlay VMs, host-side
sign decoding — in one command:

```sh
./vm/build-artifact.sh      # static musl wabbit-initrd (embeds wabbit and bnuuy)
./vm/qemu/lab.sh test noble # Ubuntu 24.04; also: jammy, bookworm, rocky
```

All four target distros pass end-to-end — every one with the sign carrying
"bnuuy protections attached and verified" and the run exiting 124 at the
sysroot poll exactly as designed:

| Distro | Kernel | `struct file` variants | sleepable set | Notable |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 (noble) | 6.8 | `_modern` | all 10 hooks | full house; `child_pid` at record offset 44 |
| Debian 12 (bookworm) | 6.1 | `_legacy` | no `path_*` family | the six `path_*` hooks degrade with sign records |
| Ubuntu 22.04 (jammy) | 5.15 | `_legacy` | `bpf`, `file_open`, `sb_mount` only | `kernel_read_file` and `path_*` record `not-sleepable`; the module-load gate moves to the syscall level (error injection on `finit_module`/`init_module`/`delete_module`/`kexec_load`) and the kmod test runs against it |
| Rocky 9 (rocky) | 5.14 (RHEL) | `_legacy` | all 10 hooks — RHEL backports exceed vanilla 5.15 | `bpf` already in the LSM list (no reboot needed); `child_pid` at 48 (lazy-preempt header padding) |

The pattern the matrix proves: the kernel's own verdicts — the BTF-checked
load of one `struct file` variant or the other, the "is not sleepable"
rejection, the format file's field offsets — select what runs on each
distro, and everything the kernel cannot host degrades with a sign record
instead of failing the boot. Rocky 9 is the sharpest example: a 5.14
kernel that hosts every hook a vanilla 5.15 cannot, with a tracepoint
record nobody else has, both handled without a single distro-specific
branch in the code.
