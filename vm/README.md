# Wabbit kernel test VMs

The target matrix is Rocky 9, Debian 12, Ubuntu 22.04, and Ubuntu
24.04. The lab runs host-built artifacts — the `wabbit-initrd` executable
and the `wabbit-install` installer, both static musl, embedding the whole
chain (the installer bundles the installer-time `wabbit-initrd`, which
embeds `wabbit` and the bnuuy eBPF object) — so no VM ever needs a
compiler.

## QEMU + KVM lab (the active path)

`vm/qemu/lab.sh` drives everything with QEMU using KVM acceleration and no
root on the host. Cloud images are downloaded once into `vm/qemu/cache/`
(git-ignored, ~0.3–1 GB each); every run boots a throwable overlay on top,
and overlays are deleted on teardown, so steady-state disk use is just the
cached images. Boot one distro at a time.

```sh
./vm/build-artifact.sh            # static musl wabbit-initrd (for `test`)
./vm/qemu/lab.sh test noble       # Ubuntu 24.04: booted-system run
./vm/qemu/lab.sh deploy noble     # Ubuntu 24.04: the real boot chain
./vm/qemu/lab.sh test jammy       # Ubuntu 22.04
./vm/qemu/lab.sh test bookworm    # Debian 12
./vm/qemu/lab.sh test rocky       # Rocky 9
```

Two flows, proving different things:

**`test <distro>` proves the launch path in a booted system.** Boots the
VM, adds `lsm=bpf` to the kernel command line and reboots (the BPF LSM
must be in the boot list or nothing of bnuuy can attach — no target
distro enables it by default), mounts tracefs, uploads the artifact, and
bind-mounts the live root at `/sysroot` — nothing mounts `/sysroot` in a
booted system, and without it the sysroot poll blocks forever, so the bind
presents the root the poll's own rules accept and the run proceeds
through the real launch path: the second freeze, cgroup2, the memfd
`@`-marked wabbit. **The success state has no ssh in it**: a started
wabbit parks waiting for Ctrl-C, `wabbit-initrd` babysits it with the
world *frozen* (the documented design until the handoff step exists), and
the freeze stops the guest's `timeout(1)` and sshd with it — so the runner
redirects wabbit-initrd's output to `/dev/console` and the host watches
the qemu serial console (which drains no matter what the guest does) for
the phase lines and wabbit's `Waiting for Ctrl-C` marker; teardown
destroys the VM, and with it the frozen world. The failure paths *thaw*
(the `Drop` backstop or the watchdog resume the world when
`wabbit-initrd` exits), so the host also polls for the exit marker over
ssh and pulls the bnuuy sign — the forensic record — out for the verdict.

**`deploy <distro>` proves the placement.** Builds `wabbit-install`
(musl — the build host's glibc is newer than every guest's) and runs it
in the VM as root: it places the artifact through the distro's own
initramfs tooling (`init-premount`/`init-bottom` hooks, or the `90wabbit`
dracut module), enrolls `lsm=bpf` on the kernel command line, and
rebuilds the initramfs. The reboot then boots the real chain — init
script → launch hook → wabbit-initrd → sysroot poll → wabbit — exactly
what a production deployment would run, and (same frozen-babysit
reality) never finishes: the host watches the serial console for winit's
info lines and wabbit's `Waiting for Ctrl-C` marker, where the launch
hook's `>/dev/console` redirect sends them. The bnuuy sign lives in the
initramfs `/run` and is lost with the VM; every phase it records is also
logged at info on the console.

Interactive use: `lab.sh up noble`, `lab.sh ssh noble`, `lab.sh down noble`.
`WABBIT_LAB_KEEP=1` keeps the overlay and console log after a failure for
inspection; `lab.sh clean` deletes all run state (never the cache).

Host requirements: `qemu-system-xvm`, `qemu-img`, `mtools` (or rootless
`podman`), an ssh key, and `/dev/kvm` for acceleration (falls back to TCG
without it).

## Vagrant + VirtualBox (secondary path)

For hosts with VirtualBox, the `Vagrantfile` defines the same four distros
(`ubuntu2404`, `ubuntu2204`, `debian12`, `rocky9`), with linked clones and
2 GB of RAM each; `vagrant up <name>` one at a time. It provisions the same
musl artifact plus `bpftool`/`bpftrace` for debugging and sets `lsm=bpf` on
the kernel command line (a reboot is required after the first `vagrant
up`). VirtualBox is not usable on the current build host, which is why the
QEMU lab above is the primary path.

## Kernel compatibility expectations

bnuuy's LSM hook layout follows mainline: the `bpf` hook reads its phony
`retval` at index 4 (only valid once `security_bpf` grew its `bool kernel`
parameter), `kernel_read_file` denies loads with `READING_MODULE == 2`
(the value the enum has had since it gained a leading `UNKNOWN` entry), and
`path_mknod`'s phony `retval` sits at index 4 behind its `dev` argument.
Older kernels predate parts of this layout: a mismatched arg count fails
cleanly at program load (the sign explains it), while a shifted enum value
leaves the module-load denial inert. The lab verifies each distro
empirically; expect Ubuntu 24.04 (kernel 6.8) to match mainline exactly and
older kernels to vary.

The guests use host-only networking in the Vagrant setup and user-mode
networking (with ssh forwarded to 127.0.0.1) in the QEMU lab; neither should
be exposed to untrusted networks.