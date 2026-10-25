# Wabbit kernel test VMs

The target matrix is Rocky 9, Debian 12, Ubuntu 22.04, and Ubuntu
24.04. The lab runs the host-built artifact — the `wabbit-initrd`
executable, static musl, embedding both the `wabbit` binary and the bnuuy
eBPF object — so no VM ever needs a compiler.

## QEMU + KVM lab (the active path)

`vm/qemu/lab.sh` drives everything with QEMU using KVM acceleration and no
root on the host. Cloud images are downloaded once into `vm/qemu/cache/`
(git-ignored, ~0.3–1 GB each); every run boots a throwable overlay on top,
and overlays are deleted on teardown, so steady-state disk use is just the
cached images. Boot one distro at a time.

```sh
./vm/build-artifact.sh            # static musl wabbit-initrd
./vm/qemu/lab.sh test noble       # Ubuntu 24.04: the whole flow, unattended
./vm/qemu/lab.sh test jammy       # Ubuntu 22.04
./vm/qemu/lab.sh test bookworm    # Debian 12
./vm/qemu/lab.sh test rocky       # Rocky 9
```

What `test` does per distro: boots the VM, adds `lsm=bpf` to the kernel
command line and reboots (the BPF LSM must be in the boot list or nothing of
bnuuy can attach — no target distro enables it by default), uploads the
artifact and retrieves the bnuuy sign over ssh, runs `wabbit-initrd`
detached and bounded by `timeout(1)` — exit 124 is the *expected* outcome,
since in a booted system the sysroot poll never completes — with its output
going to a guest-local file the host polls for (the freeze stops sshd too,
so polls just fail fast on ConnectTimeout until the world thaws), and
decodes the sign on the host side. (An earlier design carried the artifact
and sign through a 9p share, which qemu drains even while the guest world
is frozen — but RHEL-family kernels ship no 9p modules, so it could never
work on rocky; ssh works everywhere.) The verdict line looks for `bnuuy
protections attached and verified` in the sign.

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