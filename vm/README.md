# Wabbit kernel test VMs

This setup follows the layout of the Elmer VM lab: Ubuntu is the default
target, while Debian and Rocky Linux are opt-in compatibility targets. Each
guest receives a host-only address on `192.168.56.0/24` and has nested
virtualization enabled where VirtualBox supports it. Guests receive no source
tree or compiler: the complete userspace/eBPF binary is built on the host and
uploaded during provisioning.

Install VirtualBox and Vagrant, then start the default Ubuntu VM:

```sh
./vm/build-artifact.sh
vagrant up
vagrant ssh
sudo /usr/local/bin/wabbit
```

Rebuild and reprovision after host-side edits with:

```sh
./vm/build-artifact.sh
vagrant provision
```

Start the compatibility guests explicitly:

```sh
vagrant up debian
vagrant up rocky
```

The provisioner installs kernel headers/development files, `bpftool`,
`bpftrace`, Clang/LLVM, and build tools. It requires kernel BTF at
`/sys/kernel/btf/vmlinux`; Aya passes that BTF explicitly to its eBPF loader
for relocations. The guests use host-only networking and should not be exposed
to untrusted networks.
