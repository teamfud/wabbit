# wabbit

the stupidest blue team rootkit ever

THIS IS FOR EDUCATIONAL USE BY BLUE TEAMS IN REGULATED CTFs ONLY. DO NOT USE THIS TO COMMIT CRIMES. IT WILL BE REALLY BAD AT IT.

NOT an edr

abuses cgroups and eBPF to create a "higher-than-root" privileged class of processes on a system, immune to many types of red team tampering.

## Documentation

- [docs/wabbit-initrd.md](docs/wabbit-initrd.md) — the exact boot sequence
  `wabbit-initrd` follows, its failure-safety design, and the full log of
  every kernel, verifier, and toolchain problem solved to make it work on
  real distro kernels.
- [AGENTS.md](AGENTS.md) — the architecture reference for working on the
  codebase.
- [vm/README.md](vm/README.md) — the QEMU + KVM test lab.



## License

With the exception of eBPF code, wabbit is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
