//! The firewall gates — two hooks, one authorization bit, two paths.
//!
//! Modern firewall management never calls `setsockopt`. nftables — and
//! everything speaking it: `nft` itself, `iptables-nft`/`ip6tables-nft`
//! (the defaults on every target distro), `ebtables-nft`,
//! `arptables-nft`, firewalld, ipset (v6+), conntrack-tools — manages
//! rules over **nfnetlink**: `socket(AF_NETLINK, SOCK_RAW,
//! NETLINK_NETFILTER)` and netlink message batches. The legacy
//! xtables path (`iptables-legacy`, `ip6tables-legacy`) is the
//! `setsockopt(fd, SOL_IP|SOL_IPV6, IPT_SO_SET_REPLACE|…)` one.
//!
//! One bit — [`ACTION_FIREWALL`] — lifts both:
//!
//! * [`firewall_gate`] (`socket_setsockopt`) — the legacy path: rule
//!   replacement and counter adds, at the two IP levels. Deliberately
//!   narrow — only the two firewall optnames, because `setsockopt` is
//!   load-bearing for everything on the machine.
//! * [`netfilter_netlink_gate`] (`socket_create`) — the modern path:
//!   creating a netfilter netlink socket at all. `NETLINK_NETFILTER` is
//!   the whole netfilter management channel (nft, ipset, conntrack,
//!   nfqueue), so gating it denies rule changes *and* the rest of the
//!   netfilter management surface — the honest semantics of
//!   "may modify firewall".
//!
//! Both hooks are stable across the matrix (verified against the 5.14
//! and 6.8 `lsm_hook_defs.h`), and neither gate resolves a path, so
//! neither needs a sleepable hook or a `struct file` variant: they load
//! everywhere, on every target kernel.
//!
//! # Residuals
//!
//! * **an inherited socket fd** — a process that inherits an open
//!   netfilter netlink socket (or a legacy xtables fd) from an
//!   authorized process keeps it across the cgroup boundary. The same
//!   residual the bpf map fds carry; `socket_connect`/`sendmsg`/`bind`
//!   variants would need `struct sock` walks (`sk_protocol`), the
//!   exact class of unstable-offset walks this design forbids.
//! * **kernel-internal creation is exempt** — `socket_create` fires with
//!   `kern == 1` for kernel-initiated sockets; the gate passes them
//!   untouched (and kernel-side nfnetlink sockets go through
//!   `netlink_kernel_create`, which never reaches this hook at all).
//! * **rule *reads*** — `getsockopt`/netlink dumps are not gated;
//!   read-only visibility is not part of the bit.

use aya_ebpf::{macros::lsm, programs::LsmContext};
use wabbit_common::authorization::ACTION_FIREWALL;

use crate::lsm::trust::{self, EPERM};

/// `SOL_IP`, which is `IPPROTO_IP` (0) — the level iptables legacy uses.
const SOL_IP: i32 = 0;
/// `SOL_IPV6`, which is `IPPROTO_IPV6` (41) — the level ip6tables uses.
const SOL_IPV6: i32 = 41;

/// `IPT_SO_SET_REPLACE` (`IPT_BASE_CTL`), from
/// `uapi/linux/netfilter_ipv4/ip_tables.h`; ip6tables uses the same
/// values (`IP6T_BASE_CTL`).
const IPT_SO_SET_REPLACE: i32 = 64;
/// `IPT_SO_SET_ADD_COUNTERS` (`IPT_BASE_CTL + 1`).
const IPT_SO_SET_ADD_COUNTERS: i32 = 65;

/// `AF_NETLINK` (16).
const AF_NETLINK: i32 = 16;

/// `NETLINK_NETFILTER` (12): nfnetlink — nftables, iptables-nft,
/// firewalld, ipset, conntrack-tools, nfqueue.
const NETLINK_NETFILTER: i32 = 12;

/// Deny legacy firewall rule changes (see the module docs).
///
/// `security_socket_setsockopt(sock, level, optname)` runs at the top of
/// every `setsockopt(2)` (verified against the 5.14 source; the hook is
/// unchanged through 6.8). The denial is deliberately narrow — only the
/// two firewall optnames at the two IP levels — because `setsockopt` is
/// load-bearing for everything on the machine.
#[lsm(hook = "socket_setsockopt")]
pub fn firewall_gate(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, socket_setsockopt, struct socket *sock,
    //          int level, int optname) — the phony retval is index 3,
    // read once, first (the register-invariant shape; see kmod.rs).
    let retval = ctx.arg::<i32>(3);
    if retval != 0 {
        return retval;
    }
    let level = ctx.arg::<i32>(1);
    let optname = ctx.arg::<i32>(2);
    // Narrow first: only the two IP levels, only the two firewall
    // optnames. Every other setsockopt on the machine passes untouched,
    // trusted or not.
    if level != SOL_IP && level != SOL_IPV6 {
        return 0;
    }
    if optname != IPT_SO_SET_REPLACE && optname != IPT_SO_SET_ADD_COUNTERS {
        return 0;
    }
    if trust::trusted() {
        return 0;
    }
    let allowed = trust::current_authorized(ACTION_FIREWALL);
    trust::verdict(trust::HOOK_SETSOCKOPT, if allowed { 0 } else { EPERM })
}

/// Deny creating a netfilter netlink socket (see the module docs) — the
/// nftables path.
///
/// `security_socket_create(family, type, protocol, kern)` — four scalar
/// arguments, stable 5.14 through 6.8, phony retval at index 4. No
/// path resolution, so no sleepable hook is needed: loads everywhere.
#[lsm(hook = "socket_create")]
pub fn netfilter_netlink_gate(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, socket_create, int family, int type,
    //          int protocol, int kern) — the phony retval is index 4,
    // read once, first.
    let retval = ctx.arg::<i32>(4);
    if retval != 0 {
        return retval;
    }
    // Narrow first: only the netlink family, and only the netfilter
    // protocol inside it. Everything else a machine does with sockets —
    // and everything else it does with netlink (rtnl, udev's kobject
    // uevent, audit, scsi) — passes untouched, trusted or not.
    let family = ctx.arg::<i32>(0);
    if family != AF_NETLINK {
        return 0;
    }
    let protocol = ctx.arg::<i32>(2);
    if protocol != NETLINK_NETFILTER {
        return 0;
    }
    // Kernel-internal creation passes untouched: kthreads run in the
    // root cgroup, which no policy populates, and gating them would
    // break kernel socket creation. (Kernel-side nfnetlink sockets go
    // through netlink_kernel_create, which never reaches this hook —
    // this guard is belt-and-braces.)
    let kern = ctx.arg::<i32>(3);
    if kern != 0 {
        return 0;
    }
    if trust::trusted() {
        return 0;
    }
    let allowed = trust::current_authorized(ACTION_FIREWALL);
    trust::verdict(trust::HOOK_SOCKET_CREATE, if allowed { 0 } else { EPERM })
}
