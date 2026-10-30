//! The network-shape gates — raw capture and socket binding.
//!
//! Two hooks, four scalar-or-uapi arguments, no path resolution, no
//! `struct file`/`struct sock` walks: every value these gates consult is
//! either a hook argument's plain int (the `socket_create` family, type,
//! and kern flags) or the first member of `struct sockaddr` — the
//! `sa_family_t` the kernel copied from the caller's own `bind(2)`
//! argument, a uapi layout stable across the whole matrix. So neither
//! gate needs a sleepable hook, a layout variant, or a per-distro
//! offset: both load everywhere, on every target kernel.
//!
//! * [`raw_capture_gate`] (`socket_create`) — the packet-capture
//!   surface: `AF_PACKET` sockets (tcpdump's channel — every frame on
//!   every interface, other processes' traffic included) and raw IP
//!   sockets (`SOCK_RAW` at the two IP families: hand-crafted packets,
//!   sniffing). One bit lifts both: [`ACTION_RAW_CAPTURE`].
//! * [`bind_gate`] (`socket_bind`) — acquiring a **network** endpoint:
//!   `AF_INET`/`AF_INET6` binds (listeners, services) are
//!   deny-by-default, gated on [`ACTION_BIND_NET`] — the default
//!   posture blocks network sockets and nothing else. Every other
//!   family passes untouched, trusted or not: local `AF_UNIX` binds
//!   (systemd's `/run/systemd/notify`, journald's sockets, dbus, every
//!   service's local listener — the machine's connective tissue) and
//!   netlink binds (udev's uevents, rtnl, audit) are not gated at all.
//!
//! # Residuals
//!
//! * **an inherited socket fd** — the gates sit on socket *creation*
//!   and *bind*, not on the later use of an fd handed across a cgroup
//!   boundary before the gate armed (the same residual the firewall
//!   and bpf gates carry).
//! * **local and netlink binds are ungated** — `AF_UNIX` is every
//!   daemon's connective tissue (systemd, journald, dbus — holding it
//!   hostage to per-unit grants would break every boot), and netlink
//!   binds choose the *groups* received, not a resource processes
//!   contend for.
//! * **`connect(2)` is ungated** — an outbound-only socket reaches the
//!   network without ever binding; the sketch's `socket_connect` shape
//!   would need `struct sock` walks for the interesting fields.

use aya_ebpf::{bindings, helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use wabbit_common::authorization::{ACTION_BIND_NET, ACTION_RAW_CAPTURE};

use crate::lsm::trust::{self, EPERM};

/// `AF_INET` (2) — IPv4 sockets.
const AF_INET: i32 = 2;
/// `AF_INET6` (10) — IPv6 sockets.
const AF_INET6: i32 = 10;
/// `AF_PACKET` (17) — the packet socket: every frame on every interface.
const AF_PACKET: i32 = 17;

/// `SOCK_TYPE_MASK` (`0xf`, from `uapi/linux/socket.h`): the type bits
/// of the socket(2) flags argument, below `SOCK_CLOEXEC`/`SOCK_NONBLOCK`.
const SOCK_TYPE_MASK: i32 = 0xf;
/// `SOCK_RAW` (3): the type raw IP sockets — and sniffers — carry.
const SOCK_RAW: i32 = 3;

/// Deny raw packet capture (see the module docs).
///
/// `security_socket_create(family, type, protocol, kern)` — four scalar
/// arguments, stable 5.14 through 6.8, phony retval at index 4 (the same
/// shape as the netfilter gate on this hook; both attach, and the chain
/// stops at whichever gate denies first).
#[lsm(hook = "socket_create")]
pub fn raw_capture_gate(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, socket_create, int family, int type,
    //          int protocol, int kern) — the phony retval is index 4,
    // read once, first.
    let retval = ctx.arg::<i32>(4);
    if retval != 0 {
        return retval;
    }
    // Narrow first: not a capture surface at all? Untouched, trusted or
    // not — the machine's ordinary sockets must never depend on a gate.
    let family = ctx.arg::<i32>(0);
    let capture = match family {
        AF_PACKET => true,
        AF_INET | AF_INET6 => ctx.arg::<i32>(1) & SOCK_TYPE_MASK == SOCK_RAW,
        _ => false,
    };
    if !capture {
        return 0;
    }
    // Kernel-internal creation passes untouched: kthreads run in the
    // root cgroup, which no policy populates (the same exemption the
    // netfilter gate carries).
    if ctx.arg::<i32>(3) != 0 {
        return 0;
    }
    if trust::trusted() {
        return 0;
    }
    let allowed = trust::current_authorized(ACTION_RAW_CAPTURE);
    trust::verdict(trust::HOOK_SOCKET_CREATE, if allowed { 0 } else { EPERM })
}

/// Deny acquiring a **network** endpoint (see the module docs): the
/// `AF_INET`/`AF_INET6` bind needs [`ACTION_BIND_NET`]; every other
/// family — local `AF_UNIX` IPC and netlink above all — passes
/// untouched, trusted or not.
///
/// `security_socket_bind(sock, address, addrlen)` — the address is arg 1
/// (the kernel's copy of the caller's sockaddr), phony retval at index
/// 3. Only `sa_family` (the first member, offset 0) is read, through
/// `bpf_probe_read_kernel`: the uapi `struct sockaddr` head is stable
/// across the matrix, and a probe read of it cannot fail for a kernel
/// resident address — but if it somehow does, the bind falls to
/// fail-open (allow), the house rule for a protection whose failure
/// must never wedge the machine.
#[lsm(hook = "socket_bind")]
pub fn bind_gate(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, socket_bind, struct socket *sock,
    //          struct sockaddr *address, int addrlen) — the phony
    // retval is index 3, read once, first.
    let retval = ctx.arg::<i32>(3);
    if retval != 0 {
        return retval;
    }
    // Narrow first: only the two IP families are the gate's business.
    // Everything else a machine binds — the local IPC surface, udev's
    // and rtnl's netlink — passes untouched.
    let address = ctx.arg::<*mut bindings::sockaddr>(1);
    let Ok(family) = (unsafe { bpf_probe_read_kernel(address as *const u16) }) else {
        return 0;
    };
    match i32::from(family) {
        AF_INET | AF_INET6 => {}
        _ => return 0,
    }
    if trust::trusted() {
        return 0;
    }
    let allowed = trust::current_authorized(ACTION_BIND_NET);
    trust::verdict(trust::HOOK_BIND, if allowed { 0 } else { EPERM })
}
