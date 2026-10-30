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
//! # Posture
//!
//! Each gate's reach is a separate policy choice (the `network` section,
//! loaded into [`NET_POSTURE`]), so either can be narrowed or switched
//! off without touching the other:
//!
//! * bind: [`BIND_GATE_ALL`] gates every IP bind — the port-0 binds
//!   clients make before connecting included; [`BIND_GATE_PORTS`] gates
//!   only a bind naming a specific port (`sin_port`/`sin6_port`, both at
//!   offset 2 of the uapi sockaddr), so claiming a port needs the bit
//!   and outbound connectivity never does; [`BIND_GATE_OFF`] gates
//!   nothing.
//! * raw capture: [`RAW_CAPTURE_GATE_ALL`] gates `AF_PACKET` and raw IP;
//!   [`RAW_CAPTURE_GATE_ICMP`] exempts raw ICMP (`IPPROTO_ICMP` at
//!   `AF_INET`, `IPPROTO_ICMPV6` at `AF_INET6` — `ping`, `traceroute`)
//!   and still gates `AF_PACKET` and every other raw IP protocol (a raw
//!   TCP or UDP socket receives copies of every inbound packet of its
//!   protocol); [`RAW_CAPTURE_GATE_OFF`] gates
//!   nothing.
//!
//! Both strictest postures are `0`, the unpopulated map's value.
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
//! * **ephemeral listeners under [`BIND_GATE_PORTS`]** — a port-0 bind
//!   (or a `listen(2)` with no bind at all, which autobinds) still
//!   yields a listener, on a port the kernel picks: the posture gates
//!   claiming a *chosen* port, not listening as such.

use aya_ebpf::{bindings, helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use wabbit_common::authorization::{
    ACTION_BIND_NET, ACTION_RAW_CAPTURE, BIND_GATE_ALL, BIND_GATE_OFF, BIND_GATE_PORTS,
    NET_POSTURE_BIND, NET_POSTURE_RAW_CAPTURE, RAW_CAPTURE_GATE_ALL, RAW_CAPTURE_GATE_ICMP,
    RAW_CAPTURE_GATE_OFF,
};

use crate::{
    lsm::trust::{self, EPERM},
    maps::NET_POSTURE,
};

/// `AF_INET` (2) — IPv4 sockets.
const AF_INET: i32 = 2;
/// `AF_INET6` (10) — IPv6 sockets.
const AF_INET6: i32 = 10;
/// `AF_PACKET` (17) — the packet socket: every frame on every interface.
const AF_PACKET: i32 = 17;

/// `IPPROTO_ICMP` (1) — raw ICMP at `AF_INET`: `ping`'s socket.
const IPPROTO_ICMP: i32 = 1;
/// `IPPROTO_ICMPV6` (58) — raw ICMPv6 at `AF_INET6`: `ping -6`'s socket.
const IPPROTO_ICMPV6: i32 = 58;

/// `SOCK_TYPE_MASK` (`0xf`, from `uapi/linux/socket.h`): the type bits
/// of the socket(2) flags argument, below `SOCK_CLOEXEC`/`SOCK_NONBLOCK`.
const SOCK_TYPE_MASK: i32 = 0xf;
/// `SOCK_RAW` (3): the type raw IP sockets — and sniffers — carry.
const SOCK_RAW: i32 = 3;

/// One gate's posture from [`NET_POSTURE`]; a missing slot reads as the
/// strictest posture (`0`).
#[inline(always)]
fn posture(index: u32) -> u32 {
    NET_POSTURE.get(index).copied().unwrap_or(0)
}

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
    let icmp_exempt = match posture(NET_POSTURE_RAW_CAPTURE) {
        RAW_CAPTURE_GATE_ALL => false,
        RAW_CAPTURE_GATE_ICMP => true,
        RAW_CAPTURE_GATE_OFF => return 0,
        // An unknown value is a loader bug: gate as strictly as `ALL`.
        _ => false,
    };
    let family = ctx.arg::<i32>(0);
    let raw = ctx.arg::<i32>(1) & SOCK_TYPE_MASK == SOCK_RAW;
    // The ICMP exception matches the protocol to its own family only:
    // `IPPROTO_ICMP` at `AF_INET6` (or the reverse) is no ping socket.
    let protocol = ctx.arg::<i32>(2);
    let capture = match family {
        AF_PACKET => true,
        AF_INET => raw && !(icmp_exempt && protocol == IPPROTO_ICMP),
        AF_INET6 => raw && !(icmp_exempt && protocol == IPPROTO_ICMPV6),
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
/// `AF_INET`/`AF_INET6` bind needs [`ACTION_BIND_NET`] — every such bind
/// under [`BIND_GATE_ALL`], only one naming a specific port under
/// [`BIND_GATE_PORTS`]; every other family — local `AF_UNIX` IPC and
/// netlink above all — passes untouched, trusted or not.
///
/// `security_socket_bind(sock, address, addrlen)` — the address is arg 1
/// (the kernel's copy of the caller's sockaddr), phony retval at index
/// 3. Only `sa_family` (offset 0) and, under [`BIND_GATE_PORTS`], the
/// port (offset 2 in both `sockaddr_in` and `sockaddr_in6`) are read,
/// through `bpf_probe_read_kernel`: the uapi sockaddr heads are stable
/// across the matrix, and a probe read of them cannot fail for a kernel
/// resident address — but if it somehow does, the bind falls to
/// fail-open (allow), the house rule for a protection whose failure
/// must never wedge the machine. (The kernel's copy is a
/// `sockaddr_storage`, so the port read stays in bounds even for an
/// `addrlen` too short to carry one — and `inet_bind`/`inet6_bind`
/// reject such an address with `EINVAL` after this hook anyway.)
#[lsm(hook = "socket_bind")]
pub fn bind_gate(ctx: LsmContext) -> i32 {
    // LSM_HOOK(int, 0, socket_bind, struct socket *sock,
    //          struct sockaddr *address, int addrlen) — the phony
    // retval is index 3, read once, first.
    let retval = ctx.arg::<i32>(3);
    if retval != 0 {
        return retval;
    }
    let ports_only = match posture(NET_POSTURE_BIND) {
        BIND_GATE_ALL => false,
        BIND_GATE_PORTS => true,
        BIND_GATE_OFF => return 0,
        // An unknown value is a loader bug: gate as strictly as `ALL`.
        _ => false,
    };
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
    if ports_only {
        // Port 0 asks the kernel for an ephemeral port: the client
        // shape, never a claim on a chosen one. Zero is zero in either
        // byte order.
        let Ok(port) = (unsafe { bpf_probe_read_kernel((address as *const u16).wrapping_add(1)) })
        else {
            return 0;
        };
        if port == 0 {
            return 0;
        }
    }
    if trust::trusted() {
        return 0;
    }
    let allowed = trust::current_authorized(ACTION_BIND_NET);
    trust::verdict(trust::HOOK_BIND, if allowed { 0 } else { EPERM })
}
