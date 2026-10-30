//! The `network` policy section: how far the network gates reach.
//!
//! Wire layout:
//!
//! ```text
//! NetworkConfig:
//!   bind         u8: 0 all, 1 ports, 2 off
//!   raw_capture  u8: 0 all, 1 icmp, 2 off
//! ```
//!
//! The values are the `BIND_GATE_*`/`RAW_CAPTURE_GATE_*` constants in
//! `wabbit-common`, which the loader writes into the eBPF `NET_POSTURE`
//! map verbatim; any other value is rejected on decode. The two gates
//! are independent: each reach is its own choice, and what a cgroup may
//! do inside the gated set is still its `bind-net`/`raw-capture` bits.
//!
//! A policy without the section gates at the strictest posture (`all`
//! for both) — the unpopulated map's value, and the behavior before the
//! section existed.

use binrw::binrw;
use wabbit_common::authorization::{
    BIND_GATE_ALL, BIND_GATE_OFF, BIND_GATE_PORTS, RAW_CAPTURE_GATE_ALL, RAW_CAPTURE_GATE_ICMP,
    RAW_CAPTURE_GATE_OFF,
};

/// Which `AF_INET`/`AF_INET6` binds need the `bind-net` action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BindPosture {
    /// Every IP bind — the port-0 binds clients make included.
    #[default]
    All,
    /// Only a bind naming a specific port: listening on a chosen port is
    /// gated, outbound connectivity never is.
    Ports,
    /// No bind is gated.
    Off,
}

/// Which raw sockets need the `raw-capture` action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RawCapturePosture {
    /// `AF_PACKET` and `SOCK_RAW` at the IP families.
    #[default]
    All,
    /// Everything but raw ICMP/ICMPv6, which passes (`ping`,
    /// `traceroute`).
    Icmp,
    /// No raw socket is gated.
    Off,
}

impl BindPosture {
    /// The `NET_POSTURE` value of this posture.
    pub const fn map_value(self) -> u32 {
        match self {
            Self::All => BIND_GATE_ALL,
            Self::Ports => BIND_GATE_PORTS,
            Self::Off => BIND_GATE_OFF,
        }
    }

    fn from_wire(value: u8) -> Result<Self, &'static str> {
        match u32::from(value) {
            BIND_GATE_ALL => Ok(Self::All),
            BIND_GATE_PORTS => Ok(Self::Ports),
            BIND_GATE_OFF => Ok(Self::Off),
            _ => Err("unknown bind posture"),
        }
    }
}

impl RawCapturePosture {
    /// The `NET_POSTURE` value of this posture.
    pub const fn map_value(self) -> u32 {
        match self {
            Self::All => RAW_CAPTURE_GATE_ALL,
            Self::Icmp => RAW_CAPTURE_GATE_ICMP,
            Self::Off => RAW_CAPTURE_GATE_OFF,
        }
    }

    fn from_wire(value: u8) -> Result<Self, &'static str> {
        match u32::from(value) {
            RAW_CAPTURE_GATE_ALL => Ok(Self::All),
            RAW_CAPTURE_GATE_ICMP => Ok(Self::Icmp),
            RAW_CAPTURE_GATE_OFF => Ok(Self::Off),
            _ => Err("unknown raw-capture posture"),
        }
    }
}

// The field order is the wire order.

#[binrw]
#[brw(little)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetworkConfig {
    #[br(try_map = BindPosture::from_wire)]
    #[bw(map = |posture: &BindPosture| posture.map_value() as u8)]
    pub bind: BindPosture,
    #[br(try_map = RawCapturePosture::from_wire)]
    #[bw(map = |posture: &RawCapturePosture| posture.map_value() as u8)]
    pub raw_capture: RawCapturePosture,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use binrw::{BinRead, BinWrite};

    use super::*;

    #[test]
    fn encodes_documented_layout_and_round_trips() {
        let config = NetworkConfig {
            bind: BindPosture::Ports,
            raw_capture: RawCapturePosture::Icmp,
        };
        let mut writer = Cursor::new(Vec::new());
        config.write(&mut writer).unwrap();
        assert_eq!(writer.get_ref(), &[1, 1]);
        let back = NetworkConfig::read(&mut Cursor::new(writer.into_inner())).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn rejects_unknown_postures() {
        assert!(NetworkConfig::read(&mut Cursor::new([3u8, 0])).is_err());
        assert!(NetworkConfig::read(&mut Cursor::new([0u8, 3])).is_err());
    }
}
