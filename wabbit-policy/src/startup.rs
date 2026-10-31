//! The `startup` policy section: programs the boot itself launches, each
//! in the class it names, at the point in startup it chose.
//!
//! Wire layout, all integers little endian:
//!
//! ```text
//! StartupConfig:
//!   entry_count   u32, at most MAX_STARTUP_ENTRIES
//!   StartupEntry * entry_count:
//!     kind          u8                        0 initrd, 1 systemd, 2 unit
//!     unit          u32 length + UTF-8 bytes  empty unless kind 2
//!     class         u32 length + UTF-8 bytes  empty = the classless floor
//!     timeout_secs  u32                       unit polling only, 0 = forever
//!     argv_count    u32, 1..=MAX_ARGV
//!     argv          argv_count * (u32 length + UTF-8 bytes)
//! ```
//!
//! # The points
//!
//! * [`StartupKind::Initrd`] — as early as a policy program can run: the
//!   guard is enforcing and the boot is still in the initramfs, before
//!   `switch_root`. A program still running at `switch_root` is killed by
//!   a systemd initrd's sweep (only `argv[0][0] == '@'` survives) and
//!   runs on a deleted ramfs under a busybox one — the point is for
//!   short one-shots.
//! * [`StartupKind::Systemd`] — systemd is up and wabbit has crossed into
//!   the booted system.
//! * [`StartupKind::Unit`] — the named systemd unit has reached active:
//!   `multi-user.target`, `systemd-networkd-wait-online.service` ("wait
//!   online succeeded"), or any other unit a deployment waits on.
//!
//! The signature on the policy is what authorizes these runs — the same
//! trust a signed IPC run command buys, spent at boot instead of over the
//! socket — so there is no anti-replay id to burn: each entry runs
//! exactly once per boot. The runtime half lives in `wabbit`'s
//! `startup` module; every run gets the same ephemeral-cgroup treatment
//! an IPC run gets.
//!
//! # Validation
//!
//! [`StartupConfig::validate`] enforces every documented contract — a
//! unit only on the unit point and only a valid unit name, a valid class
//! name (or none), a non-empty argv of NUL-free, bounded strings — and
//! both the generator (`wabbit-policy build`) and wabbit's launcher call
//! it before anything runs.

use binrw::binrw;
use wabbit_common::cgroup_types::{CLASS_NAME_MAX_BYTES, valid_class_name};

use crate::wire::{read_string, write_string};

/// At most this many startup entries.
pub const MAX_STARTUP_ENTRIES: usize = 64;
/// At most this many argv entries per startup entry (`argv[0]` plus its
/// arguments).
pub const MAX_ARGV: usize = 64;
/// At most this many bytes per argv entry (a program path or argument).
pub const ARG_MAX_BYTES: usize = 4096;
/// At most this many bytes in a unit name (systemd's own unit-name cap).
pub const UNIT_MAX_BYTES: usize = 255;
/// The `timeout_secs` a `[[startup]]` entry carries when the TOML
/// omits the key (the generator applies it, so the authored and wire
/// shapes agree): a finite default, so a policy that forgets the key
/// cannot wait forever. `timeout_secs = 0` opts out and waits forever.
pub const DEFAULT_TIMEOUT_SECS: u32 = 300;

/// One point in system startup a `[[startup]]` program can launch at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupKind {
    /// The initramfs phase: after the guard enforces, before
    /// `switch_root`.
    Initrd,
    /// systemd is up: wabbit has crossed into the booted system.
    Systemd,
    /// The named unit (`unit`) has reached active.
    Unit,
}

impl StartupKind {
    /// This point's wire value.
    const fn wire_value(self) -> u8 {
        match self {
            Self::Initrd => 0,
            Self::Systemd => 1,
            Self::Unit => 2,
        }
    }

    /// The point a wire value names, or an error for a value no version
    /// ever wrote.
    fn from_wire(value: u8) -> Result<Self, &'static str> {
        match value {
            0 => Ok(Self::Initrd),
            1 => Ok(Self::Systemd),
            2 => Ok(Self::Unit),
            _ => Err("unknown startup point"),
        }
    }
}

/// A unit name the unit point may poll with `systemctl is-active`: the
/// systemd unit charset (ASCII alphanumerics plus `:`, `.`, `_`, `@`,
/// `-`), no `/` (a unit name is not a path here), no leading `-` (it
/// would read as an option to the poll command), 1..=[`UNIT_MAX_BYTES`]
/// bytes. Template instances (`foo@bar.service`) need nothing more — `@`
/// is in the set.
pub fn valid_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= UNIT_MAX_BYTES
        && !name.starts_with('-')
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'@' | b'-')
        })
}

/// A length-prefixed UTF-8 string on the wire, as its own type so a
/// `Vec` of them can be `count`-read (binrw has no built-in
/// length-prefixed string, and a bare `String` cannot be the `count`
/// element).
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireString {
    #[br(parse_with = read_string)]
    #[bw(write_with = write_string)]
    pub value: String,
}

/// One `[[startup]]` program: the point it launches at, the class it
/// runs under, and its argv.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, PartialEq)]
pub struct StartupEntry {
    /// The point in startup this program launches at.
    #[br(try_map = StartupKind::from_wire)]
    #[bw(map = |kind: &StartupKind| kind.wire_value())]
    pub kind: StartupKind,
    /// The unit the [`StartupKind::Unit`] point polls; empty for every
    /// other point.
    #[br(parse_with = read_string)]
    #[bw(write_with = write_string)]
    pub unit: String,
    /// The class this run executes under (the same convention a signed
    /// IPC run's class resolves through); empty = the classless floor:
    /// no authorization of its own, so the policy default when there is
    /// one and the deny-by-default floor otherwise.
    #[br(parse_with = read_string)]
    #[bw(write_with = write_string)]
    pub class: String,
    /// How long the unit point may wait for its unit, in seconds; `0`
    /// waits forever. Every other point launches immediately, so a
    /// nonzero timeout on them is rejected. The TOML source's absent
    /// key becomes [`DEFAULT_TIMEOUT_SECS`] (the generator applies it),
    /// so an entry that forgets the key cannot wait forever.
    pub timeout_secs: u32,
    #[br(temp, assert(argv_count as usize <= MAX_ARGV, "too many argv entries"))]
    #[bw(try_calc = u32::try_from(argv.len()))]
    argv_count: u32,
    /// The program and its arguments: `argv[0]` is the program, the
    /// rest its arguments. Non-empty — an entry that names no program
    /// is rejected.
    #[br(count = argv_count)]
    #[bw(assert(argv.len() <= MAX_ARGV, "too many argv entries"))]
    pub argv: Vec<WireString>,
}

impl StartupEntry {
    /// Enforce this entry's contracts (see the module docs): a unit only
    /// on the unit point (and only a valid unit name), a valid class name
    /// or none, no timeout on the immediate points, and a non-empty argv
    /// of NUL-free, bounded strings. Both the generator and wabbit's
    /// launcher call this before anything runs.
    pub fn validate(&self) -> Result<(), String> {
        match self.kind {
            StartupKind::Initrd | StartupKind::Systemd => {
                if !self.unit.is_empty() {
                    return Err(format!(
                        "the {:?} point takes no unit (found {:?})",
                        self.kind, self.unit
                    ));
                }
                if self.timeout_secs != 0 {
                    return Err(format!(
                        "the {:?} point launches immediately: timeout_secs is unit polling only",
                        self.kind
                    ));
                }
            }
            StartupKind::Unit => {
                if !valid_unit_name(&self.unit) {
                    return Err(format!(
                        "unit name {:?} is not a systemd unit name: 1-{UNIT_MAX_BYTES} bytes \
                         of [A-Za-z0-9:.@_-], no leading '-'",
                        self.unit
                    ));
                }
            }
        }
        if !self.class.is_empty() && !valid_class_name(&self.class) {
            return Err(format!(
                "class name {:?} is not valid: 1-{CLASS_NAME_MAX_BYTES} bytes of [a-z0-9-], \
                 no leading or trailing '-'",
                self.class
            ));
        }
        if self.argv.is_empty() {
            return Err("an argv must name a program (at least one entry)".to_string());
        }
        if self.argv.len() > MAX_ARGV {
            return Err(format!(
                "too many argv entries ({}, at most {MAX_ARGV})",
                self.argv.len()
            ));
        }
        for (position, arg) in self.argv.iter().enumerate() {
            if arg.value.len() > ARG_MAX_BYTES {
                return Err(format!(
                    "argv entry {position} is {} bytes (at most {ARG_MAX_BYTES})",
                    arg.value.len()
                ));
            }
            if arg.value.contains('\0') {
                return Err(format!("argv entry {position} contains a NUL"));
            }
        }
        Ok(())
    }
}

/// The `startup` section: one entry per program the boot launches.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StartupConfig {
    #[br(
        temp,
        assert(entry_count as usize <= MAX_STARTUP_ENTRIES, "too many startup entries")
    )]
    #[bw(try_calc = u32::try_from(entries.len()))]
    entry_count: u32,
    #[br(count = entry_count)]
    #[bw(assert(entries.len() <= MAX_STARTUP_ENTRIES, "too many startup entries"))]
    pub entries: Vec<StartupEntry>,
}

impl StartupConfig {
    /// Enforce every entry's contracts (see
    /// [`StartupEntry::validate`]) plus the section's own count bound.
    /// Both the generator and wabbit's loader call this before anything
    /// else sees the data.
    pub fn validate(&self) -> Result<(), String> {
        if self.entries.len() > MAX_STARTUP_ENTRIES {
            return Err(format!(
                "too many startup entries ({}, at most {MAX_STARTUP_ENTRIES})",
                self.entries.len()
            ));
        }
        for (index, entry) in self.entries.iter().enumerate() {
            entry
                .validate()
                .map_err(|error| format!("startup entry {index}: {error}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use binrw::{BinRead, BinWrite};

    use super::*;

    fn sample() -> StartupConfig {
        StartupConfig {
            entries: vec![
                StartupEntry {
                    kind: StartupKind::Initrd,
                    unit: String::new(),
                    class: String::new(),
                    timeout_secs: 0,
                    argv: vec![WireString {
                        value: "/bin/load-secrets".into(),
                    }],
                },
                StartupEntry {
                    kind: StartupKind::Unit,
                    unit: "systemd-networkd-wait-online.service".into(),
                    class: "shell".into(),
                    timeout_secs: 600,
                    argv: vec![
                        WireString {
                            value: "/usr/local/bin/announce".into(),
                        },
                        WireString {
                            value: "--online".into(),
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn round_trips() {
        let mut writer = Cursor::new(Vec::new());
        sample().write(&mut writer).unwrap();
        let back = StartupConfig::read(&mut Cursor::new(writer.into_inner())).unwrap();
        assert_eq!(back, sample());
        sample().validate().unwrap();
    }

    /// The documented layout, byte for byte, for one entry.
    #[test]
    fn encodes_documented_layout() {
        let entry = StartupEntry {
            kind: StartupKind::Initrd,
            unit: String::new(),
            class: String::new(),
            timeout_secs: 0,
            argv: vec![WireString {
                value: "/bin/true".into(),
            }],
        };
        let expected = [
            &[0u8][..],          // kind: initrd
            &0u32.to_le_bytes(), // unit: empty
            &0u32.to_le_bytes(), // class: empty
            &0u32.to_le_bytes(), // timeout_secs: 0
            &1u32.to_le_bytes(), // argv_count: 1
            &9u32.to_le_bytes(), // argv[0] length
            b"/bin/true".as_slice(),
        ]
        .concat();
        let mut writer = Cursor::new(Vec::new());
        entry.write(&mut writer).unwrap();
        assert_eq!(writer.into_inner(), expected);

        // And a unit entry carries its unit before the class.
        let unit = StartupEntry {
            kind: StartupKind::Unit,
            unit: "multi-user.target".into(),
            class: "shell".into(),
            timeout_secs: 300,
            argv: vec![WireString {
                value: "/bin/probe".into(),
            }],
        };
        let mut writer = Cursor::new(Vec::new());
        unit.write(&mut writer).unwrap();
        let bytes = writer.into_inner();
        assert_eq!(bytes[0], 2, "kind: unit");
        // The strings land in the documented field order.
        let mut reader = Cursor::new(&bytes[1..]);
        assert_eq!(
            read_string(&mut reader, binrw::Endian::Little, ()).unwrap(),
            "multi-user.target"
        );
        assert_eq!(
            read_string(&mut reader, binrw::Endian::Little, ()).unwrap(),
            "shell"
        );
    }

    #[test]
    fn rejects_unknown_points() {
        // kind byte 3 names nothing no version ever wrote.
        let bytes = [
            &3u8.to_le_bytes()[..],
            &0u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &[b'x'],
        ]
        .concat();
        assert!(StartupEntry::read(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn rejects_too_many_entries_on_decode() {
        let bytes = [
            &u32::try_from(MAX_STARTUP_ENTRIES + 1)
                .unwrap()
                .to_le_bytes()[..],
            &[0u8; 16 * (MAX_STARTUP_ENTRIES + 1)][..],
        ]
        .concat();
        assert!(StartupConfig::read(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn validates_the_entry_contracts() {
        let base = || StartupEntry {
            kind: StartupKind::Systemd,
            unit: String::new(),
            class: String::new(),
            timeout_secs: 0,
            argv: vec![WireString {
                value: "/bin/true".into(),
            }],
        };

        // A unit only on the unit point…
        let mut entry = base();
        entry.unit = "multi-user.target".into();
        assert!(entry.validate().is_err());

        // …a timeout only on the unit point…
        let mut entry = base();
        entry.timeout_secs = 10;
        assert!(entry.validate().is_err());

        // …and a unit point that is not a unit name.
        for bad in [
            "",
            "-v",
            "has/slash",
            "has space",
            &"x".repeat(UNIT_MAX_BYTES + 1),
        ] {
            let mut entry = base();
            entry.kind = StartupKind::Unit;
            entry.unit = bad.into();
            assert!(entry.validate().is_err(), "unit {bad:?}");
        }

        // The class name is a path component the runtime builds a
        // cgroupfs path from: every shape that could reinterpret is
        // rejected. (The empty string is the *classless* spelling, so
        // it is not in this list — the wire accepts it.)
        for bad in ["../escape", "UPPER", "has space"] {
            let mut entry = base();
            entry.class = bad.into();
            assert!(entry.validate().is_err(), "class {bad:?}");
        }
        let mut entry = base();
        entry.class = "shell".into();
        entry.validate().unwrap();

        // argv: non-empty, bounded, NUL-free.
        let mut entry = base();
        entry.argv = Vec::new();
        assert!(entry.validate().is_err());
        let mut entry = base();
        entry.argv[0].value = "has\0nul".into();
        assert!(entry.validate().is_err());
        let mut entry = base();
        entry.argv[0].value = "x".repeat(ARG_MAX_BYTES + 1);
        assert!(entry.validate().is_err());
        let mut entry = base();
        entry.argv = (0..=MAX_ARGV)
            .map(|_| WireString { value: "x".into() })
            .collect();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn unit_names_are_a_command_injection_boundary() {
        assert!(valid_unit_name("multi-user.target"));
        assert!(valid_unit_name("systemd-networkd-wait-online.service"));
        assert!(valid_unit_name("foo@bar.service"));
        assert!(valid_unit_name(&"x".repeat(UNIT_MAX_BYTES)));
        // No path, no option, no whitespace, no empty name.
        for bad in [
            "",
            "-v",
            "--quiet",
            "has/slash",
            "has space",
            "run\ttabs",
            &"x".repeat(UNIT_MAX_BYTES + 1),
        ] {
            assert!(!valid_unit_name(bad), "unit {bad:?}");
        }
    }
}
