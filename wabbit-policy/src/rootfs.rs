//! The `rootfs` policy section: how the root filesystem and individual paths are mounted.
//!
//! Wire layout, all integers little endian:
//!
//! ```text
//! RootFSConfig:
//!   flags     u8: bit 0 executable, bit 1 writable; the other bits must be 0
//!   count     u32, at most MAX_OVERRIDES
//!   PathOverride * count:
//!     flags     u8: bits 0..=5 inner_writable, inner_executable, outer_writable,
//!               outer_executable, outer_readable, outer_visible; bits 6 and 7 must be 0
//!     priority  u16
//!     path      u32 length + UTF-8 bytes
//!     inner_path  u8 marker (0 = absent, 1 = present), then (if present) the same as `path`
//! ```

use std::path::PathBuf;

use bilge::prelude::*;
use binrw::binrw;

use super::wire::{read_optional_path, read_path, write_optional_path, write_path};

const MAX_OVERRIDES: usize = 65_535;

/// Mount flags applied to the root of the filesystem.
#[bitsize(2, new = pub)]
#[derive(FromBits, DebugBits, Clone, Copy, PartialEq, Eq)]
pub struct RootFlags {
    /// Whether the root should NOT be mounted NOEXEC.
    pub executable: bool,
    /// Whether the root should NOT be mounted RDONLY.
    pub writable: bool,
}

/// Mount flags of a [`PathOverride`].
#[bitsize(6, new = pub)]
#[derive(FromBits, DebugBits, Clone, Copy, PartialEq, Eq)]
pub struct PathFlags {
    /// Whether the path mounted to the privileged namespace should NOT be mounted RDONLY.
    pub inner_writable: bool,
    /// Whether the path mounted to the privileged namespace should NOT be mounted NOEXEC.
    pub inner_executable: bool,
    /// Whether the path mounted to the root namespace should NOT be mounted RDONLY.
    pub outer_writable: bool,
    /// Whether the path mounted to the root namespace should NOT be mounted NOEXEC.
    pub outer_executable: bool,
    /// Whether the path mounted to the root namespace should have read permissions for non-root users
    pub outer_readable: bool,
    /// Whether the path mounted to the root namespace should NOT be hidden by wabbit-ebpf.
    pub outer_visible: bool,
}

// The field order of these types is the wire order.

#[binrw]
#[brw(little)]
#[derive(Clone, Debug, PartialEq)]
pub struct PathOverride {
    #[br(try_map = |bits: u8| u6::try_new(bits).map(PathFlags::from))]
    #[bw(map = |flags: &PathFlags| u6::from(*flags).value())]
    pub flags: PathFlags,
    /// The layer in the mount stack at which this mount should be applied
    pub priority: u16,
    /// The path to modify in the root namespace.
    #[br(parse_with = read_path)]
    #[bw(write_with = write_path)]
    pub path: PathBuf,
    /// The path to mount to the privileged namespace.
    #[br(parse_with = read_optional_path)]
    #[bw(write_with = write_optional_path)]
    pub inner_path: Option<PathBuf>,
}

#[binrw]
#[brw(little)]
#[derive(Clone, Debug, PartialEq)]
pub struct RootFSConfig {
    #[br(try_map = |bits: u8| u2::try_new(bits).map(RootFlags::from))]
    #[bw(map = |flags: &RootFlags| u2::from(*flags).value())]
    pub flags: RootFlags,
    #[br(temp, assert(override_count as usize <= MAX_OVERRIDES, "policy contains too many overrides"))]
    #[bw(try_calc = u32::try_from(overrides.len()))]
    override_count: u32,
    #[br(count = override_count)]
    #[bw(assert(overrides.len() <= MAX_OVERRIDES, "policy contains too many overrides"))]
    pub overrides: Vec<PathOverride>,
}

impl Default for RootFSConfig {
    fn default() -> Self {
        Self {
            flags: RootFlags::new(true, true),
            overrides: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use binrw::{BinRead, BinWrite};

    use super::*;

    fn sample() -> RootFSConfig {
        RootFSConfig {
            flags: RootFlags::new(false, true),
            overrides: vec![
                PathOverride {
                    flags: PathFlags::new(true, false, false, true, true, false),
                    priority: 42,
                    path: "/sysroot/var".into(),
                    inner_path: Some("/var".into()),
                },
                PathOverride {
                    flags: PathFlags::new(false, false, false, false, false, true),
                    priority: 1,
                    path: "/sysroot/etc".into(),
                    inner_path: None,
                },
            ],
        }
    }

    fn encode(config: &RootFSConfig) -> binrw::BinResult<Vec<u8>> {
        let mut writer = Cursor::new(Vec::new());
        config.write(&mut writer)?;
        Ok(writer.into_inner())
    }

    fn decode(bytes: &[u8]) -> binrw::BinResult<RootFSConfig> {
        RootFSConfig::read(&mut Cursor::new(bytes))
    }

    #[test]
    fn round_trips() {
        assert_eq!(decode(&encode(&sample()).unwrap()).unwrap(), sample());
    }

    #[test]
    fn default_round_trips() {
        let config = RootFSConfig::default();
        assert_eq!(decode(&encode(&config).unwrap()).unwrap(), config);
    }

    #[test]
    fn encodes_documented_layout() {
        let expected = [
            // executable = 0, writable = 1; two overrides
            &[0b10][..],
            &2u32.to_le_bytes(),
            // inner_writable, outer_executable and outer_readable
            &[0b01_1001],
            &42u16.to_le_bytes(),
            &12u32.to_le_bytes(),
            b"/sysroot/var",
            &[1],
            &4u32.to_le_bytes(),
            b"/var",
            // outer_visible only
            &[0b10_0000],
            &1u16.to_le_bytes(),
            &12u32.to_le_bytes(),
            b"/sysroot/etc",
            &[0],
        ]
        .concat();
        assert_eq!(encode(&sample()).unwrap(), expected);
    }

    #[test]
    fn rejects_reserved_flag_bits_and_bad_markers() {
        // Root flags only have two bits.
        let mut bytes = encode(&sample()).unwrap();
        bytes[0] = 0b100;
        assert!(decode(&bytes).is_err());

        // Path flags only have six bits.
        let mut bytes = encode(&sample()).unwrap();
        bytes[1 + 4] = 0b100_0000;
        assert!(decode(&bytes).is_err());

        // The inner path marker of the second override is the final byte.
        let mut bytes = encode(&sample()).unwrap();
        *bytes.last_mut().unwrap() = 2;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_non_utf8_paths() {
        let mut config = sample();
        config.overrides.truncate(1);
        let mut bytes = encode(&config).unwrap();
        // Corrupt the first byte of "/sysroot/var".
        bytes[1 + 4 + 1 + 2 + 4] = 0xff;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = encode(&sample()).unwrap();
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rejects_too_many_overrides() {
        let mut config = sample();
        config.overrides = vec![config.overrides[0].clone(); MAX_OVERRIDES + 1];
        let error = encode(&config).unwrap_err();
        assert!(error.to_string().contains("too many overrides"), "{error}");

        // A claimed count over the limit is rejected before any override is read.
        let mut bytes = vec![0b11];
        bytes.extend_from_slice(&u32::try_from(MAX_OVERRIDES + 1).unwrap().to_le_bytes());
        let error = decode(&bytes).unwrap_err();
        assert!(error.to_string().contains("too many overrides"), "{error}");
    }
}
