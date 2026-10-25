//! Signed binary policy files in the WSPF ("Wabbit Signed Policy File") format.
//!
//! A [`Policy`] is a set of optional sections, one per kind of configuration. Today the only
//! section is [`rootfs`]; each future kind (for example initrd modification or a kernel module
//! allowlist) is another section in its own submodule.
//!
//! Wire layout, all integers little endian:
//!
//! ```text
//! magic       "WSPF"
//! version     u16, currently 3
//! signature   [u8; 64], Ed25519 over (magic || version || everything below)
//! sections    u8, one bit per section that follows; unknown bits must be 0
//!               bit 0: rootfs
//! rootfs      a `rootfs::RootFSConfig`, present only if bit 0 of `sections` is set
//! ```
//!
//! Sections appear in bit order and each appears at most once, so every policy has exactly one
//! encoding. A reader rejects section bits it does not know, rather than ignoring a section it
//! cannot enforce.
//!
//! # Adding a section
//!
//! 1. Define the section's `#[binrw]` type in a new submodule, reusing [`wire`] helpers.
//! 2. In [`Sections`], add a `bool` for it and widen `#[bitsize(N)]`, `from_byte` and `to_byte`.
//! 3. In [`Policy`], add a `pub name: Option<T>` field after the existing ones, read with
//!    `#[br(if(sections.name()))]`, include it in the `Sections::new(..)` that is written, and
//!    handle it in [`Policy::merge`].
//! 4. Bump [`VERSION`].

use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use bilge::prelude::*;
use binrw::{BinRead, BinWrite, binrw};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub mod rootfs;
mod wire;

use rootfs::RootFSConfig;

/// WSPF / "Wabbit Signed Policy File"
pub const MAGIC: &[u8; 4] = b"WSPF";
/// Trusted Ed25519 public key for policy files.
pub const POLICY_PUBLIC_KEY: &str = wabbit_common::keys::POLICY_PUBLIC_KEY;
const VERSION: u16 = 3;
const SIGNATURE_SIZE: usize = 64;
/// Size of an Ed25519 private key: the 32-byte secret seed.
pub const PRIVATE_KEY_SIZE: usize = 32;
/// Size of the magic and version, which precede the signature.
const PREFIX_SIZE: usize = MAGIC.len() + size_of::<u16>();
const MAX_POLICY_SIZE: usize = 16 * 1024 * 1024;

/// Which sections a policy contains, one bit each, in wire order.
#[bitsize(1)]
#[derive(FromBits, Clone, Copy)]
struct Sections {
    rootfs: bool,
}

impl Sections {
    /// Decode the sections byte, rejecting bits for sections this version doesn't know about.
    fn from_byte(byte: u8) -> Result<Self, &'static str> {
        u1::try_new(byte)
            .map(Self::from)
            .map_err(|_| "policy contains unsupported sections")
    }

    fn to_byte(self) -> u8 {
        u1::from(self).value()
    }
}

/// Everything a policy file can configure. A section is `None` if the file doesn't contain it.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Policy {
    #[br(temp, try_map = Sections::from_byte)]
    #[bw(calc = Sections::new(rootfs.is_some()), map = Sections::to_byte)]
    sections: Sections,
    /// How the root filesystem and individual paths are mounted.
    #[br(if(sections.rootfs()))]
    pub rootfs: Option<RootFSConfig>,
}

impl Policy {
    /// Replace each section with the one from `newer`, keeping the sections `newer` omits.
    pub fn merge(&mut self, newer: Policy) {
        self.rootfs = newer.rootfs.or(self.rootfs.take());
    }
}

#[binrw]
#[brw(little, magic = b"WSPF")]
struct Header {
    #[br(temp, assert(version == VERSION, "unsupported policy version"))]
    #[bw(calc = VERSION)]
    version: u16,
    signature: [u8; SIGNATURE_SIZE],
}

/// Read a versioned binary policy file.
pub fn read_file(path: impl AsRef<Path>) -> Result<Policy> {
    let path = path.as_ref();
    let bytes = fs::read(path).with_context(|| format!("reading policy {}", path.display()))?;
    from_bytes(&bytes).with_context(|| format!("parsing policy {}", path.display()))
}

/// Parse a complete binary policy. No bytes may follow the encoded policy.
pub fn from_bytes(bytes: &[u8]) -> Result<Policy> {
    from_bytes_with_public_key(bytes, POLICY_PUBLIC_KEY)
}

fn from_bytes_with_public_key(bytes: &[u8], public_key: &str) -> Result<Policy> {
    if bytes.len() > MAX_POLICY_SIZE {
        bail!("policy exceeds maximum size of {MAX_POLICY_SIZE} bytes");
    }
    let mut reader = Cursor::new(bytes);
    let header = Header::read(&mut reader).context("invalid policy header")?;

    // Authenticate everything after the header before interpreting it.
    verify_signature(&signed_message(bytes), &header.signature, public_key)?;

    let policy = Policy::read(&mut reader).context("invalid policy body")?;
    if reader.position() != bytes.len() as u64 {
        bail!("trailing bytes in policy");
    }
    Ok(policy)
}

fn verify_signature(bytes: &[u8], signature: &[u8], public_key: &str) -> Result<()> {
    let signature = Signature::from_slice(signature).context("invalid Ed25519 signature")?;
    let key_bytes = hex::decode(public_key)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, public_key))
        .context("policy public key must be base64 or hexadecimal")?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("policy public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes)
        .context("invalid policy public key")?
        .verify(bytes, &signature)
        .context("policy signature verification failed")
}

/// The bytes covered by the signature: the magic, version and payload, but not the signature.
///
/// `bytes` must be at least as long as the policy header.
fn signed_message(bytes: &[u8]) -> Vec<u8> {
    [
        &bytes[..PREFIX_SIZE],
        &bytes[PREFIX_SIZE + SIGNATURE_SIZE..],
    ]
    .concat()
}

/// Replace the signature in an encoded policy with one made by `private_key`.
fn sign_in_place(bytes: &mut [u8], private_key: &[u8; PRIVATE_KEY_SIZE]) {
    let signature = SigningKey::from_bytes(private_key).sign(&signed_message(bytes));
    bytes[PREFIX_SIZE..PREFIX_SIZE + SIGNATURE_SIZE].copy_from_slice(&signature.to_bytes());
}

/// Sign a policy with an Ed25519 private key and encode it as a complete policy file.
///
/// `private_key` is the 32-byte Ed25519 secret seed. The result verifies against the
/// matching public key, which must be the compiled-in [`POLICY_PUBLIC_KEY`] for
/// [`from_bytes`] to accept it.
pub fn sign(policy: &Policy, private_key: &[u8; PRIVATE_KEY_SIZE]) -> Result<Vec<u8>> {
    let mut bytes = to_signed_bytes(policy, &[0; SIGNATURE_SIZE])?;
    sign_in_place(&mut bytes, private_key);
    Ok(bytes)
}

/// Encode a policy with an Ed25519 signature over its header and payload.
pub fn to_signed_bytes(policy: &Policy, signature: &[u8; SIGNATURE_SIZE]) -> Result<Vec<u8>> {
    let mut writer = Cursor::new(Vec::new());
    Header {
        signature: *signature,
    }
    .write(&mut writer)
    .context("encoding policy header")?;
    policy.write(&mut writer).context("encoding policy body")?;
    Ok(writer.into_inner())
}

pub fn write_new_signed(
    path: impl AsRef<Path>,
    policy: &Policy,
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<()> {
    let path = path.as_ref();
    let bytes = to_signed_bytes(policy, signature)?;
    let mut file = fs::File::create_new(path)
        .with_context(|| format!("creating policy {}", path.display()))?;
    file.write_all(&bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        rootfs::{PathFlags, PathOverride, RootFlags},
        *,
    };

    const TEST_PUBLIC_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TEST_PRIVATE_KEY: [u8; PRIVATE_KEY_SIZE] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const BODY_START: usize = PREFIX_SIZE + SIGNATURE_SIZE;

    fn sample() -> Policy {
        Policy {
            rootfs: Some(RootFSConfig {
                flags: RootFlags::new(false, true),
                overrides: vec![PathOverride {
                    flags: PathFlags::new(true, false, false, true, true, false),
                    priority: 42,
                    path: "/sysroot/var".into(),
                    inner_path: Some("/var".into()),
                }],
            }),
        }
    }

    fn signed_sample() -> Vec<u8> {
        sign(&sample(), &TEST_PRIVATE_KEY).unwrap()
    }

    /// Re-sign bytes that a test has modified.
    fn resign(bytes: &mut [u8]) {
        sign_in_place(bytes, &TEST_PRIVATE_KEY);
    }

    fn parse(bytes: &[u8]) -> Result<Policy> {
        from_bytes_with_public_key(bytes, TEST_PUBLIC_KEY)
    }

    #[test]
    fn round_trips_policy() {
        assert_eq!(parse(&signed_sample()).unwrap(), sample());
    }

    #[test]
    fn round_trips_policy_without_sections() {
        let bytes = sign(&Policy::default(), &TEST_PRIVATE_KEY).unwrap();
        assert_eq!(parse(&bytes).unwrap(), Policy::default());
    }

    #[test]
    fn encodes_documented_layout() {
        let with_rootfs = Policy {
            rootfs: Some(RootFSConfig::default()),
        };
        let expected = [
            b"WSPF".as_slice(),
            &3u16.to_le_bytes(),
            &[7; SIGNATURE_SIZE],
            // sections: rootfs
            &[0b1],
            // RootFSConfig: executable and writable, no overrides
            &[0b11],
            &0u32.to_le_bytes(),
        ]
        .concat();
        assert_eq!(
            to_signed_bytes(&with_rootfs, &[7; SIGNATURE_SIZE]).unwrap(),
            expected
        );

        let empty = [
            b"WSPF".as_slice(),
            &3u16.to_le_bytes(),
            &[7; SIGNATURE_SIZE],
            &[0b0],
        ]
        .concat();
        assert_eq!(
            to_signed_bytes(&Policy::default(), &[7; SIGNATURE_SIZE]).unwrap(),
            empty
        );
    }

    #[test]
    fn sign_only_fills_in_the_signature() {
        let signed = signed_sample();
        let unsigned = to_signed_bytes(&sample(), &[0; SIGNATURE_SIZE]).unwrap();
        assert_eq!(signed.len(), unsigned.len());
        assert_eq!(signed[..PREFIX_SIZE], unsigned[..PREFIX_SIZE]);
        assert_ne!(signed[PREFIX_SIZE..BODY_START], [0; SIGNATURE_SIZE]);
        assert_eq!(signed[BODY_START..], unsigned[BODY_START..]);
    }

    #[test]
    fn rejects_policy_signed_with_another_key() {
        let bytes = sign(&sample(), &[1; PRIVATE_KEY_SIZE]).unwrap();
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_version_and_trailing_bytes() {
        let mut bytes = signed_sample();
        bytes.push(0);
        resign(&mut bytes);
        assert!(parse(&bytes).is_err());

        let mut bytes = signed_sample();
        bytes[4] = 2;
        resign(&mut bytes);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_magic_truncation_and_tampering() {
        let bytes = signed_sample();

        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert!(parse(&bad_magic).is_err());

        assert!(parse(&bytes[..bytes.len() - 1]).is_err());

        let mut tampered = bytes.clone();
        tampered[BODY_START + 1] ^= 1;
        assert!(parse(&tampered).is_err());
    }

    #[test]
    fn rejects_unknown_sections() {
        // A section bit this version doesn't know about must not be silently ignored.
        let mut bytes = signed_sample();
        bytes[BODY_START] |= 0b10;
        resign(&mut bytes);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_a_section_that_is_missing_or_unannounced() {
        // The rootfs bit is set but its contents are cut off.
        let mut bytes = signed_sample();
        bytes.truncate(BODY_START + 1);
        resign(&mut bytes);
        assert!(parse(&bytes).is_err());

        // The contents are present but the rootfs bit is clear.
        let mut bytes = signed_sample();
        bytes[BODY_START] = 0;
        resign(&mut bytes);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn merge_replaces_only_provided_sections() {
        let mut current = sample();

        current.merge(Policy::default());
        assert_eq!(current, sample());

        let replacement = Policy {
            rootfs: Some(RootFSConfig::default()),
        };
        current.merge(replacement.clone());
        assert_eq!(current, replacement);
    }
}
