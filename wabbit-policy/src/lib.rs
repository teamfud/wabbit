//! Signed binary policy files in the WSPF ("Wabbit Signed Policy File") format.
//!
//! A [`Policy`] is a set of optional sections, one per kind of configuration:
//! [`rootfs`] (how the root filesystem and individual paths are mounted) and
//! [`authorization`] (per-cgroup classes for the steady-state gates). Each
//! future kind (for example initrd modification or a kernel module allowlist)
//! is another section in its own submodule.
//!
//! Wire layout, all integers little endian:
//!
//! ```text
//! magic       "WSPF"
//! version     u16, currently 4
//! key_id      u8, an index into POLICY_PUBLIC_KEYS naming the signing key
//! signature   [u8; 64], Ed25519 over (magic || version || key_id || sections)
//! sections    u8, one bit per section that follows; unknown bits must be 0
//!               bit 0: rootfs
//!               bit 1: authorization
//! rootfs      a `rootfs::RootFSConfig`, present only if bit 0 is set
//! authorization an `authorization::AuthorizationConfig`, present only if
//!             bit 1 is set
//! ```
//!
//! Sections appear in bit order and each appears at most once, so every policy
//! has exactly one encoding. A reader rejects section bits it does not know,
//! rather than ignoring a section it cannot enforce.
//!
//! # Adding a section
//!
//! 1. Define the section's `#[binrw]` type in a new submodule, reusing
//!    [`wire`] helpers, and add a `validate` covering its contracts.
//! 2. In [`Sections`], add a `bool` for it and widen `#[bitsize(N)]`,
//!    `from_byte` and `to_byte`.
//! 3. In [`Policy`], add a `pub name: Option<T>` field after the existing
//!    ones, read with `#[br(if(sections.name()))]`, include it in the
//!    `Sections::new(..)` that is written, and handle it in
//!    [`Policy::merge`].
//! 4. Bump [`VERSION`].
//!
//! # Off-box generation
//!
//! The CLI (this crate's `bin`, built with `--features cli`) generates and
//! audits policies: `gen-key` makes the keypair (the public half is pasted
//! into `wabbit-common/src/keys.rs`; the private half never reaches a
//! target), `build` compiles TOML source into a signed file with
//! generator-side validation, and `inspect` verifies and decodes a file
//! for audit anywhere.

use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use bilge::prelude::*;
use binrw::{BinRead, BinWrite, binrw};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub mod authorization;
pub mod rootfs;
mod wire;

use authorization::AuthorizationConfig;
use rootfs::RootFSConfig;

/// WSPF / "Wabbit Signed Policy File"
pub const MAGIC: &[u8; 4] = b"WSPF";
/// Every trusted policy-signing public key, as `(id, key)` pairs: the
/// header names the signing key, verification looks it up here.
pub const POLICY_PUBLIC_KEYS: &[(u8, &str)] = wabbit_common::keys::POLICY_PUBLIC_KEYS;
const VERSION: u16 = 4;
const SIGNATURE_SIZE: usize = 64;
/// Size of an Ed25519 private key: the 32-byte secret seed.
pub const PRIVATE_KEY_SIZE: usize = 32;
/// Size of the magic, version and key id, which precede the signature.
const PREFIX_SIZE: usize = MAGIC.len() + size_of::<u16>() + size_of::<u8>();
const MAX_POLICY_SIZE: usize = 16 * 1024 * 1024;

/// Which sections a policy contains, one bit each, in wire order.
#[bitsize(2)]
#[derive(FromBits, Clone, Copy)]
struct Sections {
    rootfs: bool,
    authorization: bool,
}

impl Sections {
    /// Decode the sections byte, rejecting bits for sections this version doesn't know about.
    fn from_byte(byte: u8) -> Result<Self, &'static str> {
        u2::try_new(byte)
            .map(Self::from)
            .map_err(|_| "policy contains unsupported sections")
    }

    fn to_byte(self) -> u8 {
        u2::from(self).value()
    }
}

/// Everything a policy file can configure. A section is `None` if the file doesn't contain it.
#[binrw]
#[brw(little)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Policy {
    #[br(temp, try_map = Sections::from_byte)]
    #[bw(calc = Sections::new(rootfs.is_some(), authorization.is_some()), map = Sections::to_byte)]
    sections: Sections,
    /// How the root filesystem and individual paths are mounted.
    #[br(if(sections.rootfs()))]
    pub rootfs: Option<RootFSConfig>,
    /// Per-cgroup authorization classes for the steady-state gates.
    #[br(if(sections.authorization()))]
    pub authorization: Option<AuthorizationConfig>,
}

impl Policy {
    /// Replace each section with the one from `newer`, keeping the sections `newer` omits.
    pub fn merge(&mut self, newer: Policy) {
        self.rootfs = newer.rootfs.or(self.rootfs.take());
        self.authorization = newer.authorization.or(self.authorization.take());
    }
}

#[binrw]
#[brw(little, magic = b"WSPF")]
struct Header {
    #[br(temp, assert(version == VERSION, "unsupported policy version"))]
    #[bw(calc = VERSION)]
    version: u16,
    /// Which of [`POLICY_PUBLIC_KEYS`] signed this policy. Verification
    /// looks the key up by id; an unknown id is rejected by name.
    key_id: u8,
    signature: [u8; SIGNATURE_SIZE],
}

/// Read a versioned binary policy file.
pub fn read_file(path: impl AsRef<Path>) -> Result<Policy> {
    let path = path.as_ref();
    let bytes = fs::read(path).with_context(|| format!("reading policy {}", path.display()))?;
    from_bytes(&bytes).with_context(|| format!("parsing policy {}", path.display()))
}

/// Parse a complete binary policy against every trusted key. No bytes may
/// follow the encoded policy.
pub fn from_bytes(bytes: &[u8]) -> Result<Policy> {
    if bytes.len() > MAX_POLICY_SIZE {
        bail!("policy exceeds maximum size of {MAX_POLICY_SIZE} bytes");
    }
    let mut reader = Cursor::new(bytes);
    let header = Header::read(&mut reader).context("invalid policy header")?;

    // Authenticate everything after the header before interpreting it.
    // The header names its key; an unknown id is rejected by name.
    let public_key = POLICY_PUBLIC_KEYS
        .iter()
        .find(|(id, _)| *id == header.key_id)
        .map(|(_, key)| *key)
        .with_context(|| {
            format!(
                "policy is signed with unknown key id {} (trusted: {})",
                header.key_id,
                POLICY_PUBLIC_KEYS
                    .iter()
                    .map(|(id, _)| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    verify_signature(&signed_message(bytes), &header.signature, public_key)?;

    let policy = Policy::read(&mut reader).context("invalid policy body")?;
    if reader.position() != bytes.len() as u64 {
        bail!("trailing bytes in policy");
    }
    Ok(policy)
}

/// Parse a complete binary policy against one specific key: no key-id
/// matching, just verify the signature against `public_key` (hex or
/// base64). `wabbit-policy inspect --public-key` uses this for deployed
/// keypairs whose key was never compiled in (the env override is
/// `option_env!` — build-time only); tests use it with their own keys.
pub fn from_bytes_with_key(bytes: &[u8], public_key: &str) -> Result<Policy> {
    if bytes.len() > MAX_POLICY_SIZE {
        bail!("policy exceeds maximum size of {MAX_POLICY_SIZE} bytes");
    }
    let mut reader = Cursor::new(bytes);
    let header = Header::read(&mut reader).context("invalid policy header")?;
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

/// The bytes covered by the signature: the magic, version, key id and
/// payload, but not the signature.
///
/// `bytes` must be at least as long as the policy header.
fn signed_message(bytes: &[u8]) -> Vec<u8> {
    [
        &bytes[..PREFIX_SIZE],
        &bytes[PREFIX_SIZE + SIGNATURE_SIZE..],
    ]
    .concat()
}

/// Sign a policy with an Ed25519 private key and encode it as a complete
/// policy file carrying `key_id`.
///
/// `private_key` is the 32-byte Ed25519 secret seed. The result verifies
/// against the `key_id`'s entry in [`POLICY_PUBLIC_KEYS`] — the generator
/// pastes the public half there (see `gen-key`) before the target's wabbit
/// build, so no private key ever reaches a target.
pub fn sign(policy: &Policy, key_id: u8, private_key: &[u8; PRIVATE_KEY_SIZE]) -> Result<Vec<u8>> {
    let mut bytes = to_signed_bytes(policy, key_id, &[0; SIGNATURE_SIZE])?;
    let signature = SigningKey::from_bytes(private_key).sign(&signed_message(&bytes));
    bytes[PREFIX_SIZE..PREFIX_SIZE + SIGNATURE_SIZE].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Encode a policy with a placeholder signature over its header and payload.
pub fn to_signed_bytes(
    policy: &Policy,
    key_id: u8,
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<Vec<u8>> {
    let mut writer = Cursor::new(Vec::new());
    Header {
        key_id,
        signature: *signature,
    }
    .write(&mut writer)
    .context("encoding policy header")?;
    policy.write(&mut writer).context("encoding policy body")?;
    Ok(writer.into_inner())
}

/// Write a policy carrying a placeholder signature to a new file. The
/// caller patches the signature ([`sign`]) — kept for compatibility with
/// the placeholder-based test fixtures.
pub fn write_new_signed(
    path: impl AsRef<Path>,
    policy: &Policy,
    key_id: u8,
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<()> {
    let path = path.as_ref();
    let bytes = to_signed_bytes(policy, key_id, signature)?;
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

    /// RFC 8032 §7.1 test vector 1: a keypair no production binary trusts.
    const TEST_KEY_ID: u8 = 7;
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
            authorization: Some(authorization::AuthorizationConfig::default()),
        }
    }

    fn signed_sample() -> Vec<u8> {
        sign(&sample(), TEST_KEY_ID, &TEST_PRIVATE_KEY).unwrap()
    }

    /// Re-sign bytes that a test has modified.
    fn resign(bytes: &mut [u8]) {
        let signature =
            ed25519_dalek::SigningKey::from_bytes(&TEST_PRIVATE_KEY).sign(&signed_message(bytes));
        bytes[PREFIX_SIZE..PREFIX_SIZE + SIGNATURE_SIZE].copy_from_slice(&signature.to_bytes());
    }

    fn parse(bytes: &[u8]) -> Result<Policy> {
        from_bytes_with_key(bytes, TEST_PUBLIC_KEY)
    }

    #[test]
    fn round_trips_policy() {
        assert_eq!(parse(&signed_sample()).unwrap(), sample());
    }

    #[test]
    fn round_trips_policy_without_sections() {
        let bytes = sign(&Policy::default(), TEST_KEY_ID, &TEST_PRIVATE_KEY).unwrap();
        assert_eq!(parse(&bytes).unwrap(), Policy::default());
    }

    #[test]
    fn encodes_documented_layout() {
        let with_rootfs = Policy {
            rootfs: Some(RootFSConfig::default()),
            authorization: None,
        };
        let expected = [
            b"WSPF".as_slice(),
            &4u16.to_le_bytes(),
            // key id
            &[TEST_KEY_ID],
            &[7; SIGNATURE_SIZE],
            // sections: rootfs
            &[0b1],
            // RootFSConfig: executable and writable, no overrides
            &[0b11],
            &0u32.to_le_bytes(),
        ]
        .concat();
        assert_eq!(
            to_signed_bytes(&with_rootfs, TEST_KEY_ID, &[7; SIGNATURE_SIZE]).unwrap(),
            expected
        );

        let empty = [
            b"WSPF".as_slice(),
            &4u16.to_le_bytes(),
            &[TEST_KEY_ID],
            &[7; SIGNATURE_SIZE],
            &[0b0],
        ]
        .concat();
        assert_eq!(
            to_signed_bytes(&Policy::default(), TEST_KEY_ID, &[7; SIGNATURE_SIZE]).unwrap(),
            empty
        );
    }

    #[test]
    fn sign_only_fills_in_the_signature() {
        let signed = signed_sample();
        let unsigned = to_signed_bytes(&sample(), TEST_KEY_ID, &[0; SIGNATURE_SIZE]).unwrap();
        assert_eq!(signed.len(), unsigned.len());
        assert_eq!(signed[..PREFIX_SIZE], unsigned[..PREFIX_SIZE]);
        assert_ne!(signed[PREFIX_SIZE..BODY_START], [0; SIGNATURE_SIZE]);
        assert_eq!(signed[BODY_START..], unsigned[BODY_START..]);
    }

    #[test]
    fn rejects_policy_signed_with_another_key() {
        // The signature verifies, but against a key no entry names.
        let bytes = sign(
            &sample(),
            TEST_KEY_ID.wrapping_add(1),
            &[1; PRIVATE_KEY_SIZE],
        )
        .unwrap();
        assert!(parse(&bytes).is_err());
        // And a wrong key under the right id fails verification.
        let bytes = sign(&sample(), TEST_KEY_ID, &[1; PRIVATE_KEY_SIZE]).unwrap();
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn from_bytes_rejects_unknown_key_ids() {
        // The full production entry point names the trusted ids in its error.
        let error = from_bytes(&signed_sample()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("unknown key id {}", TEST_KEY_ID)),
            "{error}"
        );
    }

    #[test]
    fn rejects_bad_version_and_trailing_bytes() {
        let mut bytes = signed_sample();
        bytes.push(0);
        resign(&mut bytes);
        assert!(parse(&bytes).is_err());

        let mut bytes = signed_sample();
        // The version sits at MAGIC.len(): bump it to a version that never existed.
        bytes[MAGIC.len()] = 99;
        bytes[MAGIC.len() + 1] = 0;
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
        bytes[BODY_START] |= 0b100;
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
            authorization: None,
        };
        current.merge(replacement.clone());
        assert_eq!(current.rootfs, replacement.rootfs);
        // The omitted authorization section survives the merge.
        assert_eq!(current.authorization, sample().authorization);
    }
}
