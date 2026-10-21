use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::filesystem::{PathOverride, RootFSConfig};

/// WSPF / "Wabbit Signed Policy File"
pub const MAGIC: &[u8; 4] = b"WSPF";
/// Trusted Ed25519 public key for policy files.
pub const POLICY_PUBLIC_KEY: &str = wabbit_common::keys::POLICY_PUBLIC_KEY;
const VERSION: u16 = 1;
const SIGNATURE_SIZE: usize = 64;
const MAX_POLICY_SIZE: usize = 16 * 1024 * 1024;
const MAX_OVERRIDES: usize = 65_535;

/// Read a versioned binary policy file.
pub fn read_file(path: impl AsRef<Path>) -> Result<RootFSConfig> {
    let path = path.as_ref();
    let bytes = fs::read(path).with_context(|| format!("reading policy {}", path.display()))?;
    from_bytes(&bytes).with_context(|| format!("parsing policy {}", path.display()))
}

/// Parse a complete binary policy. No bytes may follow the encoded policy.
pub fn from_bytes(bytes: &[u8]) -> Result<RootFSConfig> {
    from_bytes_with_public_key(bytes, POLICY_PUBLIC_KEY)
}

fn from_bytes_with_public_key(bytes: &[u8], public_key: &str) -> Result<RootFSConfig> {
    if bytes.len() > MAX_POLICY_SIZE {
        bail!("policy exceeds maximum size of {MAX_POLICY_SIZE} bytes");
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(4)? != MAGIC {
        bail!("invalid policy magic");
    }
    if cursor.u16()? != VERSION {
        bail!("unsupported policy version");
    }
    let signature = cursor.take(SIGNATURE_SIZE)?;
    let payload_start = cursor.position;
    verify_signature(
        &bytes[..6]
            .iter()
            .chain(bytes[payload_start..].iter())
            .copied()
            .collect::<Vec<_>>(),
        signature,
        public_key,
    )?;

    let config = RootFSConfig {
        executable: cursor.bool()?,
        writable: cursor.bool()?,
        overrides: decode_overrides(&mut cursor)?,
    };
    cursor.finish()?;
    Ok(config)
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

/// Encode a policy with an Ed25519 signature over its header and payload.
pub fn to_signed_bytes(config: &RootFSConfig, signature: &[u8; SIGNATURE_SIZE]) -> Result<Vec<u8>> {
    if config.overrides.len() > MAX_OVERRIDES {
        bail!("policy contains too many overrides");
    }
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.extend_from_slice(signature);
    output.push(config.executable as u8);
    output.push(config.writable as u8);
    put_u32(&mut output, config.overrides.len())?;
    for override_ in &config.overrides {
        output.push(override_.inner_writable as u8);
        output.push(override_.inner_executable as u8);
        output.push(override_.outer_writable as u8);
        output.push(override_.outer_executable as u8);
        output.push(override_.outer_readable as u8);
        output.push(override_.outer_visible as u8);
        output.extend_from_slice(&override_.priority.to_le_bytes());
        put_path(&mut output, &override_.path)?;
        match &override_.inner_path {
            Some(path) => {
                output.push(1);
                put_path(&mut output, path)?;
            }
            None => output.push(0),
        }
    }
    Ok(output)
}

pub fn write_new_signed(
    path: impl AsRef<Path>,
    config: &RootFSConfig,
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<()> {
    let path = path.as_ref();
    let bytes = to_signed_bytes(config, signature)?;
    let mut file = fs::File::create_new(path)
        .with_context(|| format!("creating policy {}", path.display()))?;
    std::io::Write::write_all(&mut file, &bytes)?;
    Ok(())
}

fn decode_overrides(cursor: &mut Cursor<'_>) -> Result<Vec<PathOverride>> {
    let count = cursor.u32()?;
    if count > MAX_OVERRIDES {
        bail!("policy contains too many overrides");
    }
    let mut overrides = Vec::with_capacity(count);
    for _ in 0..count {
        overrides.push(PathOverride {
            inner_writable: cursor.bool()?,
            inner_executable: cursor.bool()?,
            outer_writable: cursor.bool()?,
            outer_executable: cursor.bool()?,
            outer_readable: cursor.bool()?,
            outer_visible: cursor.bool()?,
            priority: cursor.u16()?,
            path: cursor.path()?,
            inner_path: if cursor.bool()? {
                Some(cursor.path()?)
            } else {
                None
            },
        });
    }
    Ok(overrides)
}

fn put_path(output: &mut Vec<u8>, path: &Path) -> Result<()> {
    let path = path.to_str().context("policy paths must be valid UTF-8")?;
    let bytes = path.as_bytes();
    put_u32(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_u32(output: &mut Vec<u8>, value: usize) -> Result<()> {
    output.extend_from_slice(
        &u32::try_from(value)
            .context("policy field is too large")?
            .to_le_bytes(),
    );
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("policy length overflow")?;
        let value = self
            .bytes
            .get(self.position..end)
            .context("truncated policy")?;
        self.position = end;
        Ok(value)
    }

    fn bool(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => bail!("invalid policy boolean"),
        }
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }

    fn u32(&mut self) -> Result<usize> {
        Ok(usize::try_from(u32::from_le_bytes(
            self.take(4)?.try_into()?,
        ))?)
    }

    fn path(&mut self) -> Result<PathBuf> {
        let length = self.u32()?;
        Ok(PathBuf::from(
            std::str::from_utf8(self.take(length)?).context("policy path is not UTF-8")?,
        ))
    }

    fn finish(&self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            bail!("trailing bytes in policy")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RootFSConfig {
        RootFSConfig {
            executable: false,
            writable: true,
            overrides: vec![PathOverride {
                inner_writable: true,
                inner_executable: false,
                outer_writable: false,
                outer_executable: true,
                outer_readable: true,
                outer_visible: false,
                path: "/sysroot/var".into(),
                inner_path: Some("/var".into()),
                priority: 42,
            }],
        }
    }

    #[test]
    fn round_trips_policy() {
        let config = sample();
        let mut bytes = to_signed_bytes(&config, &[0; SIGNATURE_SIZE]).unwrap();
        let message = [&bytes[..6], &bytes[6 + SIGNATURE_SIZE..]].concat();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        bytes[6..6 + SIGNATURE_SIZE]
            .copy_from_slice(&ed25519_dalek::Signer::sign(&signing_key, &message).to_bytes());
        assert_eq!(
            from_bytes_with_public_key(
                &bytes,
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            )
            .unwrap(),
            config
        );
    }

    #[test]
    fn rejects_bad_version_and_trailing_bytes() {
        let mut bytes = to_signed_bytes(&sample(), &[0; SIGNATURE_SIZE]).unwrap();
        bytes[4] = 2;
        assert!(from_bytes(&bytes).is_err());
        let mut bytes = to_signed_bytes(&sample(), &[0; SIGNATURE_SIZE]).unwrap();
        bytes.push(0);
        assert!(from_bytes(&bytes).is_err());
    }
}
