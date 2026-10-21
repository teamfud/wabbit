use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Extract the payload from a signed string.
///
/// The first line must contain a standard-base64 Ed25519 signature. Every byte
/// after the first newline is the signed payload and is returned unchanged.
pub fn extract_signed_string(signed: &str) -> Result<&str> {
    let (_, payload) = signed
        .split_once('\n')
        .context("signed string is missing its payload")?;
    let signature = signed
        .split_once('\n')
        .map(|(signature, _)| signature)
        .unwrap_or_default();
    decode_signature(signature)?;
    Ok(payload)
}

/// Verify a signed string with an Ed25519 public key and return its payload.
///
/// `public_key` may be standard-base64 or hexadecimal encoded. Surrounding
/// whitespace is ignored, but the signed payload is never normalized.
pub fn verify_signed_string<'a>(signed: &'a str, public_key: &str) -> Result<&'a str> {
    let (encoded_signature, payload) = signed
        .split_once('\n')
        .context("signed string is missing its payload")?;
    let signature = decode_signature(encoded_signature)?;
    let verifying_key = parse_public_key(public_key)?;
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .context("signed string verification failed")?;
    Ok(payload)
}

fn decode_signature(encoded: &str) -> Result<Signature> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .context("invalid base64 signature")?;
    Signature::from_slice(&bytes).context("Ed25519 signature must be 64 bytes")
}

fn parse_public_key(encoded: &str) -> Result<VerifyingKey> {
    let encoded = encoded.trim();
    let bytes = hex::decode(encoded)
        .or_else(|_| STANDARD.decode(encoded))
        .context("public key must be base64 or hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn extracts_and_verifies_payload() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let payload = "root filesystem policy";
        let signature = signing_key.sign(payload.as_bytes());
        let signed = format!("{}\n{payload}", STANDARD.encode(signature.to_bytes()));

        assert_eq!(
            verify_signed_string(
                &signed,
                &STANDARD.encode(signing_key.verifying_key().to_bytes())
            )
            .unwrap(),
            payload
        );
        assert_eq!(extract_signed_string(&signed).unwrap(), payload);
    }

    #[test]
    fn rejects_tampering() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let signature = signing_key.sign(b"trusted");
        let signed = format!("{}\ntampered", STANDARD.encode(signature.to_bytes()));

        assert!(
            verify_signed_string(
                &signed,
                &hex::encode(signing_key.verifying_key().to_bytes())
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_malformed_signed_strings() {
        assert!(extract_signed_string("not a signed string").is_err());
        assert!(extract_signed_string("%%% \npayload").is_err());
    }
}
