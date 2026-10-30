//! The signed IPC command envelope: what an IPC *command* is made of, so
//! `wabbit` (the server) and `wabbit-ipc` (the client) agree on one
//! definition.
//!
//! Every command `wabbit` will act on is signed (Ed25519, the same key
//! family as policy files) and carries two anti-replay anchors:
//!
//! * a **boot id** — the 36-byte ASCII UUID from
//!   `/proc/sys/kernel/random/boot_id`, unique to the boot the command
//!   was minted for. `wabbit` reads its own boot id once per run and
//!   rejects commands minted for any other boot, so a command that
//!   succeeded once can never come back in a later boot, where the
//!   counter below would have reset;
//! * a **command id** — a `u64` that must be *strictly greater* than the
//!   last id `wabbit` accepted this boot. The server burns ids on
//!   acceptance, so replaying the exact bytes of a command that already
//!   ran is rejected by construction.
//!
//! # Wire layout
//!
//! An IPC request is a single request-kind byte, then the command body:
//!
//! ```text
//! request  := 0b100                        (the signed-command kind)
//!             || signature (64 bytes)      (Ed25519 over the signed bytes)
//!             || signed bytes
//! signed bytes := "WBIC"                   (magic; a policy file is "WSPF",
//!                                            so a signed policy can never
//!                                            replay as a command or vice
//!                                            versa)
//!             || version: u8              (currently 1)
//!             || kind: u8                  (1 = run, 2 = reconfigure)
//!             || boot id: 36 ASCII bytes   (dashes included, no newline)
//!             || command id: u64, LE
//!             || payload                   (the command itself)
//! ```
//!
//! The payload is length-prefixed fields — `u32` little-endian byte
//! count, then the bytes — matching the framing the IPC protocol has
//! always used:
//!
//! * **run**: `program` (string), argument count (`u32`), then each
//!   argument (string), then — optionally, and only when the command
//!   names one — `class` (string): the authorization profile the run
//!   executes under. The class must be defined in the target's policy
//!   (the policy crate compiles `[[class]]` blocks into cgroup rules);
//!   the server resolves the name, gives the run its own ephemeral
//!   cgroup, and applies exactly that class's rules to it. A run with
//!   no class gets the same ephemeral cgroup with *no* rules —
//!   deny-by-default, the least-privilege floor. The field's absence
//!   is the older blob shape and decodes as "no class";
//! * **reconfigure**: the bytes of a complete signed policy file (the
//!   `WSPF` blob), which the server verifies *again* against the
//!   policy keys before applying — a reconfigure is double-signed by
//!   construction, once by the command envelope and once by the policy
//!   format itself.
//!
//! # Client-side counter discipline
//!
//! The signer's job is one monotonic `u64` per boot: read the previous
//! value, send with `previous + 1`, persist. A crash between the send and
//! the persist can re-present an id; the server rejects it (strictly
//! greater), and the retry with the next id succeeds — burning is safe.

use core::mem::size_of;

/// The envelope's magic: not `WSPF`, so no signed artifact can replay
/// across the two formats.
pub const MAGIC: &[u8; 4] = b"WBIC";

/// The envelope's version byte.
pub const VERSION: u8 = 1;

/// Payload kind: run a program in the protected namespace.
pub const KIND_RUN: u8 = 1;

/// Payload kind: apply a complete signed policy.
pub const KIND_RECONFIGURE: u8 = 2;

/// The request kind byte on the IPC wire: a signed command.
pub const SIGNED_REQUEST: u8 = 0b100;

/// The length of a boot id: a canonical ASCII UUID, dashes included,
/// no trailing newline.
pub const BOOT_ID_LEN: usize = 36;

/// The fixed length of the signed header (everything before the payload).
pub const HEADER_LEN: usize =
    MAGIC.len() + size_of::<u8>() + size_of::<u8>() + BOOT_ID_LEN + size_of::<u64>();

/// The length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// The decoded, fixed-size part of a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandHeader {
    /// Which payload follows: [`KIND_RUN`] or [`KIND_RECONFIGURE`].
    pub kind: u8,
    /// The boot the command was minted for, as
    /// `/proc/sys/kernel/random/boot_id` spells it.
    pub boot_id: [u8; BOOT_ID_LEN],
    /// The anti-replay counter: strictly increasing per boot.
    pub command_id: u64,
}

impl CommandHeader {
    /// The signed bytes of `header` followed by `payload`: what the
    /// signature covers, byte for byte. Callers pass the whole buffer
    /// (header then payload) to the signer.
    pub fn encode(&self, payload: &[u8], signed: &mut [u8]) -> Result<(), CommandError> {
        if signed.len() != HEADER_LEN + payload.len() {
            return Err(CommandError::BufferSize);
        }
        let mut position = 0;
        self.encode_into(signed, &mut position)?;
        signed[HEADER_LEN..].copy_from_slice(payload);
        Ok(())
    }

    /// The total length of the signed bytes for a payload of
    /// `payload_len` bytes.
    pub const fn signed_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    fn encode_into(&self, out: &mut [u8], position: &mut usize) -> Result<(), CommandError> {
        out.get_mut(*position..*position + MAGIC.len())
            .ok_or(CommandError::BufferSize)?
            .copy_from_slice(MAGIC);
        *position += MAGIC.len();
        out.get_mut(*position..*position + 2)
            .ok_or(CommandError::BufferSize)?
            .copy_from_slice(&[VERSION, self.kind]);
        *position += 2;
        let boot_id = out
            .get_mut(*position..*position + BOOT_ID_LEN)
            .ok_or(CommandError::BufferSize)?;
        boot_id.copy_from_slice(&self.boot_id);
        *position += BOOT_ID_LEN;
        out.get_mut(*position..*position + size_of::<u64>())
            .ok_or(CommandError::BufferSize)?
            .copy_from_slice(&self.command_id.to_le_bytes());
        *position += size_of::<u64>();
        Ok(())
    }
}

/// Decode the fixed-size header from the start of the signed bytes. The
/// payload is whatever follows; the caller slices it.
pub fn decode_header(signed: &[u8]) -> Result<CommandHeader, CommandError> {
    let mut position = 0;
    let magic = signed
        .get(position..position + MAGIC.len())
        .ok_or(CommandError::Truncated)?;
    if magic != MAGIC {
        return Err(CommandError::Magic);
    }
    position += MAGIC.len();
    let [version, kind] = signed
        .get(position..position + 2)
        .ok_or(CommandError::Truncated)?
        .try_into()
        .map_err(|_| CommandError::Truncated)?;
    if version != VERSION {
        return Err(CommandError::Version(version));
    }
    position += 2;
    let boot_id = signed
        .get(position..position + BOOT_ID_LEN)
        .ok_or(CommandError::Truncated)?
        .try_into()
        .map_err(|_| CommandError::Truncated)?;
    position += BOOT_ID_LEN;
    let command_id: [u8; size_of::<u64>()] = signed
        .get(position..position + size_of::<u64>())
        .ok_or(CommandError::Truncated)?
        .try_into()
        .map_err(|_| CommandError::Truncated)?;
    let command_id = u64::from_le_bytes(command_id);
    Ok(CommandHeader {
        kind,
        boot_id,
        command_id,
    })
}

/// Whether `boot_id` spells a canonical boot id: 36 bytes of hex
/// digits with dashes at the UUID positions. Used client-side to fail a
/// typo'd `--boot-id` before it is ever signed; the server simply
/// compares against its own boot id, so a non-canonical value could
/// never match anyway.
pub fn is_canonical_boot_id(boot_id: &[u8]) -> bool {
    if boot_id.len() != BOOT_ID_LEN {
        return false;
    }
    for (index, byte) in boot_id.iter().enumerate() {
        let dash = matches!(index, 8 | 13 | 18 | 23);
        let hex = byte.is_ascii_hexdigit();
        if (dash && *byte != b'-') || (!dash && !hex) {
            return false;
        }
    }
    true
}

/// Why a command envelope could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// A buffer was sized wrong for the operation.
    BufferSize,
    /// The signed bytes ended before the header did.
    Truncated,
    /// The magic is not this format's magic.
    Magic,
    /// The version byte is not one this decoder knows.
    Version(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> CommandHeader {
        let mut boot_id = [0u8; BOOT_ID_LEN];
        boot_id.copy_from_slice(b"01234567-89ab-cdef-0123-456789abcdef");
        CommandHeader {
            kind: KIND_RUN,
            boot_id,
            command_id: 7,
        }
    }

    #[test]
    fn header_round_trips_over_a_payload() {
        let header = header();
        let mut signed = [0u8; HEADER_LEN + b"the payload".len()];
        header.encode(b"the payload", &mut signed).unwrap();
        assert_eq!(&signed[HEADER_LEN..], b"the payload");
        let decoded = decode_header(&signed).unwrap();
        assert_eq!(decoded, header);
        // The header is exactly the fixed prefix: the payload starts
        // right after it.
        assert_eq!(HEADER_LEN, 50);
    }

    #[test]
    fn a_wrong_buffer_is_an_error_not_a_panic() {
        let header = header();
        let mut too_small = [0u8; 8];
        assert_eq!(
            header.encode(b"payload", &mut too_small),
            Err(CommandError::BufferSize)
        );
    }

    #[test]
    fn foreign_magic_is_rejected() {
        let mut signed = [0u8; HEADER_LEN];
        signed[0..4].copy_from_slice(b"WSPF");
        assert_eq!(decode_header(&signed), Err(CommandError::Magic));
    }

    #[test]
    fn truncated_headers_are_rejected() {
        assert_eq!(decode_header(&[MAGIC[0]; 3]), Err(CommandError::Truncated));
        assert_eq!(decode_header(&[]), Err(CommandError::Truncated));
    }

    #[test]
    fn unknown_versions_are_rejected_by_name() {
        let header = header();
        let mut signed = [0u8; HEADER_LEN];
        header.encode(&[], &mut signed).unwrap();
        signed[4] = 99;
        assert_eq!(decode_header(&signed), Err(CommandError::Version(99)));
    }

    #[test]
    fn canonical_boot_ids_are_recognized() {
        assert!(is_canonical_boot_id(
            b"01234567-89ab-cdef-0123-456789abcdef"
        ));
        assert!(!is_canonical_boot_id(
            b"0123456789ab-cdef-0123-456789abcdef"
        ));
        assert!(!is_canonical_boot_id(
            b"01234567-89ab_cdef-0123-456789abcdef"
        ));
        assert!(!is_canonical_boot_id(
            b"01234567-89ab-cdef-0123-456789abcdef\n"
        ));
    }
}
