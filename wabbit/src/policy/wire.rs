//! `binrw` helpers shared by the policy sections.
//!
//! `binrw` has no built-in length-prefixed string, so paths are encoded here, and
//! [`invalid`] gives the other helpers (and sections) a uniform way to report bad input.

use std::{
    io::{Read, Seek, Write},
    path::PathBuf,
};

use binrw::{BinRead, BinResult, BinWrite, Endian, Error, helpers::count};

/// An error for malformed policy data found at stream position `pos`.
pub(super) fn invalid(pos: u64, message: &str) -> Error {
    Error::AssertFail {
        pos,
        message: message.into(),
    }
}

/// Read a `u32` length followed by that many bytes of UTF-8.
pub(super) fn read_path<R: Read + Seek>(
    reader: &mut R,
    endian: Endian,
    (): (),
) -> BinResult<PathBuf> {
    let pos = reader.stream_position()?;
    let length = u32::read_options(reader, endian, ())?;
    let bytes: Vec<u8> = count(length as usize)(reader, endian, ())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid(pos, "policy path is not UTF-8"))?;
    Ok(text.into())
}

// `binrw` passes the field as `&PathBuf`, so the signature can't be `&Path`.
#[allow(clippy::ptr_arg)]
pub(super) fn write_path<W: Write + Seek>(
    path: &PathBuf,
    writer: &mut W,
    endian: Endian,
    (): (),
) -> BinResult<()> {
    let pos = writer.stream_position()?;
    let bytes = path
        .to_str()
        .ok_or_else(|| invalid(pos, "policy paths must be valid UTF-8"))?
        .as_bytes();
    let length =
        u32::try_from(bytes.len()).map_err(|_| invalid(pos, "policy field is too large"))?;
    length.write_options(writer, endian, ())?;
    bytes.write_options(writer, endian, ())
}

/// Read a marker byte (`0` = absent, `1` = present), then the path if it is present.
pub(super) fn read_optional_path<R: Read + Seek>(
    reader: &mut R,
    endian: Endian,
    (): (),
) -> BinResult<Option<PathBuf>> {
    let pos = reader.stream_position()?;
    match u8::read_options(reader, endian, ())? {
        0 => Ok(None),
        1 => read_path(reader, endian, ()).map(Some),
        _ => Err(invalid(pos, "invalid optional path marker")),
    }
}

pub(super) fn write_optional_path<W: Write + Seek>(
    path: &Option<PathBuf>,
    writer: &mut W,
    endian: Endian,
    (): (),
) -> BinResult<()> {
    match path {
        None => 0u8.write_options(writer, endian, ()),
        Some(path) => {
            1u8.write_options(writer, endian, ())?;
            write_path(path, writer, endian, ())
        }
    }
}
