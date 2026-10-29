//! The bnuuy sign: a forensic trail for a boot that did not go to plan.
//!
//! `wabbit-initrd` writes a small binary log to `/run/bnuuy.bin` — an
//! innocuous-looking runtime file that is unmistakable once examined, since
//! it starts with the magic `BNUY` and its first record explains the format.
//! It records each startup phase, and on any failure the full error chain;
//! the freeze watchdog appends its own record when it fires. A clean boot
//! removes the sign; every other exit — a propagated error, a panic (through
//! the panic hook), a `SIGKILL` the watchdog cleaned up after, or a nonzero
//! wabbit exit — leaves it behind explaining why.
//!
//! The sign must never break `wabbit-initrd` (fail-open, like everything
//! else here): every operation is best-effort, and if the sign cannot be
//! written the boot proceeds without it. It makes no mounts: it uses `/run`
//! as the initrd provides it — tmpfs when the initrd mounted it (initramfs
//! tools, dracut, and systemd initrds all do), the initramfs ramfs
//! otherwise — so it is never persistent either way.
//!
//! The format, also recorded as the file's first record:
//!
//! ```text
//! magic:    4 bytes, "BNUY"
//! version:  u16, little-endian (currently 1)
//! records:  any number of:
//!             u64  little-endian, milliseconds since boot (CLOCK_MONOTONIC)
//!             u8   kind: 0 = doc, 1 = phase, 2 = failure, 3 = watchdog,
//!                         4 = panic
//!             u32  little-endian, payload length
//!             payload bytes, UTF-8 text
//! ```

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    panic::PanicHookInfo,
    path::PathBuf,
};

use log::debug;
use rustix::process::getpid;
use wabbit_common::brand::{NAME, SIGN_MAGIC, SIGN_NAME};

/// Where the sign lives by default: the runtime directory the initrd
/// already provides. No mount is ever made for it.
const DEFAULT_SIGN_DIR: &str = "/run";

/// The sign's magic: `<sign magic>` by default, exactly four bytes,
/// validated at compile time.
const MAGIC: &[u8] = SIGN_MAGIC.as_bytes();

/// The format version, little-endian after the magic.
const FORMAT_VERSION: u16 = 1;

/// The sign's file name, `<sign name>.bin`.
fn sign_file() -> String {
    format!("{SIGN_NAME}.bin")
}

/// Where the sign directory actually is: overridable for testing with
/// `<prefix>_SIGN_DIR` (the watchdog re-exec inherits the environment and so
/// writes to the same place).
fn sign_dir() -> PathBuf {
    env::var_os(format!("{}_SIGN_DIR", wabbit_common::brand::ENV_PREFIX))
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SIGN_DIR))
}

fn sign_path() -> PathBuf {
    sign_dir().join(sign_file())
}

/// The record kinds, as written into the file.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Kind {
    /// The self-describing banner, always first.
    Doc = 0,
    /// A startup phase reached.
    Phase = 1,
    /// A failure: the propagated error, with its whole context chain.
    Failure = 2,
    /// The freeze watchdog fired.
    Watchdog = 3,
    /// A panic, from the panic hook.
    Panic = 4,
}

/// Create the sign and record the start of the run.
///
/// Best-effort by construction: a sign that cannot be written never fails
/// the boot, and every later record is dropped just as silently.
pub fn init() {
    let dir = sign_dir();
    if let Err(error) = fs::create_dir_all(&dir) {
        debug!(
            "cannot create the sign directory {}: {error}",
            dir.display()
        );
        return;
    }
    let file = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(sign_path())
    {
        Ok(mut file) => {
            let _ = file.write_all(MAGIC);
            let _ = file.write_all(&FORMAT_VERSION.to_le_bytes());
            let _ = file.write_all(&encode_record(now_ms(), Kind::Doc, &doc_record()));
            file
        }
        Err(error) => {
            debug!("cannot create the sign: {error}");
            return;
        }
    };
    drop(file);
    phase(&format!(
        "starting {NAME}-initrd (pid {pid})",
        pid = getpid()
    ));
}

/// Record a startup phase.
pub fn phase(message: &str) {
    write_record(Kind::Phase, message);
}

/// Record a failure with its whole error chain, the "why" of the sign.
pub fn failure(error: &anyhow::Error) {
    write_record(Kind::Failure, &format!("{error:#}"));
}

/// Record that the freeze watchdog fired.
pub fn watchdog(message: &str) {
    write_record(Kind::Watchdog, message);
}

/// Remove the sign: a clean boot leaves no artifact behind.
pub fn remove() {
    let _ = fs::remove_file(sign_path());
}

/// Record panics too. The world's rescue is the `Drop` backstop's job; this
/// is only the forensic trail, so the default hook still runs.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
        write_record(Kind::Panic, &info.to_string());
        previous(info);
    }));
}

/// Append one record, best-effort. The sign is only appended to, never
/// created here: a watchdog firing after a clean boot's `remove()` finds
/// nothing and writes nothing, so a successful system carries no artifact.
fn write_record(kind: Kind, message: &str) {
    let Ok(mut file) = OpenOptions::new().append(true).open(sign_path()) else {
        return;
    };
    // One `write_all` on an O_APPEND handle: the only possible concurrent
    // writer is the watchdog, and the two never interleave records in
    // practice.
    let _ = file.write_all(&encode_record(now_ms(), kind, message));
}

/// Milliseconds since boot, from the one clock that is meaningful in an
/// initrd.
fn now_ms() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `timespec` is a plain two-integer struct, valid as an output
    // buffer for `clock_gettime(2)`.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    (now.tv_sec as u64) * 1_000 + (now.tv_nsec as u64) / 1_000_000
}

/// Encode one record.
fn encode_record(timestamp_ms: u64, kind: Kind, message: &str) -> Vec<u8> {
    let mut record = Vec::with_capacity(13 + message.len());
    record.extend_from_slice(&timestamp_ms.to_le_bytes());
    record.push(kind as u8);
    record.extend_from_slice(&(message.len() as u32).to_le_bytes());
    record.extend_from_slice(message.as_bytes());
    record
}

/// The self-describing banner, always the first record.
fn doc_record() -> String {
    format!(
        "{NAME}-initrd boot log (the {SIGN_NAME} sign). This file \
             only exists when a boot did not go to plan; a clean boot \
             removes it. Format: magic \"{SIGN_MAGIC}\", u16 LE version, \
             then records of: u64 LE ms since boot, u8 kind (0 doc, 1 \
             phase, 2 failure, 3 watchdog, 4 panic), u32 LE length, UTF-8 \
             text."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a full sign file, asserting the shape as it goes.
    fn decode(bytes: &[u8]) -> Vec<(u64, u8, String)> {
        assert!(bytes.starts_with(MAGIC), "the magic must lead the file");
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        assert_eq!(version, FORMAT_VERSION);
        let mut records = Vec::new();
        let mut offset = 6;
        while offset < bytes.len() {
            let timestamp = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            let kind = bytes[offset + 8];
            let length =
                u32::from_le_bytes(bytes[offset + 9..offset + 13].try_into().unwrap()) as usize;
            offset += 13;
            let message = String::from_utf8(bytes[offset..offset + length].to_vec()).unwrap();
            offset += length;
            records.push((timestamp, kind, message));
        }
        assert_eq!(offset, bytes.len(), "no trailing bytes");
        records
    }

    #[test]
    fn records_round_trip() {
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        file.extend_from_slice(&encode_record(0, Kind::Doc, &doc_record()));
        file.extend_from_slice(&encode_record(7, Kind::Phase, "stopped the world"));
        file.extend_from_slice(&encode_record(9, Kind::Failure, "no /sys: found magic 0x0"));
        file.extend_from_slice(&encode_record(12, Kind::Watchdog, "parent gone; thawed"));

        let records = decode(&file);
        assert_eq!(records[0].1, Kind::Doc as u8);
        assert_eq!(
            records[1],
            (7, Kind::Phase as u8, "stopped the world".to_owned())
        );
        assert_eq!(
            records[3],
            (12, Kind::Watchdog as u8, "parent gone; thawed".to_owned())
        );
    }

    #[test]
    fn payloads_may_be_any_utf8() {
        let message = "sysroot à /sysroot: usr » monté ✅";
        let record = encode_record(1, Kind::Phase, message);
        let length = u32::from_le_bytes(record[9..13].try_into().unwrap()) as usize;
        assert_eq!(record.len(), 13 + message.len());
        assert_eq!(13 + length, record.len());
        assert_eq!(&record[13..], message.as_bytes());
    }

    #[test]
    fn the_banner_self_documents() {
        let banner = doc_record();
        assert!(banner.contains(SIGN_MAGIC));
        assert!(banner.contains(&format!("{NAME}-initrd")));
        assert!(banner.contains("clean boot removes"));
    }
}
