//! Ground-truth BTF reading: the one kernel-struct offset the signal
//! gate's self-guard needs.
//!
//! aya's `Btf` (and `aya-obj`'s beneath it) parses the *program
//! object's* BTF and validates relocations, but its type tables are
//! crate-private: there is no public way to ask "where does
//! `struct task_struct` keep `tgid` *on this kernel*". The self-guard
//! needs exactly that one fact, and it must be ground truth: a
//! compile-time offset is the silent-garbage lesson this workspace
//! already paid once (the distro-patched `sched_process_fork` record —
//! a wrong offset loads fine and reads nonsense as a pid), and
//! `task_struct` is precisely the struct distros patch. So this module
//! walks the running kernel's own `/sys/kernel/btf/vmlinux` by hand —
//! the same shape as the fork watcher's tracepoint-format selection:
//! parse the running kernel's description of itself at load time, never
//! trust a compile-time guess.
//!
//! Only as much of the BTF grammar as the walk needs is implemented —
//! but every kind the format defines is *sized*: an unknown kind would
//! desynchronize the walk silently, so an unknown kind is an error,
//! never a skip.
//!
//! # The format
//!
//! `Documentation/bpf/btf.rst`: a header (magic `0xeb9f`, a version
//! byte, flags, the header's own length, then four offsets and lengths
//! measured from the end of the header), a types section, and a
//! strings section. Each type is a 8-byte-plus-`vlen` record: `name`,
//! `info` (kind in bits 24–28, `vlen` in 0–15, the kind flag in bit
//! 31), and `size`/`type`; `struct`/`union` members are 12 bytes each
//! (name, type, and a *bit* offset — masked to 24 bits when the kind
//! flag is set, which is also how bitfield sizes ride along). The
//! kernel emits it little-endian, and every target of this workspace is
//! little-endian; the parser reads it that way and says so in its
//! magic check.

use std::fs;

use anyhow::{Context, Result, bail};

/// The running kernel's own BTF.
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// BTF magic (`0xeb9f`), little-endian.
const BTF_MAGIC: u16 = 0xeb9f;

// Type kinds, `include/uapi/linux/btf.h`. Every kind is listed because
// the walk must size each record's tail exactly; the `SIZE_*` consts
// name the tail sizes that are not plain `vlen`-multiples.
const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;

/// The tail of an `INT` record: a `u32` of encoding and bit widths.
const SIZE_INT_EXTRA: usize = 4;
/// The tail of an `ARRAY` record: three `u32`s (type, index, count).
const SIZE_ARRAY: usize = 12;
/// The tail of one `struct`/`union` member: name, type, bit offset.
const SIZE_MEMBER: usize = 12;
/// The tail of one `ENUM` value: name and value.
const SIZE_ENUM_VALUE: usize = 8;
/// The tail of one `FUNC_PROTO` parameter: name and type.
const SIZE_PARAM: usize = 8;
/// The tail of a `VAR` record: a `u32` linkage.
const SIZE_VAR_EXTRA: usize = 4;
/// The tail of one `DATASEC` entry: three `u32`s.
const SIZE_DATASEC_ENTRY: usize = 12;
/// The tail of a `DECL_TAG` record: a `u32` component index.
const SIZE_DECL_TAG_EXTRA: usize = 4;
/// The tail of one `ENUM64` value: name and an 8-byte value.
const SIZE_ENUM64_VALUE: usize = 12;

/// A little-endian reader over the BTF bytes.
struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    /// Read one `u32`, or fail at the section's end.
    fn u32(&mut self) -> Result<u32> {
        let bytes = self
            .data
            .get(self.position..self.position + 4)
            .context("BTF ends mid-record")?;
        self.position += 4;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("the slice above is four bytes"),
        ))
    }
}

/// The byte offset of `member` in `struct <struct_name>`, from the
/// running kernel's own BTF — ground truth (see the module docs).
///
/// The offset is *uniquely* determined or an error: multiple structs of
/// the same name that disagree on the member's offset is a BTF this
/// parser refuses to guess into, and no struct carrying the member is
/// an error the caller turns into an unarmed self-guard — never a
/// default.
pub fn task_struct_member_offset(struct_name: &str, member: &str) -> Result<usize> {
    member_offset(VMLINUX_BTF, struct_name, member)
}

/// The underlying walk, over a BTF file: the tests exercise it against
/// synthetic blobs, the loader against the running kernel.
fn member_offset(path: &str, struct_name: &str, member: &str) -> Result<usize> {
    let data = fs::read(path).with_context(|| format!("reading the BTF file {path}"))?;
    let (types, strings) = split_sections(&data).context("parsing the BTF header")?;

    let mut cursor = Cursor {
        data: types,
        position: 0,
    };
    // The bit offsets the member was found at, across every struct of
    // the name: BTF can legally carry more than one, and this parser
    // only proceeds when they agree — anything else is a guess.
    let mut found: Vec<usize> = Vec::new();
    while cursor.position < types.len() {
        let name = cursor.u32()?;
        let info = cursor.u32()?;
        // `size` for struct kinds, `type` for reference kinds; either
        // way the record's tail follows it.
        let _size_or_type = cursor.u32()?;
        let kind = ((info >> 24) & 0x1f) as u8;
        let vlen = (info & 0xffff) as usize;
        let kind_flag = (info >> 31) != 0;
        let tail = match kind {
            KIND_INT => SIZE_INT_EXTRA,
            KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
            | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
            KIND_ARRAY => SIZE_ARRAY,
            KIND_STRUCT | KIND_UNION => vlen * SIZE_MEMBER,
            KIND_ENUM => vlen * SIZE_ENUM_VALUE,
            KIND_FUNC_PROTO => vlen * SIZE_PARAM,
            KIND_VAR => SIZE_VAR_EXTRA,
            KIND_DATASEC => vlen * SIZE_DATASEC_ENTRY,
            KIND_DECL_TAG => SIZE_DECL_TAG_EXTRA,
            KIND_ENUM64 => vlen * SIZE_ENUM64_VALUE,
            other => bail!("unknown BTF type kind {other}: refusing to guess the walk"),
        };
        if kind == KIND_STRUCT && string_at(strings, name).as_deref() == Some(struct_name) {
            if let Some(bit_offset) =
                member_bit_offset(&mut cursor, strings, vlen, kind_flag, member)?
            {
                found.push(bit_offset);
            }
            cursor.position -= vlen * SIZE_MEMBER;
        }
        cursor.position += tail;
    }
    let (Some(&first), rest) = (found.first(), &found[1..]) else {
        bail!("no struct {struct_name} with a {member} member in {path}");
    };
    if rest.iter().any(|&offset| offset != first) {
        bail!(
            "the structs named {struct_name} disagree on {member}'s offset in {path}: \
             refusing to guess"
        );
    }
    let bytes = first / 8;
    if first % 8 != 0 {
        bail!("{struct_name}.{member} is bit-packed at bit {first}: not a byte offset");
    }
    Ok(bytes)
}

/// Walk one `vlen`-member struct record for `member`, consuming only as
/// many bytes as the members occupy.
fn member_bit_offset(
    cursor: &mut Cursor<'_>,
    strings: &[u8],
    vlen: usize,
    kind_flag: bool,
    member: &str,
) -> Result<Option<usize>> {
    let mut found = None;
    for _ in 0..vlen {
        let name = cursor.u32()?;
        let _type = cursor.u32()?;
        let offset = cursor.u32()?;
        if string_at(strings, name).as_deref() == Some(member) {
            // With the kind flag the low 24 bits are the bit offset and
            // the high 8 the bitfield size; without it the whole word is
            // the bit offset. A member with a bitfield size is not a byte
            // address at all — refusing it is the point.
            let bitfield_size = if kind_flag { offset >> 24 } else { 0 };
            if bitfield_size != 0 {
                bail!("{member} is a {bitfield_size}-bit bitfield: no byte offset exists");
            }
            found = Some(if kind_flag {
                (offset & 0x00ff_ffff) as usize
            } else {
                offset as usize
            });
        }
    }
    Ok(found)
}

/// Split the file into its types and strings sections.
fn split_sections(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut header = Cursor { data, position: 0 };
    let magic = header.u32()?;
    if (magic & 0xffff) as u16 != BTF_MAGIC {
        bail!("not a little-endian BTF file: magic {magic:#010x}");
    }
    // u16 magic, u8 version, u8 flags — read as one u32 above.
    let hdr_len = header.u32()? as usize;
    let type_off = header.u32()? as usize;
    let type_len = header.u32()? as usize;
    let str_off = header.u32()? as usize;
    let str_len = header.u32()? as usize;
    let types = data
        .get(hdr_len + type_off..hdr_len + type_off + type_len)
        .context("the BTF types section is truncated")?;
    let strings = data
        .get(hdr_len + str_off..hdr_len + str_off + str_len)
        .context("the BTF strings section is truncated")?;
    Ok((types, strings))
}

/// The NUL-terminated string at `offset` in the strings section.
fn string_at(strings: &[u8], offset: u32) -> Option<&str> {
    let bytes = strings.get(offset as usize..)?;
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal BTF blob: one `int`, a struct with the members
    /// the tests place, and a few other kinds (an `enum64`, a
    /// `func_proto`, a `decl_tag`) so the walk has to size their tails
    /// correctly to reach the struct's members.
    fn build_btf(struct_size: u32, members: &[(&str, u32)]) -> Vec<u8> {
        // The strings section: the empty string, the type names, the
        // member names, each NUL-terminated.
        let mut strings: Vec<u8> = vec![0];
        let mut place = |strings: &mut Vec<u8>, text: &str| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            at
        };
        let int_name = place(&mut strings, "int");
        let struct_name = place(&mut strings, "task_struct");
        let mut member_names = Vec::new();
        for (name, _) in members {
            member_names.push(place(&mut strings, name));
        }
        let enum64_name = place(&mut strings, "enum64");
        let func_proto_name = place(&mut strings, "func_proto");

        let mut types: Vec<u8> = Vec::new();
        let mut record = |types: &mut Vec<u8>, name: u32, info: u32, size_or_type: u32| {
            types.extend_from_slice(&name.to_le_bytes());
            types.extend_from_slice(&info.to_le_bytes());
            types.extend_from_slice(&size_or_type.to_le_bytes());
        };
        // The `int` type, id 1: kind 1, vlen 0, size 4, plus the 4-byte
        // encoding tail.
        record(&mut types, int_name, (KIND_INT as u32) << 24, 4);
        types.extend_from_slice(&0u32.to_le_bytes());
        // The `enum64`, id 2: kind 19, vlen 1 — a 12-byte value the walk
        // must skip to reach what follows.
        record(&mut types, enum64_name, ((KIND_ENUM64 as u32) << 24) | 1, 8);
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&0u64.to_le_bytes());
        // The `func_proto`, id 3: kind 13, vlen 1 — two 8-byte params.
        record(
            &mut types,
            func_proto_name,
            ((KIND_FUNC_PROTO as u32) << 24) | 1,
            0,
        );
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        // The struct, id 4: kind 4, vlen = members.len().
        let info = ((KIND_STRUCT as u32) << 24) | members.len() as u32;
        record(&mut types, struct_name, info, struct_size);
        for (at, (_, bit_offset)) in member_names.iter().zip(members) {
            types.extend_from_slice(&at.to_le_bytes());
            types.extend_from_slice(&1u32.to_le_bytes()); // the `int` type
            types.extend_from_slice(&bit_offset.to_le_bytes());
        }

        // The header: magic, version 1, flags 0, its own length (24),
        // then the two sections (types first, strings after).
        let mut blob = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&24u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes()); // type_off
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes()); // str_off
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strings);
        blob
    }

    #[test]
    fn finds_the_member_offset_past_other_kinds() {
        // `tgid` 32 bits after `pid`, the layout every mainline kernel
        // carries; the enum64 and func_proto records ahead of the
        // struct prove the walk sizes their tails.
        let blob = build_btf(16, &[("pid", 64), ("tgid", 96)]);
        let path = std::env::temp_dir().join("wabbit-btf-test-synthetic.btf");
        std::fs::write(&path, blob).unwrap();
        let offset = member_offset(path.to_str().unwrap(), "task_struct", "tgid").unwrap();
        assert_eq!(offset, 12);
        let offset = member_offset(path.to_str().unwrap(), "task_struct", "pid").unwrap();
        assert_eq!(offset, 8);
    }

    #[test]
    fn a_bitfield_member_is_refused_not_guessed() {
        // The kind flag set: the member's offset word carries the
        // bitfield size in its high byte, and a bit-packed member has
        // no byte offset at all.
        let mut strings: Vec<u8> = vec![0];
        let mut place = |text: &str| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            at
        };
        let struct_name = place("task_struct");
        let member = place("flags");
        let mut types: Vec<u8> = Vec::new();
        types.extend_from_slice(&struct_name.to_le_bytes());
        // Kind flag (bit 31) set, kind 4, vlen 1.
        types.extend_from_slice(&(((KIND_STRUCT as u32) << 24) | (1 << 31) | 1).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        // The member: 3 bits at bit offset 8 (word 0x0300_0008).
        types.extend_from_slice(&member.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0x0300_0008u32.to_le_bytes());
        let mut blob = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&24u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strings);
        let path = std::env::temp_dir().join("wabbit-btf-test-bitfield.btf");
        std::fs::write(&path, blob).unwrap();
        assert!(member_offset(path.to_str().unwrap(), "task_struct", "flags").is_err());
    }

    /// The running kernel is the ground truth the loader will meet:
    /// `task_struct`'s `tgid` must sit 4 bytes after `pid` (the two
    /// `pid_t`s are adjacent in every kernel of the target matrix),
    /// inside the struct, 4-byte aligned. Skipped on hosts that carry
    /// no readable vmlinux BTF (no target of this workspace does).
    #[test]
    fn the_running_kernel_yields_the_adjacent_pid_tgids() {
        let pid = match task_struct_member_offset("task_struct", "pid") {
            Ok(offset) => offset,
            Err(error) => {
                eprintln!("skipping: no BTF task_struct here ({error:#})");
                return;
            }
        };
        let tgid = task_struct_member_offset("task_struct", "tgid")
            .expect("tgid sits next to pid in every task_struct");
        assert_eq!(tgid, pid + 4);
        assert_eq!(tgid % 4, 0);
    }
}
