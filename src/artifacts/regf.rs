//! Minimal Windows Registry hive (REGF) reader.
//!
//! Just enough of the on-disk format to walk a key tree and read its
//! values — this backs the Amcache parser today and is generic enough
//! for any future registry-hive artifact (SYSTEM/SOFTWARE/NTUSER) to
//! reuse without touching this module.
//!
//! Layout, in the order this module actually uses it:
//!
//! - A fixed 4096-byte base block (`"regf"` signature, a root-key
//!   offset at 0x24) precedes all hive-bin data.
//! - Hive bins (`"hbin"`) subdivide the rest of the file; we never need
//!   to walk bin boundaries directly because every offset a cell stores
//!   is already relative to the start of hive-bin data (i.e. absolute
//!   file offset `HBIN_DATA_START + relative_offset`).
//! - A cell is a 4-byte signed size prefix (negative = allocated) plus
//!   its payload. The payload's first two bytes are a type signature:
//!   `"nk"` (key node), `"vk"` (value node), `"lf"`/`"lh"`/`"li"`/`"ri"`
//!   (subkey lists), `"db"` (big-data segment list for values that
//!   don't fit in one cell).
//!
//! Reference: the on-disk format as documented across Sentinel Chicken's
//! "Windows NT Registry File (REGF) format" writeup and reproduced
//! consistently by every open-source implementation (regf/libregf,
//! python-registry, impacket's `winregistry`).
//!
//! Every walk here is bounded by a node budget (see `MAX_NODES`) — a
//! hive from a compromised host is attacker-influenced input, and a
//! corrupt or deliberately cyclic subkey list must degrade to partial
//! results, never hang or blow the stack.

use chrono::{DateTime, TimeZone, Utc};

use super::reader::Reader;

const HBIN_DATA_START: usize = 4096;
const ROOT_OFFSET_FIELD: usize = 0x24;
const RESIDENT_FLAG: u32 = 0x8000_0000;
/// Generous ceiling on total nodes visited in one hive walk (keys +
/// subkey-list entries). A real Amcache.hve has at most a few hundred
/// keys; this only exists to bound a hostile/corrupt hive.
const MAX_NODES: usize = 200_000;

const FILETIME_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

fn filetime_to_datetime(ft: u64) -> Option<DateTime<Utc>> {
    let ft = ft as i64;
    if ft <= 0 {
        return None;
    }
    let unix_100ns = ft - FILETIME_EPOCH_OFFSET;
    let secs = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;
    Utc.timestamp_opt(secs, nanos).single()
}

/// Reads the cell at `rel_offset` (relative to hive-bin data) and
/// returns its payload — the bytes after the 4-byte size prefix, sized
/// to what that prefix actually claims (bounds-checked against the
/// buffer, so a corrupt/oversized size claim just truncates rather than
/// panicking).
fn cell_at(hive: &[u8], rel_offset: u32) -> Option<&[u8]> {
    if rel_offset == u32::MAX {
        return None;
    }
    let abs = HBIN_DATA_START.checked_add(rel_offset as usize)?;
    let r = Reader::new(hive);
    let raw_size = r.u32(abs)? as i32;
    if raw_size >= 0 {
        // Positive size = free/unallocated cell; nothing valid to read.
        return None;
    }
    let size = raw_size.checked_neg()? as usize;
    hive.get(abs + 4..abs.checked_add(size)?)
}

#[derive(Debug, Clone, Copy)]
pub enum ValueKind {
    Sz,
    ExpandSz,
    Binary,
    Dword,
    MultiSz,
    Qword,
    Other,
}

impl ValueKind {
    fn from_raw(v: u32) -> Self {
        match v {
            1 => ValueKind::Sz,
            2 => ValueKind::ExpandSz,
            3 => ValueKind::Binary,
            4 | 5 => ValueKind::Dword,
            7 => ValueKind::MultiSz,
            11 => ValueKind::Qword,
            _ => ValueKind::Other,
        }
    }
}

pub struct ValueNode {
    pub name: String,
    pub kind: ValueKind,
    data: Vec<u8>,
}

impl ValueNode {
    pub fn as_string(&self) -> Option<String> {
        match self.kind {
            ValueKind::Sz | ValueKind::ExpandSz | ValueKind::MultiSz => {
                let units: Vec<u16> = self
                    .data
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&units);
                Some(s.trim_end_matches('\0').to_string())
            }
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        let r = Reader::new(&self.data);
        r.u32(0).or_else(|| {
            // Some resident DWORDs are stored as fewer than 4 bytes
            // when the value happens to be small; pad on read.
            let mut buf = [0u8; 4];
            let n = self.data.len().min(4);
            buf[..n].copy_from_slice(&self.data[..n]);
            (!self.data.is_empty()).then(|| u32::from_le_bytes(buf))
        })
    }

    pub fn as_u64(&self) -> Option<u64> {
        Reader::new(&self.data).u64(0).or_else(|| {
            // Mirrors `as_u32`: some resident QWORDs are stored with
            // fewer than 8 significant bytes; pad on read instead of
            // silently dropping an otherwise-valid value.
            let mut buf = [0u8; 8];
            let n = self.data.len().min(8);
            buf[..n].copy_from_slice(&self.data[..n]);
            (!self.data.is_empty()).then(|| u64::from_le_bytes(buf))
        })
    }
}

/// Resolves a `vk` cell's data pointer: resident data lives inline in
/// the 4-byte offset field itself (top bit set, low 31 bits = length);
/// otherwise the offset field points at a normal cell holding the
/// bytes, or (for anything bigger than one cell) a `db` big-data
/// segment list we reassemble here.
fn resolve_value_data(hive: &[u8], data_len_field: u32, data_offset_field: u32) -> Vec<u8> {
    let resident = data_len_field & RESIDENT_FLAG != 0;
    let size = (data_len_field & !RESIDENT_FLAG) as usize;

    if resident {
        let bytes = data_offset_field.to_le_bytes();
        let n = size.min(4);
        return bytes[..n].to_vec();
    }
    if size == 0 {
        return Vec::new();
    }
    let Some(cell) = cell_at(hive, data_offset_field) else {
        return Vec::new();
    };
    if cell.len() >= 2 && &cell[0..2] == b"db" {
        return resolve_big_data(hive, cell, size);
    }
    cell[..size.min(cell.len())].to_vec()
}

/// `db` big-data cell: a signature, a segment count, and an offset to a
/// segment-list cell (a flat array of 4-byte offsets, each pointing at
/// a raw data chunk up to 16344 bytes). Concatenates them back into one
/// buffer, capped at `total_size`.
fn resolve_big_data(hive: &[u8], db_cell: &[u8], total_size: usize) -> Vec<u8> {
    let r = Reader::new(db_cell);
    let Some(segment_count) = r.u16(2) else {
        return Vec::new();
    };
    let Some(list_offset) = r.u32(4) else {
        return Vec::new();
    };
    let Some(list_cell) = cell_at(hive, list_offset) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(total_size);
    for i in 0..segment_count as usize {
        if out.len() >= total_size {
            break;
        }
        let Some(seg_offset) = Reader::new(list_cell).u32(i * 4) else {
            break;
        };
        let Some(seg) = cell_at(hive, seg_offset) else {
            break;
        };
        let remaining = total_size - out.len();
        out.extend_from_slice(&seg[..remaining.min(seg.len())]);
    }
    out
}

fn read_value(hive: &[u8], rel_offset: u32) -> Option<ValueNode> {
    let cell = cell_at(hive, rel_offset)?;
    let r = Reader::new(cell);
    if cell.len() < 0x14 || &cell[0..2] != b"vk" {
        return None;
    }
    let name_len = r.u16(0x02)? as usize;
    let data_len_field = r.u32(0x04)?;
    let data_offset_field = r.u32(0x08)?;
    let value_type = r.u32(0x0C)?;
    let flags = r.u16(0x10)?;

    let name = if name_len == 0 {
        String::new() // the "(default)" value
    } else {
        let name_bytes = r.slice(0x14, name_len)?;
        if flags & 0x1 != 0 {
            String::from_utf8_lossy(name_bytes).into_owned()
        } else {
            let units: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
    };

    Some(ValueNode {
        name,
        kind: ValueKind::from_raw(value_type),
        data: resolve_value_data(hive, data_len_field, data_offset_field),
    })
}

/// Real hives never nest `ri` (list-of-lists) more than one level deep —
/// this bounds recursion depth independently of `MAX_NODES`, since a
/// budget alone still lets a hostile chain of self/mutually-referencing
/// `ri` cells recurse tens of thousands of stack frames deep before the
/// budget runs out.
const MAX_SUBKEY_LIST_DEPTH: usize = 16;

/// Flattens one subkey-list cell into raw `nk` offsets. `lf`/`lh` pair
/// each offset with a 4-byte name hint we don't need (case-insensitive
/// name comparison on the resolved key is simpler and just as correct);
/// `li` is the same but hash-less; `ri` is an index of *other*
/// subkey-list cells, resolved recursively.
fn read_subkey_list(hive: &[u8], list_offset: u32, budget: &mut usize) -> Vec<u32> {
    read_subkey_list_at_depth(hive, list_offset, budget, 0)
}

fn read_subkey_list_at_depth(
    hive: &[u8],
    list_offset: u32,
    budget: &mut usize,
    depth: usize,
) -> Vec<u32> {
    let mut out = Vec::new();
    if depth >= MAX_SUBKEY_LIST_DEPTH {
        return out;
    }
    let Some(cell) = cell_at(hive, list_offset) else {
        return out;
    };
    if cell.len() < 4 {
        return out;
    }
    let sig = &cell[0..2];
    let r = Reader::new(cell);
    let Some(count) = r.u16(2) else { return out };

    match sig {
        b"lf" | b"lh" => {
            for i in 0..count as usize {
                if *budget == 0 {
                    break;
                }
                let Some(off) = r.u32(4 + i * 8) else { break };
                out.push(off);
                *budget -= 1;
            }
        }
        b"li" => {
            for i in 0..count as usize {
                if *budget == 0 {
                    break;
                }
                let Some(off) = r.u32(4 + i * 4) else { break };
                out.push(off);
                *budget -= 1;
            }
        }
        b"ri" => {
            for i in 0..count as usize {
                if *budget == 0 {
                    break;
                }
                // Spend one unit of budget on the `ri` entry itself
                // (not just the leaf offsets it eventually yields) so a
                // chain of self- or mutually-referencing `ri` cells
                // can't recurse indefinitely — a corrupt/hostile hive
                // must degrade to a partial result, never blow the
                // stack. The depth cap above is the real backstop; this
                // just keeps total work bounded too.
                *budget -= 1;
                let Some(sub_list_off) = r.u32(4 + i * 4) else {
                    break;
                };
                out.extend(read_subkey_list_at_depth(
                    hive,
                    sub_list_off,
                    budget,
                    depth + 1,
                ));
            }
        }
        _ => {}
    }
    out
}

pub struct KeyNode<'a> {
    hive: &'a [u8],
    cell: &'a [u8],
}

impl<'a> KeyNode<'a> {
    pub fn name(&self) -> String {
        let r = Reader::new(self.cell);
        let (Some(flags), Some(name_len)) = (r.u16(0x02), r.u16(0x48)) else {
            return String::new();
        };
        let name_len = name_len as usize;
        let Some(name_bytes) = r.slice(0x4C, name_len) else {
            return String::new();
        };
        if flags & 0x20 != 0 {
            String::from_utf8_lossy(name_bytes).into_owned()
        } else {
            let units: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
    }

    /// The key's LastWritten timestamp — for Amcache specifically, this
    /// is the closest thing to "when this inventory entry was recorded"
    /// (there's no separate created-time field on a registry key).
    pub fn last_written(&self) -> Option<DateTime<Utc>> {
        Reader::new(self.cell)
            .u64(0x04)
            .and_then(filetime_to_datetime)
    }

    pub fn subkeys(&self) -> Vec<KeyNode<'a>> {
        let r = Reader::new(self.cell);
        let (Some(num_subkeys), Some(list_offset)) = (r.u32(0x14), r.u32(0x1C)) else {
            return Vec::new();
        };
        if num_subkeys == 0 || list_offset == u32::MAX {
            return Vec::new();
        }
        let mut budget = MAX_NODES;
        read_subkey_list(self.hive, list_offset, &mut budget)
            .into_iter()
            .filter_map(|off| key_at(self.hive, off))
            .collect()
    }

    pub fn find_subkey(&self, name: &str) -> Option<KeyNode<'a>> {
        self.subkeys()
            .into_iter()
            .find(|k| k.name().eq_ignore_ascii_case(name))
    }

    pub fn values(&self) -> Vec<ValueNode> {
        let r = Reader::new(self.cell);
        let (Some(num_values), Some(list_offset)) = (r.u32(0x24), r.u32(0x28)) else {
            return Vec::new();
        };
        if num_values == 0 || list_offset == u32::MAX {
            return Vec::new();
        }
        let Some(list_cell) = cell_at(self.hive, list_offset) else {
            return Vec::new();
        };
        let available = list_cell.len() / 4;
        let n = (num_values as usize).min(available);
        let lr = Reader::new(list_cell);
        (0..n)
            .filter_map(|i| lr.u32(i * 4))
            .filter_map(|off| read_value(self.hive, off))
            .collect()
    }
}

fn key_at(hive: &[u8], rel_offset: u32) -> Option<KeyNode<'_>> {
    let cell = cell_at(hive, rel_offset)?;
    if cell.len() < 0x4C || &cell[0..2] != b"nk" {
        return None;
    }
    Some(KeyNode { hive, cell })
}

/// Validates the base block and resolves the hive's root key. Returns
/// `None` for anything that isn't a well-formed REGF file — including
/// truncated files too small to hold a root key cell.
pub fn parse_hive_root(hive: &[u8]) -> Option<KeyNode<'_>> {
    if hive.len() < HBIN_DATA_START + 0x4C || &hive[0..4] != b"regf" {
        return None;
    }
    let root_offset = Reader::new(hive).u32(ROOT_OFFSET_FIELD)?;
    key_at(hive, root_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cell(buf: &mut Vec<u8>, abs_offset: usize, payload: &[u8]) {
        let total_size = 4 + payload.len();
        let raw_size = -(total_size as i32);
        if buf.len() < abs_offset + total_size {
            buf.resize(abs_offset + total_size, 0);
        }
        buf[abs_offset..abs_offset + 4].copy_from_slice(&raw_size.to_le_bytes());
        buf[abs_offset + 4..abs_offset + total_size].copy_from_slice(payload);
    }

    /// A hive whose root key's subkey list is a single `ri` cell that
    /// points back at itself. A real hive never does this, but a
    /// corrupt or hostile one might — this must degrade to an empty
    /// subkey list, not hang or blow the stack.
    #[test]
    fn self_referencing_ri_list_does_not_hang_or_overflow() {
        let mut hive = vec![0u8; HBIN_DATA_START];
        hive[0..4].copy_from_slice(b"regf");
        hive[ROOT_OFFSET_FIELD..ROOT_OFFSET_FIELD + 4].copy_from_slice(&0u32.to_le_bytes());

        // Root `nk` cell at rel_offset 0 (abs HBIN_DATA_START).
        let mut nk_payload = vec![0u8; 0x4C];
        nk_payload[0..2].copy_from_slice(b"nk");
        nk_payload[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // num_subkeys
        nk_payload[0x1C..0x20].copy_from_slice(&80u32.to_le_bytes()); // subkey list rel offset
        nk_payload[0x28..0x2C].copy_from_slice(&u32::MAX.to_le_bytes());
        write_cell(&mut hive, HBIN_DATA_START, &nk_payload);

        // `ri` cell at rel_offset 80 (abs HBIN_DATA_START + 80), whose
        // single entry points right back at itself.
        let mut ri_payload = vec![0u8; 8];
        ri_payload[0..2].copy_from_slice(b"ri");
        ri_payload[2..4].copy_from_slice(&1u16.to_le_bytes()); // count
        ri_payload[4..8].copy_from_slice(&80u32.to_le_bytes()); // points at itself
        write_cell(&mut hive, HBIN_DATA_START + 80, &ri_payload);

        let root = parse_hive_root(&hive).expect("root key should parse");
        // Must return promptly with an empty (degraded) result, not
        // recurse forever.
        assert_eq!(root.subkeys().len(), 0);
    }
}
