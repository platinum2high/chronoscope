//! NTFS $MFT (Master File Table) artifact.
//!
//! Parses raw FILE records (fixed 1024-byte entries, the near-universal
//! size on modern NTFS volumes) directly from an exported `$MFT` dump.
//! For each record we read two attributes:
//!
//! - `$STANDARD_INFORMATION` (0x10) — the four MACB timestamps most
//!   tools show, plus DOS file attributes. This is what every
//!   filesystem-aware application updates.
//! - `$FILE_NAME` (0x30) — the name, parent directory reference, and
//!   its *own* copy of the four timestamps. Critically, `$FILE_NAME`
//!   timestamps are only updated by the NTFS driver on rename/move —
//!   not by user-mode API calls — so most anti-forensic timestamp
//!   tools (timestomp, SetMace) only patch `$STANDARD_INFORMATION`.
//!   A creation-time mismatch between the two is a well-known
//!   timestomping indicator, which we flag inline.
//!
//! We do not reconstruct full paths (that needs the whole table
//! resolved into a tree, all records at once) — the parent MFT
//! reference is exposed in `extra` for a downstream tool to resolve.
//!
//! Reference: NTFS on-disk format, as documented across Microsoft's
//! public technical references and reproduced consistently by every
//! open-source implementation (Sleuthkit, dissect.ntfs, MFTECmd).

use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};

use super::reader::Reader;
use super::ArtifactParser;
use crate::timeline::{ArtifactSource, TimelineEvent};

const RECORD_SIGNATURE: &[u8; 4] = b"FILE";
const RECORD_SIZE: usize = 1024;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_END: u32 = 0xFFFF_FFFF;

const FILETIME_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

fn filetime_to_datetime(ft: u64) -> Option<DateTime<Utc>> {
    let ft = ft as i64;
    if ft <= FILETIME_EPOCH_OFFSET {
        return None;
    }
    let unix_100ns = ft - FILETIME_EPOCH_OFFSET;
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    Utc.timestamp_opt(secs, nanos).single()
}

struct StandardInfo {
    created: Option<DateTime<Utc>>,
    modified: Option<DateTime<Utc>>,
    mft_modified: Option<DateTime<Utc>>,
    accessed: Option<DateTime<Utc>>,
}

struct FileNameAttr {
    name: String,
    namespace: u8,
    parent_ref: u64,
    created: Option<DateTime<Utc>>,
}

/// Apply the NTFS update-sequence fixup: the last 2 bytes of each
/// 512-byte sector in the record are swapped out for a check value at
/// write time, with the real bytes stashed in the Update Sequence
/// Array. Skipping this leaves two corrupt bytes near the end of every
/// sector-aligned attribute — usually invisible, but it's free to do
/// correctly.
fn apply_fixup(record: &mut [u8]) -> bool {
    let r = Reader::new(record);
    let Some(usa_offset) = r.u16(4) else {
        return false;
    };
    let Some(usa_count) = r.u16(6) else {
        return false;
    };
    let usa_offset = usa_offset as usize;
    let usa_count = usa_count as usize;
    if usa_count == 0 || usa_offset + usa_count * 2 > record.len() {
        return false;
    }
    // usa_count includes the USN value itself; entries follow it.
    for sector in 0..usa_count.saturating_sub(1) {
        let sector_end = (sector + 1) * 512;
        if sector_end > record.len() || sector_end < 2 {
            break;
        }
        let entry_off = usa_offset + 2 + sector * 2;
        if entry_off + 2 > record.len() {
            break;
        }
        record[sector_end - 2] = record[entry_off];
        record[sector_end - 1] = record[entry_off + 1];
    }
    true
}

fn parse_standard_information(content: &[u8]) -> Option<StandardInfo> {
    let r = Reader::new(content);
    Some(StandardInfo {
        created: r.u64(0).and_then(filetime_to_datetime),
        modified: r.u64(8).and_then(filetime_to_datetime),
        mft_modified: r.u64(16).and_then(filetime_to_datetime),
        accessed: r.u64(24).and_then(filetime_to_datetime),
    })
}

fn parse_file_name(content: &[u8]) -> Option<FileNameAttr> {
    let r = Reader::new(content);
    let parent_ref = r.u64(0)?;
    let created = r.u64(8).and_then(filetime_to_datetime);
    let name_len_chars = *content.get(64)? as usize;
    let namespace = *content.get(65)?;
    let name_bytes = r.slice(66, name_len_chars * 2)?;
    let units: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let name = String::from_utf16_lossy(&units);
    Some(FileNameAttr {
        name,
        namespace,
        parent_ref,
        created,
    })
}

/// One parsed FILE record's worth of timeline-relevant data.
struct MftRecord {
    entry_number: Option<u64>,
    std_info: Option<StandardInfo>,
    /// Prefer the Win32 (or Win32+DOS) namespace name when a file has
    /// more than one $FILE_NAME attribute (short + long name pairs are
    /// common); fall back to whichever came first.
    file_name: Option<FileNameAttr>,
}

fn parse_record(record: &[u8], mft_offset: usize) -> Option<MftRecord> {
    let mut buf = record.to_vec();
    if &buf[0..4] != RECORD_SIGNATURE {
        return None;
    }
    if !apply_fixup(&mut buf) {
        return None;
    }
    let r = Reader::new(&buf);
    let attrs_offset = r.u16(20)? as usize;
    let entry_number = Some((mft_offset / RECORD_SIZE) as u64);

    let mut std_info = None;
    let mut file_name: Option<FileNameAttr> = None;

    let mut offset = attrs_offset;
    let mut guard = 0;
    while offset + 8 <= buf.len() && guard < 64 {
        guard += 1;
        let Some(attr_type) = r.u32(offset) else {
            break;
        };
        if attr_type == ATTR_END {
            break;
        }
        let Some(attr_len) = r.u32(offset + 4) else {
            break;
        };
        if attr_len < 8 || attr_len as usize > buf.len().saturating_sub(offset) {
            break;
        }
        let non_resident = buf.get(offset + 8).copied().unwrap_or(1);
        if non_resident == 0 {
            if let (Some(content_len), Some(content_off)) = (r.u32(offset + 16), r.u16(offset + 20))
            {
                let content_start = offset + content_off as usize;
                if let Some(content) = r.slice(content_start, content_len as usize) {
                    match attr_type {
                        ATTR_STANDARD_INFORMATION => {
                            std_info = parse_standard_information(content);
                        }
                        ATTR_FILE_NAME => {
                            if let Some(fna) = parse_file_name(content) {
                                let better = file_name
                                    .as_ref()
                                    .map(|existing| fna.namespace <= existing.namespace)
                                    .unwrap_or(true);
                                if better {
                                    file_name = Some(fna);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        offset += attr_len as usize;
    }

    Some(MftRecord {
        entry_number,
        std_info,
        file_name,
    })
}

pub struct MftParser;

impl ArtifactParser for MftParser {
    fn source_name(&self) -> &'static str {
        "mft"
    }

    fn matches(&self, raw: &[u8]) -> bool {
        raw.len() >= 4 && &raw[0..4] == RECORD_SIGNATURE
    }

    fn parse(&self, raw: &[u8], path: &Path) -> Vec<TimelineEvent> {
        if !self.matches(raw) {
            return Vec::new();
        }
        let mut events = Vec::new();
        let mut offset = 0;

        while offset + RECORD_SIZE <= raw.len() {
            let record = &raw[offset..offset + RECORD_SIZE];
            if &record[0..4] == RECORD_SIGNATURE {
                if let Some(rec) = parse_record(record, offset) {
                    events.extend(build_events(&rec, path));
                }
            }
            offset += RECORD_SIZE;
        }

        events
    }
}

fn build_events(rec: &MftRecord, path: &Path) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    let Some(si) = &rec.std_info else { return out };

    let name = rec
        .file_name
        .as_ref()
        .map(|f| f.name.clone())
        .unwrap_or_else(|| "(unknown name)".to_string());

    let timestomp_suspected = match (si.created, rec.file_name.as_ref().and_then(|f| f.created)) {
        (Some(si_created), Some(fn_created)) => (si_created - fn_created).num_seconds().abs() > 60,
        _ => false,
    };

    let kinds: [(&str, Option<DateTime<Utc>>, &str); 4] = [
        ("mft_file_created", si.created, "created"),
        ("mft_file_modified", si.modified, "modified"),
        ("mft_entry_modified", si.mft_modified, "MFT entry modified"),
        ("mft_file_accessed", si.accessed, "accessed"),
    ];

    for (event_type, ts, verb) in kinds {
        let Some(ts) = ts else { continue };
        let mut event = TimelineEvent::new(
            ts,
            ArtifactSource::Mft,
            event_type,
            format!("File {verb}: {name}"),
            path.to_path_buf(),
        )
        .with_target(name.clone());

        if let Some(entry) = rec.entry_number {
            event = event.with_extra("mft_entry", entry);
        }
        if let Some(fna) = &rec.file_name {
            event = event.with_extra("parent_mft_ref", fna.parent_ref & 0x0000_FFFF_FFFF_FFFF);
            event = event.with_extra("namespace", fna.namespace as u64);
        }
        if event_type == "mft_file_created" && timestomp_suspected {
            event = event.with_extra("timestomp_suspected", true).with_extra(
                "note",
                "$STANDARD_INFORMATION creation time differs from $FILE_NAME creation time by more than 60s",
            );
        }
        out.push(event);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filetime_bytes(unix_ts: i64) -> [u8; 8] {
        let ft = (unix_ts * 10_000_000 + FILETIME_EPOCH_OFFSET) as u64;
        ft.to_le_bytes()
    }

    /// Builds a single 1024-byte FILE record with $STANDARD_INFORMATION
    /// and $FILE_NAME attributes, no update-sequence corruption (fixup
    /// is a no-op — sector-tail bytes match the USN already).
    fn build_mft_record(si_created: i64, fn_created: i64, name: &str) -> Vec<u8> {
        let mut rec = vec![0u8; RECORD_SIZE];
        rec[0..4].copy_from_slice(RECORD_SIGNATURE);
        // usa_offset=42, usa_count=3 (1 USN + 2 sector entries for a 1024-byte record)
        rec[4..6].copy_from_slice(&42u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        let usn: u16 = 0x0001;
        rec[42..44].copy_from_slice(&usn.to_le_bytes());
        rec[44..46].copy_from_slice(&usn.to_le_bytes()); // sector 1 tail placeholder
        rec[46..48].copy_from_slice(&usn.to_le_bytes()); // sector 2 tail placeholder
        rec[510..512].copy_from_slice(&usn.to_le_bytes());
        rec[1022..1024].copy_from_slice(&usn.to_le_bytes());

        let attrs_offset: u16 = 56;
        rec[20..22].copy_from_slice(&attrs_offset.to_le_bytes());

        let mut off = attrs_offset as usize;

        // --- $STANDARD_INFORMATION ---
        let si_content_len: u32 = 48;
        let si_header_len: u32 = 24 + si_content_len;
        rec[off..off + 4].copy_from_slice(&ATTR_STANDARD_INFORMATION.to_le_bytes());
        rec[off + 4..off + 8].copy_from_slice(&si_header_len.to_le_bytes());
        rec[off + 8] = 0; // resident
        rec[off + 16..off + 20].copy_from_slice(&si_content_len.to_le_bytes());
        rec[off + 20..off + 22].copy_from_slice(&24u16.to_le_bytes()); // content_offset
        let content_start = off + 24;
        rec[content_start..content_start + 8].copy_from_slice(&filetime_bytes(si_created));
        rec[content_start + 8..content_start + 16].copy_from_slice(&filetime_bytes(si_created + 5));
        rec[content_start + 16..content_start + 24]
            .copy_from_slice(&filetime_bytes(si_created + 10));
        rec[content_start + 24..content_start + 32]
            .copy_from_slice(&filetime_bytes(si_created + 15));
        off += si_header_len as usize;

        // --- $FILE_NAME ---
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let fn_content_len: u32 = 66 + (name_units.len() as u32) * 2;
        let fn_header_len: u32 = (24 + fn_content_len).div_ceil(8) * 8; // 8-byte aligned
        rec[off..off + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        rec[off + 4..off + 8].copy_from_slice(&fn_header_len.to_le_bytes());
        rec[off + 8] = 0; // resident
        rec[off + 16..off + 20].copy_from_slice(&fn_content_len.to_le_bytes());
        rec[off + 20..off + 22].copy_from_slice(&24u16.to_le_bytes());
        let content_start = off + 24;
        rec[content_start..content_start + 8].copy_from_slice(&5u64.to_le_bytes()); // parent ref
        rec[content_start + 8..content_start + 16].copy_from_slice(&filetime_bytes(fn_created));
        rec[content_start + 64] = name_units.len() as u8;
        rec[content_start + 65] = 1; // Win32 namespace
        for (i, u) in name_units.iter().enumerate() {
            let p = content_start + 66 + i * 2;
            rec[p..p + 2].copy_from_slice(&u.to_le_bytes());
        }
        off += fn_header_len as usize;

        rec[off..off + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        rec
    }

    #[test]
    fn parses_macb_timestamps_and_name() {
        let base = 1_700_000_000i64;
        let raw = build_mft_record(base, base, "evil.exe");
        let parser = MftParser;
        assert!(parser.matches(&raw));
        let events = parser.parse(&raw, Path::new("$MFT"));
        assert_eq!(events.len(), 4);
        assert!(events
            .iter()
            .all(|e| e.target_path.as_deref() == Some("evil.exe")));
        let created = events
            .iter()
            .find(|e| e.event_type == "mft_file_created")
            .unwrap();
        assert_eq!(created.timestamp.timestamp(), base);
        assert_eq!(
            created.extra.get("timestomp_suspected"),
            None,
            "matching $SI/$FN creation times should not flag timestomping"
        );
    }

    #[test]
    fn flags_standard_information_filename_creation_mismatch() {
        let base = 1_700_000_000i64;
        // $SI creation backdated by a day relative to $FILE_NAME —
        // the classic timestomp.exe / SetMace signature.
        let raw = build_mft_record(base - 86_400, base, "backdated.dll");
        let events = MftParser.parse(&raw, Path::new("$MFT"));
        let created = events
            .iter()
            .find(|e| e.event_type == "mft_file_created")
            .unwrap();
        assert_eq!(
            created
                .extra
                .get("timestomp_suspected")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn non_mft_bytes_yield_nothing() {
        let parser = MftParser;
        let raw = b"not an mft record".to_vec();
        assert!(!parser.matches(&raw));
        assert!(parser.parse(&raw, Path::new("x")).is_empty());
    }
}
