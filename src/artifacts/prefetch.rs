//! Windows Prefetch (.pf) artifact — SCCA format.
//!
//! Vista/7 (version 23) and earlier (version 17, XP/2003) files are
//! stored uncompressed, starting with a version DWORD then the "SCCA"
//! signature at offset 4. Windows 8 (26), Windows 10 (30), and Windows
//! 11 (31) wrap the same SCCA structure in Microsoft's Xpress-Huffman
//! ("MAM\x04") compression — see `xpress.rs`.
//!
//! Prefetch execution timestamps and the referenced-files list (loaded
//! DLLs/modules) are core process-execution and LOLBin/proxy-execution
//! evidence, so this parser surfaces both, plus two derived indicators:
//! a run-count/last-run-time consistency check (mirrors `mft.rs`'s
//! `timestomp_suspected` pattern) and a prefetch-hash/filename
//! cross-check (the ".pf" filename always encodes the same hash stored
//! in the header — a mismatch means the file was renamed, copied from
//! elsewhere, or otherwise planted).
//!
//! The SCCA field layout is stable across versions except for the size
//! of the last-run-time array (1 vs. 8 entries), the resulting shift in
//! the run-count field's offset, and — for version 30 specifically —
//! two documented file-information-section variants of different
//! total size. Rather than guess the variant from the version number
//! alone, we read the file's own `file_metrics_array_offset` field
//! (present at a fixed offset in every version) and derive the actual
//! file-information section size from it, then pick the matching
//! layout — a data-driven disambiguation instead of a version-number
//! guess.
//!
//! Reference: SCCA/PF field layout as documented across public
//! forensic references (independently reproduced by every open-source
//! Prefetch parser); LZXPRESS Huffman bitstream format per `xpress.rs`.

use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};

use super::reader::Reader;
use super::xpress;
use super::ArtifactParser;
use crate::timeline::{ArtifactSource, TimelineEvent};

const MAM_MAGIC: [u8; 4] = *b"MAM\x04";
const SCCA_MAGIC: [u8; 4] = *b"SCCA";
const SCCA_MAGIC_OFFSET: usize = 4;

const HEADER_SIZE: usize = 84;
const EXECUTABLE_NAME_OFFSET: usize = 16;
const EXECUTABLE_NAME_MAX_CHARS: usize = 30;
const PREFETCH_HASH_OFFSET: usize = 76;
const FLAGS_OFFSET: usize = 80;
const IS_BOOT_PREFETCH: u32 = 0x01;

// These four fields sit at the same absolute offset in every SCCA
// version's file-information section (they only ever grew *after*
// these, to make room for a longer last-run-time array).
const METRICS_ARRAY_OFFSET_FIELD: usize = HEADER_SIZE; // 84
const FILENAME_STRINGS_OFFSET_FIELD: usize = HEADER_SIZE + 16; // 100
const FILENAME_STRINGS_SIZE_FIELD: usize = HEADER_SIZE + 20; // 104
const VOLUMES_OFFSET_FIELD: usize = HEADER_SIZE + 24; // 108
const VOLUMES_COUNT_FIELD: usize = HEADER_SIZE + 28; // 112

const MAX_LAST_RUN_TIMES: usize = 8;
const MAX_FILENAME_STRINGS: usize = 4096;
const MAX_STRING_CHARS: usize = 1024;

const FILETIME_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

/// See `mft.rs`'s `filetime_to_datetime` for why the guard is `ft <= 0`
/// (only the "never set" sentinel / an impossible wrapped-negative
/// value) rather than rejecting every pre-1970 FILETIME, and why
/// `div_euclid`/`rem_euclid` are required once `unix_100ns` can be
/// negative.
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

/// Version-dependent field offsets within the file-information section.
struct VersionLayout {
    last_run_time_offset: usize,
    last_run_time_count: usize,
    run_count_offset: usize,
}

/// `file_info_size` is derived from the file's own metrics-array-offset
/// field (`metrics_array_offset - HEADER_SIZE`), which disambiguates
/// version 30's two documented variants without guessing from the
/// version number alone.
fn layout_for_version(version: u32, file_info_size: usize) -> Option<VersionLayout> {
    match version {
        17 => Some(VersionLayout {
            last_run_time_offset: HEADER_SIZE + 36,
            last_run_time_count: 1,
            run_count_offset: HEADER_SIZE + 60,
        }),
        23 => Some(VersionLayout {
            last_run_time_offset: HEADER_SIZE + 44,
            last_run_time_count: 1,
            run_count_offset: HEADER_SIZE + 68,
        }),
        26 => Some(VersionLayout {
            last_run_time_offset: HEADER_SIZE + 44,
            last_run_time_count: MAX_LAST_RUN_TIMES,
            run_count_offset: HEADER_SIZE + 124,
        }),
        30 => match file_info_size {
            220 => Some(VersionLayout {
                last_run_time_offset: HEADER_SIZE + 44,
                last_run_time_count: MAX_LAST_RUN_TIMES,
                run_count_offset: HEADER_SIZE + 124,
            }),
            212 => Some(VersionLayout {
                last_run_time_offset: HEADER_SIZE + 44,
                last_run_time_count: MAX_LAST_RUN_TIMES,
                run_count_offset: HEADER_SIZE + 116,
            }),
            _ => None,
        },
        31 => Some(VersionLayout {
            last_run_time_offset: HEADER_SIZE + 44,
            last_run_time_count: MAX_LAST_RUN_TIMES,
            run_count_offset: HEADER_SIZE + 116,
        }),
        _ => None,
    }
}

struct VolumeInfo {
    device_path: Option<String>,
    created: Option<DateTime<Utc>>,
    serial_number: Option<u32>,
}

struct PrefetchFields {
    version: u32,
    executable_name: Option<String>,
    prefetch_hash: Option<u32>,
    is_boot_prefetch: bool,
    run_count: u32,
    last_run_times: Vec<DateTime<Utc>>,
    volume: Option<VolumeInfo>,
    referenced_files: Vec<String>,
}

/// Hand-rolled UTF-16LE decode (no shared helper exists in
/// `reader.rs` — every parser in this codebase does this the same
/// way), truncated at the first embedded NUL rather than trimmed at
/// the end, since trailing bytes after a short string can be remnant
/// data rather than clean zero padding.
fn read_utf16le_cstr(r: &Reader, offset: usize, max_chars: usize) -> Option<String> {
    let max_chars = max_chars.min(MAX_STRING_CHARS);
    let bytes = r.slice(offset, max_chars.checked_mul(2)?)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&units[..end]))
}

fn parse_volume(r: &Reader, volumes_offset: usize, volumes_count: u32) -> Option<VolumeInfo> {
    if volumes_count == 0 {
        return None;
    }
    let device_path_rel = r.u32(volumes_offset)?;
    let device_path_chars = r.u32(volumes_offset + 4)? as usize;
    let created = r.u64(volumes_offset + 8).and_then(filetime_to_datetime);
    let serial_number = r.u32(volumes_offset + 16);
    let device_path = volumes_offset
        .checked_add(device_path_rel as usize)
        .and_then(|abs| read_utf16le_cstr(r, abs, device_path_chars));
    Some(VolumeInfo {
        device_path,
        created,
        serial_number,
    })
}

fn parse_last_run_times(r: &Reader, layout: &VersionLayout) -> Vec<DateTime<Utc>> {
    let mut out = Vec::new();
    for i in 0..layout.last_run_time_count.min(MAX_LAST_RUN_TIMES) {
        let offset = layout.last_run_time_offset + i * 8;
        if let Some(ts) = r.u64(offset).and_then(filetime_to_datetime) {
            out.push(ts);
        }
    }
    out
}

/// Filename strings is a flat block of back-to-back NUL-terminated
/// UTF-16LE paths (loaded DLLs/modules, config files, etc.) — bounded
/// loop, matching the "walk N variable-length records" idiom used in
/// `mft.rs` (`guard < 64`) and `lnk.rs` (`MAX_EXTRA_BLOCKS`).
fn parse_filename_strings(r: &Reader) -> Vec<String> {
    let mut out = Vec::new();
    let Some(section_offset) = r.u32(FILENAME_STRINGS_OFFSET_FIELD) else {
        return out;
    };
    let Some(section_size) = r.u32(FILENAME_STRINGS_SIZE_FIELD) else {
        return out;
    };
    let Some(section) = r.slice(section_offset as usize, section_size as usize) else {
        return out;
    };
    let units: Vec<u16> = section
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    let mut start = 0usize;
    for (i, &u) in units.iter().enumerate() {
        if u != 0 {
            continue;
        }
        if i > start {
            let s = String::from_utf16_lossy(&units[start..i]);
            if !s.is_empty() {
                out.push(s);
            }
        }
        start = i + 1;
        if out.len() >= MAX_FILENAME_STRINGS {
            break;
        }
    }
    out
}

fn decompress_if_needed(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() >= 8 && raw[0..4] == MAM_MAGIC {
        let r = Reader::new(raw);
        let decompressed_size = r.u32(4)? as usize;
        let compressed = r.slice(8, raw.len().saturating_sub(8))?;
        xpress::decompress(compressed, decompressed_size)
    } else {
        Some(raw.to_vec())
    }
}

fn parse_fields(decompressed: &[u8]) -> Option<PrefetchFields> {
    let r = Reader::new(decompressed);
    let version = r.u32(0)?;
    if r.slice(SCCA_MAGIC_OFFSET, 4)? != SCCA_MAGIC {
        return None;
    }

    let metrics_array_offset = r.u32(METRICS_ARRAY_OFFSET_FIELD)? as usize;
    let file_info_size = metrics_array_offset.checked_sub(HEADER_SIZE)?;
    let layout = layout_for_version(version, file_info_size)?;

    let executable_name = read_utf16le_cstr(&r, EXECUTABLE_NAME_OFFSET, EXECUTABLE_NAME_MAX_CHARS);
    let prefetch_hash = r.u32(PREFETCH_HASH_OFFSET);
    let is_boot_prefetch = r.u32(FLAGS_OFFSET).unwrap_or(0) & IS_BOOT_PREFETCH != 0;
    let run_count = r.u32(layout.run_count_offset).unwrap_or(0);
    let last_run_times = parse_last_run_times(&r, &layout);

    let volumes_offset = r.u32(VOLUMES_OFFSET_FIELD).unwrap_or(0) as usize;
    let volumes_count = r.u32(VOLUMES_COUNT_FIELD).unwrap_or(0);
    let volume = parse_volume(&r, volumes_offset, volumes_count);
    let referenced_files = parse_filename_strings(&r);

    Some(PrefetchFields {
        version,
        executable_name,
        prefetch_hash,
        is_boot_prefetch,
        run_count,
        last_run_times,
        volume,
        referenced_files,
    })
}

/// The hash embedded in a Prefetch filename (`NAME-HHHHHHHH.pf`) should
/// always match the header's own `prefetch_hash` field — Windows
/// generates both from the same executable path. A mismatch means this
/// .pf file was renamed, copied from another host, or otherwise
/// planted rather than generated in place.
fn filename_declared_hash(path: &Path) -> Option<u32> {
    let stem = path.file_stem()?.to_str()?;
    let (_, hash_part) = stem.rsplit_once('-')?;
    if hash_part.len() != 8 {
        return None;
    }
    u32::from_str_radix(hash_part, 16).ok()
}

pub struct PrefetchParser;

impl ArtifactParser for PrefetchParser {
    fn source_name(&self) -> &'static str {
        "prefetch"
    }

    fn matches(&self, raw: &[u8]) -> bool {
        (raw.len() >= 8 && raw[0..4] == MAM_MAGIC)
            || (raw.len() >= SCCA_MAGIC_OFFSET + 4
                && raw[SCCA_MAGIC_OFFSET..SCCA_MAGIC_OFFSET + 4] == SCCA_MAGIC)
    }

    fn parse(&self, raw: &[u8], path: &Path) -> Vec<TimelineEvent> {
        if !self.matches(raw) {
            return Vec::new();
        }
        let Some(decompressed) = decompress_if_needed(raw) else {
            return Vec::new();
        };
        let Some(fields) = parse_fields(&decompressed) else {
            return Vec::new();
        };
        build_events(&fields, path)
    }
}

fn build_events(fields: &PrefetchFields, path: &Path) -> Vec<TimelineEvent> {
    let executable_name = fields
        .executable_name
        .clone()
        .unwrap_or_else(|| "(unknown)".to_string());

    let run_count_mismatch = (fields.run_count > 0 && fields.last_run_times.is_empty())
        || (fields.run_count == 0 && !fields.last_run_times.is_empty());

    let filename_hash = filename_declared_hash(path);
    let filename_hash_mismatch = match (fields.prefetch_hash, filename_hash) {
        (Some(header_hash), Some(name_hash)) => header_hash != name_hash,
        _ => false,
    };

    let timestamps: Vec<DateTime<Utc>> = if fields.last_run_times.is_empty() {
        vec![std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|_| Utc::now())]
    } else {
        fields.last_run_times.clone()
    };

    let mut out = Vec::with_capacity(timestamps.len());
    for ts in timestamps {
        let mut event = TimelineEvent::new(
            ts,
            ArtifactSource::Prefetch,
            "prefetch_execution",
            format!(
                "Executed: {executable_name} (run count: {})",
                fields.run_count
            ),
            path.to_path_buf(),
        )
        .with_target(executable_name.clone())
        .with_extra("scca_version", fields.version as u64)
        .with_extra("run_count", fields.run_count as u64)
        .with_extra(
            "referenced_file_count",
            fields.referenced_files.len() as u64,
        );

        if let Some(hash) = fields.prefetch_hash {
            event = event.with_extra("prefetch_hash", format!("0x{hash:08X}"));
        }
        if fields.is_boot_prefetch {
            event = event.with_extra("is_boot_prefetch", true);
        }
        if let Some(vol) = &fields.volume {
            if let Some(dp) = &vol.device_path {
                event = event.with_extra("volume_device_path", dp.clone());
            }
            if let Some(serial) = vol.serial_number {
                event = event.with_extra("volume_serial_number", format!("0x{serial:08X}"));
            }
            if let Some(created) = vol.created {
                event = event.with_extra("volume_created", created.to_rfc3339());
            }
        }
        if run_count_mismatch {
            event = event
                .with_extra("run_count_mismatch_suspected", true)
                .with_extra(
                    "run_count_mismatch_note",
                    "run_count and recorded last-run timestamp count are inconsistent — \
                 possible truncated or tampered prefetch file",
                );
        }
        if filename_hash_mismatch {
            event = event.with_extra("filename_hash_mismatch", true).with_extra(
                "filename_hash_mismatch_note",
                "prefetch hash embedded in the filename does not match the header's \
                 prefetch_hash field — this file was likely renamed, copied from \
                 another host, or otherwise planted rather than generated in place",
            );
        }

        out.push(event);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn filetime_bytes(unix_ts: i64) -> [u8; 8] {
        ((unix_ts * 10_000_000 + FILETIME_EPOCH_OFFSET) as u64).to_le_bytes()
    }

    /// Builds a synthetic, uncompressed version-23 (Vista/7) SCCA
    /// buffer: header, file-information section (single last-run
    /// time), one volume-information entry, and a two-entry filename
    /// strings section.
    fn build_v23_prefetch(
        exe_name: &str,
        prefetch_hash: u32,
        run_count: u32,
        last_run_unix: Option<i64>,
        referenced: &[&str],
    ) -> Vec<u8> {
        const FILE_INFO_SIZE: usize = 156;
        let mut buf = vec![0u8; HEADER_SIZE + FILE_INFO_SIZE];

        buf[0..4].copy_from_slice(&23u32.to_le_bytes());
        buf[4..8].copy_from_slice(&SCCA_MAGIC);
        let name_bytes = utf16le(exe_name);
        buf[EXECUTABLE_NAME_OFFSET..EXECUTABLE_NAME_OFFSET + name_bytes.len()]
            .copy_from_slice(&name_bytes);
        buf[PREFETCH_HASH_OFFSET..PREFETCH_HASH_OFFSET + 4]
            .copy_from_slice(&prefetch_hash.to_le_bytes());

        // Filename strings section, appended after the fixed header.
        let filename_strings_offset = buf.len() as u32;
        let mut filename_strings = Vec::new();
        for name in referenced {
            filename_strings.extend_from_slice(&utf16le(name));
            filename_strings.extend_from_slice(&[0, 0]);
        }
        let filename_strings_size = filename_strings.len() as u32;
        buf.extend_from_slice(&filename_strings);

        // One volume-information entry (104 bytes), appended next.
        let volumes_offset = buf.len() as u32;
        let device_path = r"\DEVICE\HARDDISKVOLUME1";
        let device_path_bytes = utf16le(device_path);
        let mut volume_entry = vec![0u8; 104];
        let device_path_rel_offset: u32 = 104; // right after this entry
        volume_entry[0..4].copy_from_slice(&device_path_rel_offset.to_le_bytes());
        volume_entry[4..8].copy_from_slice(&(device_path.chars().count() as u32).to_le_bytes());
        volume_entry[8..16].copy_from_slice(&filetime_bytes(1_600_000_000));
        volume_entry[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buf.extend_from_slice(&volume_entry);
        buf.extend_from_slice(&device_path_bytes);
        buf.extend_from_slice(&[0, 0]);

        // File-information section fields (all at HEADER_SIZE + N).
        let fi = HEADER_SIZE;
        let metrics_array_offset = buf.len() as u32; // no metrics entries; offset just needs to be self-consistent
        buf[fi..fi + 4].copy_from_slice(&metrics_array_offset.to_le_bytes());
        buf[fi + 16..fi + 20].copy_from_slice(&filename_strings_offset.to_le_bytes());
        buf[fi + 20..fi + 24].copy_from_slice(&filename_strings_size.to_le_bytes());
        buf[fi + 24..fi + 28].copy_from_slice(&volumes_offset.to_le_bytes());
        buf[fi + 28..fi + 32].copy_from_slice(&1u32.to_le_bytes()); // volumes count
        if let Some(ts) = last_run_unix {
            buf[fi + 44..fi + 52].copy_from_slice(&filetime_bytes(ts));
        }
        buf[fi + 68..fi + 72].copy_from_slice(&run_count.to_le_bytes());

        buf
    }

    #[test]
    fn parses_executable_name_and_last_run_time() {
        let raw = build_v23_prefetch(
            "CMD.EXE",
            0x1234_5678,
            5,
            Some(1_700_000_000),
            &[
                r"C:\WINDOWS\SYSTEM32\NTDLL.DLL",
                r"C:\WINDOWS\SYSTEM32\KERNEL32.DLL",
            ],
        );
        let parser = PrefetchParser;
        assert!(parser.matches(&raw));
        let events = parser.parse(&raw, Path::new("CMD.EXE-12345678.pf"));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.target_path.as_deref(), Some("CMD.EXE"));
        assert_eq!(event.timestamp.timestamp(), 1_700_000_000);
        assert_eq!(
            event.extra.get("run_count").and_then(|v| v.as_u64()),
            Some(5)
        );
        assert_eq!(
            event
                .extra
                .get("referenced_file_count")
                .and_then(|v| v.as_u64()),
            Some(2)
        );
        assert_eq!(
            event
                .extra
                .get("volume_serial_number")
                .and_then(|v| v.as_str()),
            Some("0xDEADBEEF")
        );
        assert!(event.extra.get("filename_hash_mismatch").is_none());
    }

    #[test]
    fn flags_run_count_last_run_mismatch() {
        let raw = build_v23_prefetch("EVIL.EXE", 0x1111_1111, 7, None, &[]);
        let events = PrefetchParser.parse(&raw, Path::new("EVIL.EXE-11111111.pf"));
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .extra
                .get("run_count_mismatch_suspected")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn flags_filename_hash_mismatch() {
        let raw = build_v23_prefetch("NOTEPAD.EXE", 0xAAAA_BBBB, 1, Some(1_700_000_000), &[]);
        // Filename declares a different hash than the header's.
        let events = PrefetchParser.parse(&raw, Path::new("NOTEPAD.EXE-00000000.pf"));
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .extra
                .get("filename_hash_mismatch")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn non_prefetch_bytes_yield_nothing() {
        let parser = PrefetchParser;
        let raw = b"not a prefetch file at all, just plain text".to_vec();
        assert!(!parser.matches(&raw));
        assert!(parser.parse(&raw, Path::new("x")).is_empty());
    }

    #[test]
    fn matches_recognizes_mam_wrapper() {
        let parser = PrefetchParser;
        let mut mam = MAM_MAGIC.to_vec();
        mam.extend_from_slice(&100u32.to_le_bytes());
        mam.extend_from_slice(&[0u8; 32]);
        assert!(parser.matches(&mam));
    }

    #[test]
    fn corrupt_mam_size_field_yields_no_events_not_panic() {
        let mut mam = MAM_MAGIC.to_vec();
        mam.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        mam.extend_from_slice(&[0xAB; 512]);
        let events = PrefetchParser.parse(&mam, Path::new("huge.pf"));
        assert!(events.is_empty());
    }
}
