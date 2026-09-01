//! Windows Shortcut (.lnk) artifact — MS-SHLLINK.
//!
//! Chronoscope's job here is narrower than IOC Hunter's `analyze` LNK
//! module: not threat scoring, just turning a shortcut into timeline
//! events an analyst can sort alongside every other artifact. We still
//! walk the full structure (LinkInfo, StringData, TrackerDataBlock)
//! because the target path and the builder-host provenance the tracker
//! block leaks are exactly what a timeline needs.
//!
//! Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/

use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};

use super::reader::Reader;
use super::ArtifactParser;
use crate::timeline::{ArtifactSource, TimelineEvent};

/// HeaderSize (0x4C LE) + LinkCLSID {00021401-0000-0000-C000-000000000046}.
pub const HEADER_MAGIC: [u8; 20] = [
    0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
];

const HEADER_SIZE: usize = 0x4C;

const HAS_LINK_TARGET_ID_LIST: u32 = 0x0001;
const HAS_LINK_INFO: u32 = 0x0002;
const HAS_NAME: u32 = 0x0004;
const HAS_RELATIVE_PATH: u32 = 0x0008;
const HAS_WORKING_DIR: u32 = 0x0010;
const HAS_ARGUMENTS: u32 = 0x0020;
const HAS_ICON_LOCATION: u32 = 0x0040;
const IS_UNICODE: u32 = 0x0080;

const BLOCK_TRACKER: u32 = 0xA000_0003;
const MAX_EXTRA_BLOCKS: usize = 64;

/// 100ns ticks between the FILETIME epoch (1601-01-01) and the Unix
/// epoch (1970-01-01).
const FILETIME_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

#[derive(Debug, Default)]
struct LnkFields {
    local_base_path: Option<String>,
    network_path: Option<String>,
    name: Option<String>,
    relative_path: Option<String>,
    working_dir: Option<String>,
    arguments: Option<String>,
    icon_location: Option<String>,
    machine_id: Option<String>,
    mac_address: Option<String>,
}

impl LnkFields {
    fn target(&self) -> Option<&str> {
        self.local_base_path
            .as_deref()
            .or(self.relative_path.as_deref())
            .or(self.network_path.as_deref())
    }
}

pub struct LnkParser;

impl ArtifactParser for LnkParser {
    fn source_name(&self) -> &'static str {
        "lnk"
    }

    fn matches(&self, raw: &[u8]) -> bool {
        raw.len() >= HEADER_MAGIC.len() && raw[..HEADER_MAGIC.len()] == HEADER_MAGIC
    }

    fn parse(&self, raw: &[u8], path: &Path) -> Vec<TimelineEvent> {
        if !self.matches(raw) {
            return Vec::new();
        }
        let r = Reader::new(raw);

        let link_flags = r.u32(20).unwrap_or(0);
        let show_command = r.u32(60).unwrap_or(0);
        let ctime = filetime_to_datetime(r.u64(28).unwrap_or(0));
        let wtime = filetime_to_datetime(r.u64(44).unwrap_or(0));
        let atime = filetime_to_datetime(r.u64(36).unwrap_or(0));

        let mut offset = HEADER_SIZE;
        offset = skip_id_list(&r, offset, link_flags);
        let (offset2, mut fields) = parse_link_info(&r, offset, link_flags);
        offset = offset2;
        offset = parse_string_data(&r, offset, link_flags, &mut fields);
        let offset3 = parse_extra_data(&r, offset, &mut fields);

        let overlay_len = raw.len().saturating_sub(offset3);

        let timestamp = wtime.or(ctime).unwrap_or_else(|| {
            // No usable header timestamp (builder kits zero these out) —
            // fall back to the file's own mtime so the event still lands
            // somewhere sane on the timeline rather than being dropped.
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .map(DateTime::<Utc>::from)
                .unwrap_or_else(|_| Utc::now())
        });

        let target = fields.target().unwrap_or("(no target)").to_string();
        let description = match &fields.arguments {
            Some(args) if !args.trim().is_empty() => {
                format!("Shortcut targets {target} with arguments: {args}")
            }
            _ => format!("Shortcut targets {target}"),
        };

        let mut event = TimelineEvent::new(
            timestamp,
            ArtifactSource::Lnk,
            "lnk_target_referenced",
            description,
            path.to_path_buf(),
        )
        .with_target(target)
        .with_extra("show_command", show_command)
        .with_extra("link_flags", format!("0x{link_flags:08x}"));

        if let Some(ct) = ctime {
            event = event.with_extra("target_created", ct.to_rfc3339());
        }
        if let Some(at) = atime {
            event = event.with_extra("target_accessed", at.to_rfc3339());
        }
        if let Some(args) = &fields.arguments {
            event = event.with_extra("arguments", args.clone());
        }
        if let Some(wd) = &fields.working_dir {
            event = event.with_extra("working_dir", wd.clone());
        }
        if let Some(icon) = &fields.icon_location {
            event = event.with_extra("icon_location", icon.clone());
        }
        if let Some(machine) = &fields.machine_id {
            event = event.with_extra("builder_machine_id", machine.clone());
        }
        if let Some(mac) = &fields.mac_address {
            event = event.with_extra("builder_mac_address", mac.clone());
        }
        if overlay_len > 16 {
            event = event.with_extra("overlay_bytes", overlay_len as u64);
        }

        vec![event]
    }
}

fn skip_id_list(r: &Reader, offset: usize, link_flags: u32) -> usize {
    if link_flags & HAS_LINK_TARGET_ID_LIST == 0 {
        return offset;
    }
    match r.u16(offset) {
        Some(size) => offset + 2 + size as usize,
        None => offset,
    }
}

fn parse_link_info(r: &Reader, offset: usize, link_flags: u32) -> (usize, LnkFields) {
    let mut out = LnkFields::default();
    if link_flags & HAS_LINK_INFO == 0 {
        return (offset, out);
    }
    let li_size = match r.u32(offset) {
        Some(v) if v >= 0x1C => v as usize,
        _ => return (offset, out),
    };
    let flags = r.u32(offset + 8).unwrap_or(0);

    if flags & 0x1 != 0 {
        // VolumeIDAndLocalBasePath
        if let Some(lbp_off) = r.u32(offset + 16) {
            if lbp_off != 0 {
                out.local_base_path = r.cstr(offset + lbp_off as usize, 1024);
            }
        }
    }
    if flags & 0x2 != 0 {
        // CommonNetworkRelativeLinkAndPathSuffix
        if let Some(cnrl_off) = r.u32(offset + 20) {
            if cnrl_off != 0 {
                let cnrl_off = offset + cnrl_off as usize;
                if let Some(net_off) = r.u32(cnrl_off + 8) {
                    if net_off != 0 {
                        out.network_path = r.cstr(cnrl_off + net_off as usize, 1024);
                    }
                }
            }
        }
    }
    (offset + li_size, out)
}

type StringFieldSetter = fn(&mut LnkFields, String);

fn parse_string_data(r: &Reader, mut offset: usize, link_flags: u32, out: &mut LnkFields) -> usize {
    let unicode = link_flags & IS_UNICODE != 0;
    let fields: [(u32, StringFieldSetter); 5] = [
        (HAS_NAME, |f, s| f.name = Some(s)),
        (HAS_RELATIVE_PATH, |f, s| f.relative_path = Some(s)),
        (HAS_WORKING_DIR, |f, s| f.working_dir = Some(s)),
        (HAS_ARGUMENTS, |f, s| f.arguments = Some(s)),
        (HAS_ICON_LOCATION, |f, s| f.icon_location = Some(s)),
    ];
    for (flag, setter) in fields {
        if link_flags & flag == 0 {
            continue;
        }
        let count = match r.u16(offset) {
            Some(c) => c as usize,
            None => break,
        };
        offset += 2;
        let nbytes = if unicode { count * 2 } else { count };
        let buf = match r.slice(offset, nbytes) {
            Some(b) => b,
            None => break,
        };
        offset += nbytes;
        let s = if unicode {
            let units: Vec<u16> = buf
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(buf).into_owned()
        };
        setter(out, s);
    }
    offset
}

fn parse_extra_data(r: &Reader, mut offset: usize, out: &mut LnkFields) -> usize {
    for _ in 0..MAX_EXTRA_BLOCKS {
        let size = match r.u32(offset) {
            Some(s) if s >= 4 => s as usize,
            Some(_) => {
                offset += 4;
                break;
            }
            None => break,
        };
        let sig = r.u32(offset + 4).unwrap_or(0);
        if !(0xA000_0000..=0xA000_000C).contains(&sig) {
            break;
        }
        if sig == BLOCK_TRACKER && size >= 0x60 {
            if let Some(machine) = r.slice(offset + 16, 16) {
                let nul = machine
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(machine.len());
                out.machine_id = Some(String::from_utf8_lossy(&machine[..nul]).into_owned());
            }
            if let Some(guid) = r.slice(offset + 48, 16) {
                out.mac_address = uuid_v1_mac(guid);
            }
        }
        offset += size;
    }
    offset
}

/// Extract the MAC node from an on-disk version-1 UUID (Droid file id).
fn uuid_v1_mac(guid: &[u8]) -> Option<String> {
    if guid.len() != 16 {
        return None;
    }
    let time_hi = u16::from_le_bytes([guid[6], guid[7]]);
    if time_hi >> 12 != 1 {
        return None;
    }
    let node = &guid[10..16];
    if node == [0u8; 6] {
        return None;
    }
    Some(
        node.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but structurally valid MS-SHLLINK builder — mirrors the
    /// fixture builder in IOC Hunter's `test_analyze_lnk.py`, just enough
    /// to exercise header + LinkInfo + StringData + tracker block.
    fn build_lnk(target: &str, args: Option<&str>, machine: Option<&str>) -> Vec<u8> {
        let ft_2023: u64 = (1_685_577_600u64 * 10_000_000) + 116_444_736_000_000_000;

        let mut flags: u32 = 0x80; // IsUnicode
        flags |= 0x0002; // HasLinkInfo
        if args.is_some() {
            flags |= 0x0020; // HasArguments
        }

        let mut header = vec![0u8; HEADER_SIZE];
        header[0..20].copy_from_slice(&HEADER_MAGIC);
        header[20..24].copy_from_slice(&flags.to_le_bytes());
        header[28..36].copy_from_slice(&ft_2023.to_le_bytes()); // ctime
        header[36..44].copy_from_slice(&ft_2023.to_le_bytes()); // atime
        header[44..52].copy_from_slice(&ft_2023.to_le_bytes()); // wtime
        header[60..64].copy_from_slice(&1u32.to_le_bytes()); // ShowCommand

        // LinkInfo: VolumeIDAndLocalBasePath only.
        let lbp = target.as_bytes();
        let vol = {
            let mut v = vec![0u8; 16];
            v[0..4].copy_from_slice(&0x11u32.to_le_bytes());
            v
        };
        let vol_off: u32 = 0x1C;
        let lbp_off: u32 = vol_off + vol.len() as u32;
        let mut link_info_body = Vec::new();
        link_info_body.extend_from_slice(&0u32.to_le_bytes()); // LinkInfoSize placeholder
        link_info_body.extend_from_slice(&0x1Cu32.to_le_bytes()); // LinkInfoHeaderSize
        link_info_body.extend_from_slice(&0x1u32.to_le_bytes()); // Flags: VolumeIDAndLocalBasePath
        link_info_body.extend_from_slice(&vol_off.to_le_bytes());
        link_info_body.extend_from_slice(&lbp_off.to_le_bytes());
        link_info_body.extend_from_slice(&0u32.to_le_bytes());
        link_info_body.extend_from_slice(&(lbp_off + lbp.len() as u32 + 1).to_le_bytes());
        link_info_body.extend_from_slice(&vol);
        link_info_body.extend_from_slice(lbp);
        link_info_body.push(0);
        let total_len = link_info_body.len() as u32;
        link_info_body[0..4].copy_from_slice(&total_len.to_le_bytes());

        let mut string_data = Vec::new();
        if let Some(a) = args {
            let units: Vec<u16> = a.encode_utf16().collect();
            string_data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                string_data.extend_from_slice(&u.to_le_bytes());
            }
        }

        let mut extra = Vec::new();
        if let Some(m) = machine {
            let mut block = vec![0u8; 0x60];
            block[0..4].copy_from_slice(&0x60u32.to_le_bytes());
            block[4..8].copy_from_slice(&BLOCK_TRACKER.to_le_bytes());
            let mbytes = m.as_bytes();
            block[16..16 + mbytes.len().min(16)].copy_from_slice(&mbytes[..mbytes.len().min(16)]);
            // Version-1 UUID at offset 48..64: set version nibble + a MAC node.
            block[48 + 7] = 0x10; // time_hi_and_version high byte -> version 1
            block[48 + 10..48 + 16].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            extra.extend_from_slice(&block);
        }
        extra.extend_from_slice(&0u32.to_le_bytes()); // terminal block

        let mut out = header;
        out.extend_from_slice(&link_info_body);
        out.extend_from_slice(&string_data);
        out.extend_from_slice(&extra);
        out
    }

    #[test]
    fn parses_target_and_timestamp() {
        let raw = build_lnk(r"C:\Windows\System32\cmd.exe", None, None);
        let parser = LnkParser;
        assert!(parser.matches(&raw));
        let events = parser.parse(&raw, Path::new("test.lnk"));
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].target_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            events[0].timestamp.to_rfc3339(),
            "2023-06-01T00:00:00+00:00"
        );
    }

    #[test]
    fn captures_arguments_and_tracker_provenance() {
        let raw = build_lnk(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            Some("-enc AAAA"),
            Some("BUILDER-PC"),
        );
        let parser = LnkParser;
        let events = parser.parse(&raw, Path::new("evil.lnk"));
        assert_eq!(events.len(), 1);
        let extra = &events[0].extra;
        assert_eq!(
            extra.get("arguments").and_then(|v| v.as_str()),
            Some("-enc AAAA")
        );
        assert_eq!(
            extra.get("builder_machine_id").and_then(|v| v.as_str()),
            Some("BUILDER-PC")
        );
        assert_eq!(
            extra.get("builder_mac_address").and_then(|v| v.as_str()),
            Some("aa:bb:cc:dd:ee:ff")
        );
    }

    #[test]
    fn non_lnk_bytes_yield_nothing() {
        let parser = LnkParser;
        let raw = b"not a shortcut".to_vec();
        assert!(!parser.matches(&raw));
        assert!(parser.parse(&raw, Path::new("x")).is_empty());
    }
}
