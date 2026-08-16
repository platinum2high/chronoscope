//! Windows Event Log (EVTX) artifact.
//!
//! Ports the binary-parsing core of IOC Hunter's `analyze/evtx.py`
//! (file/chunk/record structure, BinXML tokenizer, template-instance
//! substitution) to Rust. Chronoscope stops where IOC Hunter's 25+
//! ATT&CK detection rules begin — this module's job is turning every
//! record into a timeline event with a readable one-line description,
//! not scoring it.
//!
//! References:
//! - MS-EVEN6 Windows Event Log protocol specification
//! - EVTX specification by Joachim Metz (libevtx project)
//! - python-evtx by Willi Ballenthin (MIT license) — same approach IOC
//!   Hunter's Python analyzer was built against.

use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use super::reader::Cursor;
use super::ArtifactParser;
use crate::timeline::{ArtifactSource, TimelineEvent};

const FILE_MAGIC: &[u8; 8] = b"ElfFile\0";
const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
const RECORD_MAGIC: [u8; 4] = [0x2a, 0x2a, 0x00, 0x00];

const FILE_HEADER_SIZE: usize = 4096;
const CHUNK_SIZE: usize = 65536;
const CHUNK_HEADER_TOTAL: usize = 512;
const RECORD_HEADER_SIZE: usize = 24;

const MAX_CHUNKS: usize = 32_768;
const MAX_FIELDS: usize = 256;
const MAX_FIELD_LEN: usize = 4096;

const FILETIME_EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;

// BinXML tokens.
const TOK_EOF: u8 = 0x00;
const TOK_OPEN_ELEM: u8 = 0x01;
const TOK_CLOSE_ELEM: u8 = 0x02;
const TOK_CLOSE_EMPTY: u8 = 0x03;
const TOK_END_ELEM: u8 = 0x04;
const TOK_VALUE: u8 = 0x05;
const TOK_ATTR: u8 = 0x06;
const TOK_TMPL_INST: u8 = 0x0C;
const TOK_NORM_SUBST: u8 = 0x0D;
const TOK_OPT_SUBST: u8 = 0x0E;
const TOK_FRAG_HDR: u8 = 0x0F;

// BinXML value types.
const VT_NULL: u8 = 0x00;
const VT_WSTR: u8 = 0x01;
const VT_STR: u8 = 0x02;
const VT_U8: u8 = 0x04;
const VT_U16: u8 = 0x06;
const VT_U32: u8 = 0x08;
const VT_U64: u8 = 0x0A;
const VT_BOOL: u8 = 0x0D;
const VT_BINARY: u8 = 0x0E;
const VT_GUID: u8 = 0x0F;
const VT_FILETIME: u8 = 0x11;
const VT_SYSTEMTIME: u8 = 0x12;
const VT_SID: u8 = 0x13;
const VT_HEX32: u8 = 0x14;
const VT_HEX64: u8 = 0x15;
const VT_BXML: u8 = 0x21;

const FLAG_NULL: u8 = 0x80;

/// Standard Windows event System-element template substitution slots
/// (0-indexed), used only as a last-resort fallback when a record's
/// template definition couldn't be loaded at all.
fn system_subst(id: u16) -> Option<&'static str> {
    Some(match id {
        0 => "Provider",
        1 => "ProviderGuid",
        2 => "Qualifiers",
        3 => "EventID",
        4 => "Version",
        5 => "Level",
        6 => "Task",
        7 => "Opcode",
        8 => "Keywords",
        9 => "TimeCreated",
        10 => "EventRecordID",
        11 => "ActivityID",
        12 => "RelatedActivityID",
        13 => "ProcessID",
        14 => "ThreadID",
        15 => "Channel",
        16 => "Computer",
        17 => "UserID",
        _ => return None,
    })
}

#[derive(Debug, Default, Clone)]
struct TemplateInfo {
    field_map: HashMap<u16, String>,
    literal_fields: HashMap<String, String>,
}

pub struct EvtxEvent {
    pub record_id: u64,
    pub timestamp: DateTime<Utc>,
    pub event_id: u32,
    pub channel: String,
    pub computer: String,
    pub provider: String,
    pub user_sid: String,
    pub process_id: u32,
    pub fields: HashMap<String, String>,
}

// ---------------------------------------------------------------------
// FILETIME
// ---------------------------------------------------------------------

fn filetime_to_datetime(ft: u64) -> Option<DateTime<Utc>> {
    let ft = ft as i64;
    if ft <= 0 {
        return None;
    }
    let unix_100ns = ft - FILETIME_EPOCH_DIFF_100NS;
    let secs = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;
    Utc.timestamp_opt(secs, nanos).single()
}

// ---------------------------------------------------------------------
// Name / value decoding
// ---------------------------------------------------------------------

/// Read a BinXML element/attribute name from an absolute offset.
/// Layout (NameStringNode): next_offset(4) + hash(2) + length_chars(2)
/// + UTF-16LE chars (length_chars x 2) + null(2).
fn binxml_name(data: &[u8], offset: usize) -> String {
    let Some(len_bytes) = data.get(offset + 6..offset + 8) else {
        return String::new();
    };
    let length = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if length == 0 {
        return String::new();
    }
    let start = offset + 8;
    let end = start + length * 2;
    match data.get(start..end) {
        Some(bytes) => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        None => String::new(),
    }
}

fn parse_sid(data: &[u8]) -> String {
    if data.len() < 8 {
        return String::new();
    }
    let revision = data[0];
    let sub_count = data[1] as usize;
    let mut authority_bytes = [0u8; 8];
    authority_bytes[2..8].copy_from_slice(&data[2..8]);
    let authority = u64::from_be_bytes(authority_bytes);
    if data.len() < 8 + sub_count * 4 {
        return String::new();
    }
    let subs: Vec<String> = (0..sub_count)
        .map(|i| {
            let off = 8 + i * 4;
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap()).to_string()
        })
        .collect();
    format!("S-{revision}-{authority}-{}", subs.join("-"))
}

fn decode_value(data: &[u8], vtype: u8) -> String {
    match vtype {
        VT_WSTR => {
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        VT_STR => String::from_utf8_lossy(data).into_owned(),
        VT_U8 if !data.is_empty() => data[0].to_string(),
        VT_U16 if data.len() >= 2 => u16::from_le_bytes([data[0], data[1]]).to_string(),
        VT_U32 if data.len() >= 4 => u32::from_le_bytes(data[0..4].try_into().unwrap()).to_string(),
        VT_U64 if data.len() >= 8 => u64::from_le_bytes(data[0..8].try_into().unwrap()).to_string(),
        VT_HEX32 if data.len() >= 4 => {
            format!(
                "0x{:08x}",
                u32::from_le_bytes(data[0..4].try_into().unwrap())
            )
        }
        VT_HEX64 if data.len() >= 8 => {
            format!(
                "0x{:016x}",
                u64::from_le_bytes(data[0..8].try_into().unwrap())
            )
        }
        VT_FILETIME if data.len() >= 8 => {
            let ft = u64::from_le_bytes(data[0..8].try_into().unwrap());
            filetime_to_datetime(ft)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "1601-01-01T00:00:00Z".to_string())
        }
        VT_GUID if data.len() >= 16 => {
            let d1 = u32::from_le_bytes(data[0..4].try_into().unwrap());
            let d2 = u16::from_le_bytes(data[4..6].try_into().unwrap());
            let d3 = u16::from_le_bytes(data[6..8].try_into().unwrap());
            let d4 = &data[8..16];
            format!(
                "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{}}}",
                d4[0],
                d4[1],
                d4[2..6]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<String>()
            )
        }
        VT_SID => parse_sid(data),
        VT_BOOL if data.len() >= 4 => {
            if u32::from_le_bytes(data[0..4].try_into().unwrap()) != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        VT_BINARY => data.iter().map(|b| format!("{b:02x}")).collect(),
        VT_SYSTEMTIME if data.len() >= 16 => {
            let yr = u16::from_le_bytes([data[0], data[1]]);
            let mo = u16::from_le_bytes([data[2], data[3]]);
            let dy = u16::from_le_bytes([data[6], data[7]]);
            let hr = u16::from_le_bytes([data[8], data[9]]);
            let mi = u16::from_le_bytes([data[10], data[11]]);
            let sc = u16::from_le_bytes([data[12], data[13]]);
            format!("{yr:04}-{mo:02}-{dy:02}T{hr:02}:{mi:02}:{sc:02}Z")
        }
        _ if !data.is_empty() => data.iter().map(|b| format!("{b:02x}")).collect(),
        _ => String::new(),
    }
}

fn read_typed_value(r: &mut Cursor, vtype: u8) -> String {
    match vtype {
        VT_NULL => String::new(),
        VT_WSTR => match r.u16() {
            Some(len) => r
                .read(len as usize * 2)
                .map(|raw| decode_value(raw, VT_WSTR))
                .unwrap_or_default(),
            None => String::new(),
        },
        VT_STR => match r.u16() {
            Some(len) => r
                .read(len as usize)
                .map(|raw| String::from_utf8_lossy(raw).into_owned())
                .unwrap_or_default(),
            None => String::new(),
        },
        VT_U8 => r.u8().map(|v| v.to_string()).unwrap_or_default(),
        VT_U16 => r.u16().map(|v| v.to_string()).unwrap_or_default(),
        VT_U32 => r.u32().map(|v| v.to_string()).unwrap_or_default(),
        VT_U64 => r.u64().map(|v| v.to_string()).unwrap_or_default(),
        VT_HEX32 => r.u32().map(|v| format!("0x{v:08x}")).unwrap_or_default(),
        VT_HEX64 => r.u64().map(|v| format!("0x{v:016x}")).unwrap_or_default(),
        VT_FILETIME => r
            .u64()
            .map(|v| decode_value(&v.to_le_bytes(), VT_FILETIME))
            .unwrap_or_default(),
        VT_GUID => r
            .read(16)
            .map(|raw| decode_value(raw, VT_GUID))
            .unwrap_or_default(),
        VT_SID => {
            if r.remaining() < 2 {
                return String::new();
            }
            let sub_count = r.data[r.pos + 1] as usize;
            r.read(8 + sub_count * 4).map(parse_sid).unwrap_or_default()
        }
        VT_BOOL => r
            .u32()
            .map(|v| if v != 0 { "true" } else { "false" }.to_string())
            .unwrap_or_default(),
        VT_BINARY => match r.u16() {
            Some(len) => r
                .read(len as usize)
                .map(|raw| raw.iter().map(|b| format!("{b:02x}")).collect())
                .unwrap_or_default(),
            None => String::new(),
        },
        VT_SYSTEMTIME => r
            .read(16)
            .map(|raw| decode_value(raw, VT_SYSTEMTIME))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------
// Template definition parsing
// ---------------------------------------------------------------------

fn subst_context_name(elem: &str, attr: &str) -> Option<&'static str> {
    Some(match (elem, attr) {
        ("Provider", "Name") => "Provider",
        ("Provider", "Guid") => "ProviderGuid",
        ("EventID", "Qualifiers") => "Qualifiers",
        ("EventID", "") => "EventID",
        ("Level", "") => "Level",
        ("Task", "") => "Task",
        ("Opcode", "") => "Opcode",
        ("Keywords", "") => "Keywords",
        ("TimeCreated", "SystemTime") => "TimeCreated",
        ("EventRecordID", "") => "EventRecordID",
        ("Execution", "ProcessID") => "ProcessID",
        ("Execution", "ThreadID") => "ThreadID",
        ("Correlation", "ActivityID") => "ActivityID",
        ("Channel", "") => "Channel",
        ("Computer", "") => "Computer",
        ("Security", "UserID") => "UserID",
        ("Version", "") => "Version",
        _ => return None,
    })
}

fn parse_template_binxml(binxml: &[u8], chunk: &[u8], binxml_start: usize) -> TemplateInfo {
    let mut field_map = HashMap::new();
    let mut literal_fields = HashMap::new();
    let mut r = Cursor::new(binxml);
    let mut elem_stack: Vec<String> = Vec::new();
    let mut attr_pending = String::new();
    let mut pending_data_name = String::new();

    let skip_inline_name = |r: &mut Cursor, name_off: u32| {
        let cur_chunk_pos = binxml_start + r.pos;
        let name_off = name_off as usize;
        if name_off >= cur_chunk_pos && name_off + 8 <= chunk.len() {
            if let Some(len_bytes) = chunk.get(name_off + 6..name_off + 8) {
                let ns_len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
                r.skip(10 + ns_len * 2);
            }
        }
    };

    while r.remaining() > 0 {
        let Some(tok) = r.u8() else { break };
        if tok == TOK_EOF {
            break;
        }
        match tok {
            TOK_FRAG_HDR => {
                r.skip(3);
            }
            t if t == TOK_OPEN_ELEM || t == 0x41 => {
                let has_flag = t & 0x40 != 0;
                r.skip(2); // dep_id
                r.skip(4); // data_size
                let Some(name_off) = r.u32() else { break };
                skip_inline_name(&mut r, name_off);
                if has_flag {
                    r.skip(4);
                }
                elem_stack.push(binxml_name(chunk, name_off as usize));
                pending_data_name.clear();
            }
            TOK_CLOSE_ELEM => {}
            t if t == TOK_CLOSE_EMPTY || t == TOK_END_ELEM => {
                elem_stack.pop();
            }
            t if t == TOK_ATTR || t == 0x46 => {
                let Some(name_off) = r.u32() else { break };
                skip_inline_name(&mut r, name_off);
                attr_pending = binxml_name(chunk, name_off as usize);
            }
            TOK_VALUE => {
                let Some(vtype) = r.u8() else { break };
                let val = read_typed_value(&mut r, vtype);
                if attr_pending == "Name" && elem_stack.last().map(String::as_str) == Some("Data") {
                    pending_data_name = val;
                } else if !val.is_empty() && !elem_stack.is_empty() && attr_pending.is_empty() {
                    if let Some(ctx) = subst_context_name(elem_stack.last().unwrap(), "") {
                        literal_fields.insert(ctx.to_string(), val);
                    }
                }
                attr_pending.clear();
            }
            t if t == TOK_NORM_SUBST || t == TOK_OPT_SUBST || t == 0x4D || t == 0x4E => {
                let Some(subst_id) = r.u16() else { break };
                let Some(_vtype) = r.u8() else { break };
                let elem = elem_stack.last().cloned().unwrap_or_default();
                if elem == "Data" && !pending_data_name.is_empty() {
                    field_map.insert(subst_id, pending_data_name.clone());
                } else if let Some(ctx) = subst_context_name(&elem, &attr_pending) {
                    field_map.insert(subst_id, ctx.to_string());
                }
                attr_pending.clear();
            }
            _ => {}
        }
    }

    TemplateInfo {
        field_map,
        literal_fields,
    }
}

fn load_template(
    chunk: &[u8],
    offset: usize,
    cache: &mut HashMap<usize, Rc<TemplateInfo>>,
) -> Option<Rc<TemplateInfo>> {
    if let Some(t) = cache.get(&offset) {
        return Some(t.clone());
    }
    if offset + 24 > chunk.len() {
        return None;
    }
    let data_size =
        u32::from_le_bytes(chunk[offset + 20..offset + 24].try_into().unwrap()) as usize;
    if data_size > chunk.len().saturating_sub(offset + 24) {
        return None;
    }
    let binxml_start = offset + 24;
    let binxml = &chunk[binxml_start..binxml_start + data_size];
    let info = Rc::new(parse_template_binxml(binxml, chunk, binxml_start));
    cache.insert(offset, info.clone());
    Some(info)
}

// ---------------------------------------------------------------------
// Event record BinXML
// ---------------------------------------------------------------------

fn inline_attr_key(elem: &str, attr: &str) -> Option<String> {
    match (elem, attr) {
        ("Provider", "Name") => Some("Provider".into()),
        ("Provider", "Guid") => Some("ProviderGuid".into()),
        ("EventID", "Qualifiers") => Some("Qualifiers".into()),
        ("TimeCreated", "SystemTime") => Some("TimeCreated".into()),
        ("Execution", "ProcessID") => Some("ProcessID".into()),
        ("Execution", "ThreadID") => Some("ThreadID".into()),
        ("Correlation", "ActivityID") => Some("ActivityID".into()),
        ("Security", "UserID") => Some("UserID".into()),
        ("Data", "Name") => Some("_DataName".into()),
        _ if !attr.is_empty() => Some(format!("{elem}/{attr}")),
        _ => Some(elem.to_string()),
    }
}

fn parse_bxml_blob(
    blob: &[u8],
    chunk: &[u8],
    blob_chunk_start: usize,
    tmpl_cache: &mut HashMap<usize, Rc<TemplateInfo>>,
    fields: &mut HashMap<String, String>,
) {
    let mut r = Cursor::new(blob);
    if r.remaining() < 1 {
        return;
    }
    if r.peek() == Some(TOK_FRAG_HDR) {
        r.skip(4);
    }
    if r.u8() != Some(TOK_TMPL_INST) {
        return;
    }
    r.skip(1); // unknown
    r.skip(4); // template_id
    let Some(tmpl_offset) = r.u32() else { return };
    let tmpl_offset = tmpl_offset as usize;

    if tmpl_offset == blob_chunk_start + r.pos && tmpl_offset + 24 <= chunk.len() {
        let data_length = u32::from_le_bytes(
            chunk[tmpl_offset + 20..tmpl_offset + 24]
                .try_into()
                .unwrap(),
        );
        if !r.skip(24 + data_length as usize) {
            return;
        }
    }

    let Some(num_values) = r.u32() else { return };
    if num_values > 512 {
        return;
    }

    let mut descriptors = Vec::with_capacity(num_values as usize);
    for _ in 0..num_values {
        let (Some(sz), Some(vt), Some(fl)) = (r.u16(), r.u8(), r.u8()) else {
            return;
        };
        descriptors.push((sz as usize, vt, fl));
    }

    let total: usize = descriptors.iter().map(|d| d.0).sum();
    let Some(value_blob) = r.read(total) else {
        return;
    };

    let tmpl = if tmpl_offset < chunk.len() {
        load_template(chunk, tmpl_offset, tmpl_cache)
    } else {
        None
    };

    let mut blob_pos = 0;
    for (i, (sz, vt, fl)) in descriptors.iter().enumerate() {
        let vdata = &value_blob[blob_pos..blob_pos + sz];
        blob_pos += sz;
        if fl & FLAG_NULL != 0 || *sz == 0 {
            continue;
        }
        let field_name = tmpl
            .as_ref()
            .and_then(|t| t.field_map.get(&(i as u16)))
            .cloned();
        let Some(field_name) = field_name else {
            continue;
        };
        let decoded = decode_value(vdata, *vt);
        if !decoded.is_empty() && field_name.len() <= 64 {
            fields.insert(field_name, decoded.chars().take(MAX_FIELD_LEN).collect());
        }
    }
}

fn apply_template_instance(
    r: &mut Cursor,
    chunk: &[u8],
    tmpl_cache: &mut HashMap<usize, Rc<TemplateInfo>>,
    fields: &mut HashMap<String, String>,
    binxml_start: usize,
) {
    if r.u8().is_none() {
        return;
    }
    if !r.skip(4) {
        return;
    }
    let Some(data_offset) = r.u32() else { return };
    let data_offset = data_offset as usize;

    if data_offset == binxml_start + r.pos && data_offset + 24 <= chunk.len() {
        let data_length = u32::from_le_bytes(
            chunk[data_offset + 20..data_offset + 24]
                .try_into()
                .unwrap(),
        );
        if !r.skip(24 + data_length as usize) {
            return;
        }
    }

    let Some(num_values) = r.u32() else { return };
    if num_values > 512 {
        return;
    }

    let mut descriptors = Vec::with_capacity(num_values as usize);
    for _ in 0..num_values {
        let (Some(sz), Some(vt), Some(fl)) = (r.u16(), r.u8(), r.u8()) else {
            return;
        };
        descriptors.push((sz as usize, vt, fl));
    }

    let total: usize = descriptors.iter().map(|d| d.0).sum();
    let value_blob_chunk_start = binxml_start + r.pos;
    let Some(value_blob) = r.read(total) else {
        return;
    };

    let tmpl = if data_offset < chunk.len() {
        load_template(chunk, data_offset, tmpl_cache)
    } else {
        None
    };

    let mut blob_pos = 0;
    for (i, (sz, vt, fl)) in descriptors.iter().enumerate() {
        let vdata = &value_blob[blob_pos..blob_pos + sz];
        let entry_chunk_start = value_blob_chunk_start + blob_pos;
        blob_pos += sz;

        if fl & FLAG_NULL != 0 || *sz == 0 {
            continue;
        }
        if *vt == VT_BXML {
            parse_bxml_blob(vdata, chunk, entry_chunk_start, tmpl_cache, fields);
            continue;
        }

        let field_name = tmpl
            .as_ref()
            .and_then(|t| t.field_map.get(&(i as u16)).cloned())
            .or_else(|| system_subst(i as u16).map(String::from));
        let Some(field_name) = field_name else {
            continue;
        };
        let decoded = decode_value(vdata, *vt);
        if !decoded.is_empty() && field_name.len() <= 64 {
            fields.insert(field_name, decoded.chars().take(MAX_FIELD_LEN).collect());
        }
    }

    if let Some(t) = &tmpl {
        for (k, v) in &t.literal_fields {
            fields
                .entry(k.clone())
                .or_insert_with(|| v.chars().take(MAX_FIELD_LEN).collect());
        }
    }
}

fn parse_event_binxml(
    binxml: &[u8],
    chunk: &[u8],
    tmpl_cache: &mut HashMap<usize, Rc<TemplateInfo>>,
    binxml_start: usize,
) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut elem_stack: Vec<String> = Vec::new();
    let mut attr_pending = String::new();
    let mut r = Cursor::new(binxml);

    while r.remaining() > 0 && fields.len() < MAX_FIELDS {
        let Some(tok) = r.u8() else { break };
        if tok == TOK_EOF {
            break;
        }
        match tok {
            TOK_FRAG_HDR => {
                if !r.skip(3) {
                    break;
                }
            }
            TOK_OPEN_ELEM => {
                if !r.skip(2) || !r.skip(4) {
                    break;
                }
                let Some(name_off) = r.u32() else { break };
                elem_stack.push(binxml_name(binxml, name_off as usize));
            }
            t if t == TOK_CLOSE_ELEM || t == TOK_CLOSE_EMPTY => {
                elem_stack.pop();
                attr_pending.clear();
            }
            TOK_ATTR => {
                let Some(name_off) = r.u32() else { break };
                attr_pending = binxml_name(binxml, name_off as usize);
            }
            TOK_VALUE => {
                let Some(vtype) = r.u8() else { break };
                let val = read_typed_value(&mut r, vtype);
                if val.is_empty() {
                    attr_pending.clear();
                    continue;
                }
                let elem = elem_stack.last().cloned().unwrap_or_default();
                if !attr_pending.is_empty() {
                    if let Some(key) = inline_attr_key(&elem, &attr_pending) {
                        if key.len() <= 64 {
                            fields.insert(key, val.chars().take(MAX_FIELD_LEN).collect());
                        }
                    }
                    attr_pending.clear();
                } else if elem == "Data" {
                    if let Some(data_name) = fields.remove("_DataName") {
                        fields.insert(data_name, val.chars().take(MAX_FIELD_LEN).collect());
                    }
                } else if !elem.is_empty() && elem.len() <= 64 {
                    fields.insert(elem, val.chars().take(MAX_FIELD_LEN).collect());
                }
            }
            TOK_TMPL_INST => {
                apply_template_instance(&mut r, chunk, tmpl_cache, &mut fields, binxml_start);
            }
            t if t == TOK_NORM_SUBST || t == TOK_OPT_SUBST => {
                if !r.skip(3) {
                    break;
                }
            }
            _ => break,
        }
    }

    fields
}

// ---------------------------------------------------------------------
// File / chunk / record structure walking
// ---------------------------------------------------------------------

fn iter_chunks(raw: &[u8]) -> Vec<(usize, &[u8])> {
    let mut out = Vec::new();
    let mut offset = FILE_HEADER_SIZE;
    let mut count = 0;
    while offset + CHUNK_SIZE <= raw.len() && count < MAX_CHUNKS {
        let chunk = &raw[offset..offset + CHUNK_SIZE];
        if &chunk[0..8] == CHUNK_MAGIC.as_slice() {
            out.push((offset, chunk));
        }
        offset += CHUNK_SIZE;
        count += 1;
    }
    out
}

fn iter_chunk_records(chunk: &[u8]) -> Vec<(u64, u64, &[u8], usize)> {
    let mut out = Vec::new();
    let mut pos = CHUNK_HEADER_TOTAL;
    let n = chunk.len();

    while pos + RECORD_HEADER_SIZE <= n {
        if chunk[pos..pos + 4] != RECORD_MAGIC {
            pos += 4;
            continue;
        }
        let size = u32::from_le_bytes(chunk[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if size < RECORD_HEADER_SIZE || pos + size > n {
            pos += 4;
            continue;
        }
        let record_id = u64::from_le_bytes(chunk[pos + 8..pos + 16].try_into().unwrap());
        let filetime = u64::from_le_bytes(chunk[pos + 16..pos + 24].try_into().unwrap());
        let binxml_start = pos + RECORD_HEADER_SIZE;
        let binxml = &chunk[binxml_start..pos + size];
        out.push((record_id, filetime, binxml, binxml_start));
        pos += size;
    }
    out
}

fn decode_record(
    record_id: u64,
    filetime: u64,
    binxml: &[u8],
    chunk: &[u8],
    tmpl_cache: &mut HashMap<usize, Rc<TemplateInfo>>,
    binxml_start: usize,
) -> EvtxEvent {
    let fields = parse_event_binxml(binxml, chunk, tmpl_cache, binxml_start);

    let event_id = fields
        .get("EventID")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let process_id = fields
        .get("ProcessID")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let timestamp = fields
        .get("TimeCreated")
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| filetime_to_datetime(filetime))
        .unwrap_or_else(Utc::now);

    EvtxEvent {
        record_id,
        timestamp,
        event_id,
        channel: fields.get("Channel").cloned().unwrap_or_default(),
        computer: fields.get("Computer").cloned().unwrap_or_default(),
        provider: fields.get("Provider").cloned().unwrap_or_default(),
        user_sid: fields.get("UserID").cloned().unwrap_or_default(),
        process_id,
        fields,
    }
}

// ---------------------------------------------------------------------
// Description building — the handful of EventIDs that matter most on
// an incident timeline. Everything else still becomes an event; it
// just gets a generic description instead of a tailored one.
// ---------------------------------------------------------------------

fn describe(ev: &EvtxEvent) -> (String, Option<String>) {
    let f = |k: &str| ev.fields.get(k).map(String::as_str).unwrap_or("");
    match ev.event_id {
        4624 => (
            format!(
                "Logon: {} (type {}) from {}",
                f("TargetUserName"),
                f("LogonType"),
                f("IpAddress")
            ),
            None,
        ),
        4625 => (
            format!(
                "Failed logon: {} from {} (status {})",
                f("TargetUserName"),
                f("IpAddress"),
                f("Status")
            ),
            None,
        ),
        4688 => (
            format!(
                "Process created: {} (parent {}) cmd: {}",
                f("NewProcessName"),
                f("ParentProcessName"),
                f("CommandLine")
            ),
            Some(f("NewProcessName").to_string()).filter(|s| !s.is_empty()),
        ),
        1 if ev.provider.contains("Sysmon") => (
            format!(
                "Sysmon process create: {} (parent {}) cmd: {}",
                f("Image"),
                f("ParentImage"),
                f("CommandLine")
            ),
            Some(f("Image").to_string()).filter(|s| !s.is_empty()),
        ),
        3 if ev.provider.contains("Sysmon") => (
            format!(
                "Sysmon network connection: {} -> {}:{}",
                f("Image"),
                f("DestinationIp"),
                f("DestinationPort")
            ),
            Some(f("Image").to_string()).filter(|s| !s.is_empty()),
        ),
        4720 => (
            format!("User account created: {}", f("TargetUserName")),
            None,
        ),
        4728 | 4732 | 4756 => (
            format!(
                "Member added to privileged group {}: {}",
                f("TargetUserName"),
                f("MemberName")
            ),
            None,
        ),
        7045 => (
            format!(
                "Service installed: {} ({})",
                f("ServiceName"),
                f("ImagePath")
            ),
            Some(f("ImagePath").to_string()).filter(|s| !s.is_empty()),
        ),
        4698 => (format!("Scheduled task created: {}", f("TaskName")), None),
        1102 => (
            format!("Security audit log cleared by {}", f("SubjectUserName")),
            None,
        ),
        104 => ("System event log cleared".to_string(), None),
        4769 => (
            format!(
                "Kerberos service ticket requested: {} by {} (etype {})",
                f("ServiceName"),
                f("TargetUserName"),
                f("TicketEncryptionType")
            ),
            None,
        ),
        4768 => (
            format!(
                "Kerberos TGT requested by {} (etype {})",
                f("TargetUserName"),
                f("TicketEncryptionType")
            ),
            None,
        ),
        _ => (
            format!(
                "{} event {} on {}",
                if ev.provider.is_empty() {
                    "Unknown provider"
                } else {
                    &ev.provider
                },
                ev.event_id,
                ev.channel
            ),
            None,
        ),
    }
}

pub struct EvtxParser;

impl ArtifactParser for EvtxParser {
    fn source_name(&self) -> &'static str {
        "evtx"
    }

    fn matches(&self, raw: &[u8]) -> bool {
        raw.len() >= 8 && &raw[0..8] == FILE_MAGIC.as_slice()
    }

    fn parse(&self, raw: &[u8], path: &Path) -> Vec<TimelineEvent> {
        if !self.matches(raw) {
            return Vec::new();
        }
        let mut events = Vec::new();

        for (_chunk_offset, chunk) in iter_chunks(raw) {
            let mut tmpl_cache: HashMap<usize, Rc<TemplateInfo>> = HashMap::new();
            for (record_id, filetime, binxml, binxml_start) in iter_chunk_records(chunk) {
                let ev = decode_record(
                    record_id,
                    filetime,
                    binxml,
                    chunk,
                    &mut tmpl_cache,
                    binxml_start,
                );
                let (description, target) = describe(&ev);

                let mut event = TimelineEvent::new(
                    ev.timestamp,
                    ArtifactSource::Evtx,
                    format!("evtx_event_{}", ev.event_id),
                    description,
                    path.to_path_buf(),
                )
                .with_extra("record_id", ev.record_id)
                .with_extra("event_id", ev.event_id)
                .with_extra("channel", ev.channel.clone())
                .with_extra("computer", ev.computer.clone())
                .with_extra("provider", ev.provider.clone());

                if let Some(t) = target {
                    event = event.with_target(t);
                }
                if !ev.user_sid.is_empty() {
                    event = event.with_extra("user_sid", ev.user_sid.clone());
                }
                if ev.process_id != 0 {
                    event = event.with_extra("process_id", ev.process_id);
                }
                let extra_fields: serde_json::Map<String, Value> = ev
                    .fields
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                event = event.with_extra("fields", Value::Object(extra_fields));

                events.push(event);
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD_HEADER_SIZE: usize = 24;

    fn name_node(name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// Minimal template BinXML builder. Names are embedded *inline* at
    /// first use (chunk-relative offset written immediately followed by
    /// the NameStringNode bytes) — matching genuine EVTX layout, which
    /// is what `parse_template_binxml`'s inline-name skip logic expects.
    struct TemplateBuilder {
        chunk_base: usize,
        tok: Vec<u8>,
        name_off: HashMap<String, u32>,
    }

    impl TemplateBuilder {
        fn new(chunk_base: usize) -> Self {
            Self {
                chunk_base,
                tok: Vec::new(),
                name_off: HashMap::new(),
            }
        }
        fn emit_name_ref(&mut self, name: &str) {
            if let Some(&off) = self.name_off.get(name) {
                self.tok.extend_from_slice(&off.to_le_bytes());
            } else {
                let off = (self.chunk_base + self.tok.len() + 4) as u32;
                self.name_off.insert(name.to_string(), off);
                self.tok.extend_from_slice(&off.to_le_bytes());
                self.tok.extend_from_slice(&name_node(name));
            }
        }
        fn frag(&mut self) -> &mut Self {
            self.tok.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
            self
        }
        fn open_elem(&mut self, name: &str) -> &mut Self {
            self.tok.push(0x01);
            self.tok.extend_from_slice(&0u16.to_le_bytes());
            self.tok.extend_from_slice(&0u32.to_le_bytes());
            self.emit_name_ref(name);
            self
        }
        fn close_start(&mut self) -> &mut Self {
            self.tok.push(0x02);
            self
        }
        fn close_empty(&mut self) -> &mut Self {
            self.tok.push(0x03);
            self
        }
        fn end_elem(&mut self) -> &mut Self {
            self.tok.push(0x04);
            self
        }
        fn attr(&mut self, name: &str) -> &mut Self {
            self.tok.push(0x06);
            self.emit_name_ref(name);
            self
        }
        fn val_wstr(&mut self, s: &str) -> &mut Self {
            self.tok.extend_from_slice(&[0x05, 0x01]);
            self.tok.extend_from_slice(&(s.len() as u16).to_le_bytes());
            for u in s.encode_utf16() {
                self.tok.extend_from_slice(&u.to_le_bytes());
            }
            self
        }
        fn subst(&mut self, id: u16, vtype: u8) -> &mut Self {
            self.tok.push(0x0d);
            self.tok.extend_from_slice(&id.to_le_bytes());
            self.tok.push(vtype);
            self
        }
        fn eof(&mut self) -> &mut Self {
            self.tok.push(0x00);
            self
        }
        fn build(self) -> Vec<u8> {
            self.tok
        }
    }

    fn filetime_bytes(unix_ts: f64) -> [u8; 8] {
        let ft = ((unix_ts + 11_644_473_600.0) * 10_000_000.0) as u64;
        ft.to_le_bytes()
    }

    /// Builds a one-chunk EVTX file with a single TemplateInstance-based
    /// 4624 logon record — the dominant real-world encoding (as opposed
    /// to the literal/inline BinXML form, which is simpler to generate
    /// but rare in genuine Windows event logs). Byte layout was
    /// cross-validated against IOC Hunter's independently-implemented
    /// Python EVTX parser before being ported here as a fixture.
    fn build_template_evtx() -> Vec<u8> {
        const CHUNK_HEADER_SIZE: usize = 512;
        let binxml_start_in_chunk = CHUNK_HEADER_SIZE + RECORD_HEADER_SIZE; // 536
        let header_part_len = 14;
        let template_def_offset = binxml_start_in_chunk + header_part_len; // 550
        let template_binxml_chunk_base = template_def_offset + 24; // 574

        let mut tb = TemplateBuilder::new(template_binxml_chunk_base);
        tb.frag()
            .open_elem("Event")
            .close_start()
            .open_elem("System")
            .close_start()
            .open_elem("Provider")
            .attr("Name")
            .subst(0, VT_WSTR)
            .close_empty()
            .open_elem("EventID")
            .close_start()
            .subst(1, VT_U16)
            .end_elem()
            .open_elem("TimeCreated")
            .attr("SystemTime")
            .subst(2, VT_FILETIME)
            .close_empty()
            .open_elem("EventRecordID")
            .close_start()
            .subst(3, VT_U32)
            .end_elem()
            .open_elem("Execution")
            .attr("ProcessID")
            .subst(4, VT_U32)
            .attr("ThreadID")
            .subst(5, VT_U32)
            .close_empty()
            .open_elem("Channel")
            .close_start()
            .subst(6, VT_WSTR)
            .end_elem()
            .open_elem("Computer")
            .close_start()
            .subst(7, VT_WSTR)
            .end_elem()
            .end_elem() // /System
            .open_elem("EventData")
            .close_start()
            .open_elem("Data")
            .attr("Name")
            .val_wstr("TargetUserName")
            .close_start()
            .subst(8, VT_WSTR)
            .end_elem()
            .open_elem("Data")
            .attr("Name")
            .val_wstr("LogonType")
            .close_start()
            .subst(9, VT_U32)
            .end_elem()
            .open_elem("Data")
            .attr("Name")
            .val_wstr("IpAddress")
            .close_start()
            .subst(10, VT_WSTR)
            .end_elem()
            .end_elem() // /EventData
            .end_elem() // /Event
            .eof();
        let tmpl_binxml = tb.build();

        let mut tmpl_def = Vec::new();
        tmpl_def.extend_from_slice(&0u32.to_le_bytes()); // next_offset
        tmpl_def.extend_from_slice(&[0x11u8; 16]); // GUID
        tmpl_def.extend_from_slice(&(tmpl_binxml.len() as u32).to_le_bytes());
        tmpl_def.extend_from_slice(&tmpl_binxml);

        let unix_ts = 1_717_200_000.0;
        let values: Vec<(u8, Vec<u8>)> = vec![
            (
                VT_WSTR,
                "Microsoft-Windows-Security-Auditing"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect(),
            ),
            (VT_U16, 4624u16.to_le_bytes().to_vec()),
            (VT_FILETIME, filetime_bytes(unix_ts).to_vec()),
            (VT_U32, 1u32.to_le_bytes().to_vec()),
            (VT_U32, 4u32.to_le_bytes().to_vec()),
            (VT_U32, 8u32.to_le_bytes().to_vec()),
            (
                VT_WSTR,
                "Security"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect(),
            ),
            (
                VT_WSTR,
                "WIN-DC01"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect(),
            ),
            (
                VT_WSTR,
                "jdoe"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect(),
            ),
            (VT_U32, 10u32.to_le_bytes().to_vec()),
            (
                VT_WSTR,
                "10.0.0.5"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect(),
            ),
        ];
        let mut descriptors = Vec::new();
        let mut value_blob = Vec::new();
        for (vt, data) in &values {
            descriptors.extend_from_slice(&(data.len() as u16).to_le_bytes());
            descriptors.push(*vt);
            descriptors.push(0); // flags
            value_blob.extend_from_slice(data);
        }

        let mut header_part = Vec::new();
        header_part.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]); // FragHeader
        header_part.push(TOK_TMPL_INST);
        header_part.push(0); // unknown
        header_part.extend_from_slice(&0u32.to_le_bytes()); // template_id
        header_part.extend_from_slice(&(template_def_offset as u32).to_le_bytes()); // data_offset
        assert_eq!(header_part.len(), header_part_len);

        let mut record_binxml = header_part;
        record_binxml.extend_from_slice(&tmpl_def);
        record_binxml.extend_from_slice(&(values.len() as u32).to_le_bytes());
        record_binxml.extend_from_slice(&descriptors);
        record_binxml.extend_from_slice(&value_blob);

        let total = RECORD_HEADER_SIZE + record_binxml.len();
        let ft = u64::from_le_bytes(filetime_bytes(unix_ts));
        let mut record = Vec::new();
        record.extend_from_slice(&RECORD_MAGIC);
        record.extend_from_slice(&(total as u32).to_le_bytes());
        record.extend_from_slice(&1u64.to_le_bytes()); // record_id
        record.extend_from_slice(&ft.to_le_bytes());
        record.extend_from_slice(&record_binxml);

        let mut chunk_hdr = vec![0u8; CHUNK_HEADER_SIZE];
        chunk_hdr[0..8].copy_from_slice(CHUNK_MAGIC.as_slice());
        chunk_hdr[8..16].copy_from_slice(&1u64.to_le_bytes());
        chunk_hdr[16..24].copy_from_slice(&1u64.to_le_bytes());
        chunk_hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
        chunk_hdr[32..40].copy_from_slice(&1u64.to_le_bytes());
        chunk_hdr[40..44].copy_from_slice(&128u32.to_le_bytes());

        let mut chunk = chunk_hdr;
        chunk.extend_from_slice(&record);
        chunk.resize(CHUNK_SIZE, 0);

        let mut file_hdr = vec![0u8; FILE_HEADER_SIZE];
        file_hdr[0..8].copy_from_slice(FILE_MAGIC.as_slice());
        file_hdr[8..16].copy_from_slice(&0u64.to_le_bytes());
        file_hdr[16..24].copy_from_slice(&0u64.to_le_bytes());
        file_hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
        file_hdr[32..36].copy_from_slice(&128u32.to_le_bytes());
        file_hdr[36..38].copy_from_slice(&1u16.to_le_bytes());
        file_hdr[38..40].copy_from_slice(&3u16.to_le_bytes());
        file_hdr[40..42].copy_from_slice(&0x1000u16.to_le_bytes());
        file_hdr[42..44].copy_from_slice(&1u16.to_le_bytes());

        let mut full = file_hdr;
        full.extend_from_slice(&chunk);
        full
    }

    #[test]
    fn parses_template_instance_logon_event() {
        let raw = build_template_evtx();
        let parser = EvtxParser;
        assert!(parser.matches(&raw));
        let events = parser.parse(&raw, Path::new("test.evtx"));
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, "evtx_event_4624");
        assert_eq!(ev.description, "Logon: jdoe (type 10) from 10.0.0.5");
        assert_eq!(
            ev.extra.get("provider").and_then(|v| v.as_str()),
            Some("Microsoft-Windows-Security-Auditing")
        );
        assert_eq!(
            ev.extra.get("channel").and_then(|v| v.as_str()),
            Some("Security")
        );
        assert_eq!(
            ev.extra.get("computer").and_then(|v| v.as_str()),
            Some("WIN-DC01")
        );
        let fields = ev.extra.get("fields").unwrap();
        assert_eq!(
            fields.get("TargetUserName").and_then(|v| v.as_str()),
            Some("jdoe")
        );
        assert_eq!(
            fields.get("IpAddress").and_then(|v| v.as_str()),
            Some("10.0.0.5")
        );
        assert_eq!(fields.get("LogonType").and_then(|v| v.as_str()), Some("10"));
    }

    #[test]
    fn non_evtx_bytes_yield_nothing() {
        let parser = EvtxParser;
        let raw = b"not an event log".to_vec();
        assert!(!parser.matches(&raw));
        assert!(parser.parse(&raw, Path::new("x")).is_empty());
    }
}
