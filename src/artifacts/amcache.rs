//! Amcache (`Amcache.hve`) artifact.
//!
//! Amcache is a registry hive Windows maintains purely for application
//! inventory (originally to power compatibility telemetry) — but it
//! keeps a record of every executable the OS has ever noticed on disk,
//! including its SHA-1, size, PE compile timestamp, and the registry
//! key's own LastWritten time. Files never touched by Prefetch (because
//! they didn't run interactively, or Prefetch was disabled/full) often
//! still show up here, which makes it one of the few artifacts that can
//! place a *specific binary* on disk at a *specific time* independent
//! of execution.
//!
//! This targets the modern (Windows 10/11) `Root\Inventory*` schema, not
//! the older Windows 8/8.1 `Root\File\{volume-guid}\...` layout — that
//! older layout is a different key structure entirely and isn't handled
//! here.
//!
//! We extract two categories, chosen because they're the two with real
//! forensic weight and because a real sample hive
//! (`tests/fixtures/amcache/Amcache.hve`) has non-empty data to validate
//! against:
//!
//! - `InventoryApplicationFile` — one subkey per file the OS has ever
//!   inventoried. `InventoryApplication` is cross-referenced by
//!   `ProgramId` to resolve which installed application (if any) each
//!   file belongs to.
//! - `InventoryDevicePnp` / `InventoryDeviceContainer` — PnP device and
//!   device-container history (useful for USB/removable-media timeline
//!   reconstruction).
//!
//! `InventoryDriverBinary`, `InventoryDriverPackage`, and
//! `InventoryApplicationShortcut` follow the same shape but aren't
//! implemented yet — the sample hive used for validation has none of
//! those populated, and adding them un-validated would mean shipping
//! unverified guesses.
//!
//! Reference: value names cross-checked directly against a real
//! Windows Server 2022 `Amcache.hve` via `impacket.winregistry`, not
//! just secondary writeups — see the module's git history for the
//! inspection notes.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};

use super::regf::{self, KeyNode, ValueNode};
use super::ArtifactParser;
use crate::timeline::{ArtifactSource, TimelineEvent};

/// Amcache-specific marker subkeys under `Root` — any one of these
/// existing is enough to tell an Amcache hive apart from every other
/// registry hive (SYSTEM, SOFTWARE, NTUSER.DAT, ...), which all share
/// the same base REGF container format.
const MARKER_SUBKEYS: [&str; 3] = [
    "InventoryApplicationFile",
    "InventoryApplication",
    "InventoryDevicePnp",
];

fn values_by_name(key: &KeyNode) -> HashMap<String, ValueNode> {
    key.values()
        .into_iter()
        .map(|v| (v.name.to_ascii_lowercase(), v))
        .collect()
}

fn get_string(values: &HashMap<String, ValueNode>, name: &str) -> Option<String> {
    values
        .get(&name.to_ascii_lowercase())
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty())
}

fn get_u32(values: &HashMap<String, ValueNode>, name: &str) -> Option<u32> {
    values
        .get(&name.to_ascii_lowercase())
        .and_then(|v| v.as_u32())
}

fn get_u64(values: &HashMap<String, ValueNode>, name: &str) -> Option<u64> {
    values
        .get(&name.to_ascii_lowercase())
        .and_then(|v| v.as_u64())
}

/// `FileId`/hash values in Amcache carry a 4-hex-character algorithm-ID
/// prefix ("0000" for SHA-1, the only algorithm Amcache has ever used)
/// before the actual 40-character digest.
fn strip_hash_prefix(raw: &str) -> &str {
    if raw.len() > 4 {
        &raw[4..]
    } else {
        raw
    }
}

/// `LinkDate` is stored as an `MM/DD/YYYY HH:MM:SS` string, in contrast
/// to every other Amcache timestamp (which comes from the registry key
/// itself as a FILETIME). It's the PE header's compile timestamp, so a
/// value far outside plausible build history is either a reproducible
/// build's hash-derived placeholder (common on modern Microsoft
/// binaries) or a sign the binary lies about its own build time — worth
/// keeping either way, never worth silently dropping.
fn parse_link_date(raw: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(raw, "%m/%d/%Y %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc())
}

fn is_amcache_hive(root: &KeyNode) -> bool {
    let Some(root_key) = root.find_subkey("Root") else {
        return false;
    };
    MARKER_SUBKEYS
        .iter()
        .any(|marker| root_key.find_subkey(marker).is_some())
}

/// Maps `ProgramId` -> the installed application's display name, built
/// from `InventoryApplication` so file entries can say *which*
/// application they belong to instead of just "Unassociated".
fn build_program_index(root_key: &KeyNode) -> HashMap<String, String> {
    let mut index = HashMap::new();
    let Some(apps) = root_key.find_subkey("InventoryApplication") else {
        return index;
    };
    for app in apps.subkeys() {
        let values = values_by_name(&app);
        if let (Some(program_id), Some(name)) = (
            get_string(&values, "ProgramId"),
            get_string(&values, "Name"),
        ) {
            index.insert(program_id, name);
        }
    }
    index
}

fn build_file_event(
    entry: &KeyNode,
    program_index: &HashMap<String, String>,
    path: &Path,
) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    let Some(recorded_at) = entry.last_written() else {
        return out;
    };
    let values = values_by_name(entry);

    let full_path = get_string(&values, "LowerCaseLongPath");
    let name = get_string(&values, "Name");
    let display_name = full_path
        .clone()
        .or_else(|| name.clone())
        .unwrap_or_else(|| entry.name());

    let sha1 = get_string(&values, "FileId").map(|f| strip_hash_prefix(&f).to_string());
    let program_id = get_string(&values, "ProgramId");
    let application_name = program_id
        .as_ref()
        .and_then(|id| program_index.get(id))
        .cloned()
        .unwrap_or_else(|| "Unassociated".to_string());
    let binary_type = get_string(&values, "BinaryType");
    let is_pe = binary_type.as_deref().is_some_and(|t| t.starts_with("pe"));

    let mut event = TimelineEvent::new(
        recorded_at,
        ArtifactSource::Amcache,
        "amcache_file_inventory",
        match &sha1 {
            Some(hash) => format!("Amcache file inventory entry: {display_name} (SHA1 {hash})"),
            None => format!("Amcache file inventory entry: {display_name}"),
        },
        path.to_path_buf(),
    );
    if let Some(fp) = &full_path {
        event = event.with_target(fp.clone());
    }
    event = event.with_extra("application_name", application_name);
    if let Some(v) = &program_id {
        event = event.with_extra("program_id", v.clone());
    }
    if let Some(v) = &sha1 {
        event = event.with_extra("sha1", v.clone());
    }
    if let Some(v) = &name {
        event = event.with_extra("name", v.clone());
    }
    if let Some(v) = get_string(&values, "OriginalFileName") {
        event = event.with_extra("original_file_name", v);
    }
    if let Some(v) = get_string(&values, "Publisher") {
        event = event.with_extra("publisher", v);
    }
    if let Some(v) = get_string(&values, "ProductName") {
        event = event.with_extra("product_name", v);
    }
    if let Some(v) = get_string(&values, "Version") {
        event = event.with_extra("version", v);
    }
    if let Some(v) = get_string(&values, "ProductVersion") {
        event = event.with_extra("product_version", v);
    }
    if let Some(v) = &binary_type {
        event = event.with_extra("binary_type", v.clone());
    }
    event = event.with_extra("is_pe_file", is_pe);
    if let Some(v) = get_u64(&values, "Size") {
        event = event.with_extra("size", v);
    }
    if let Some(v) = get_u32(&values, "IsOsComponent") {
        event = event.with_extra("is_os_component", v != 0);
    }
    if let Some(v) = get_u32(&values, "Language") {
        event = event.with_extra("language_lcid", v);
    }
    if let Some(v) = get_u64(&values, "Usn") {
        event = event.with_extra("usn", v);
    }
    out.push(event);

    if let Some(link_date_raw) = get_string(&values, "LinkDate") {
        if let Some(link_date) = parse_link_date(&link_date_raw) {
            let now = Utc::now();
            let anomalous = link_date.year() < 1990 || link_date > now + chrono::Duration::days(30);
            let mut link_event = TimelineEvent::new(
                link_date,
                ArtifactSource::Amcache,
                "amcache_pe_link_date",
                format!("PE link/compile timestamp for {display_name}"),
                path.to_path_buf(),
            );
            if let Some(fp) = &full_path {
                link_event = link_event.with_target(fp.clone());
            }
            if anomalous {
                link_event = link_event
                    .with_extra("link_date_anomalous", true)
                    .with_extra(
                        "note",
                        "PE timestamp is implausible for a real compile date — likely a \
                     reproducible-build hash-derived placeholder, but verify it isn't backdating",
                    );
            }
            out.push(link_event);
        }
    }

    out
}

fn build_pnp_event(entry: &KeyNode, path: &Path) -> Option<TimelineEvent> {
    let recorded_at = entry.last_written()?;
    let values = values_by_name(entry);
    let description = get_string(&values, "Description").unwrap_or_else(|| entry.name());

    let mut event = TimelineEvent::new(
        recorded_at,
        ArtifactSource::Amcache,
        "amcache_device_pnp",
        format!("Device seen: {description}"),
        path.to_path_buf(),
    )
    .with_target(entry.name());

    for (field, key) in [
        ("model", "Model"),
        ("manufacturer", "Manufacturer"),
        ("class", "Class"),
        ("enumerator", "Enumerator"),
        ("hwid", "HWID"),
        ("container_id", "ContainerId"),
        ("driver_ver_date", "DriverVerDate"),
        ("driver_ver_version", "DriverVerVersion"),
        ("first_install_date", "FirstInstallDate"),
        ("install_date", "InstallDate"),
    ] {
        if let Some(v) = get_string(&values, key) {
            event = event.with_extra(field, v);
        }
    }
    Some(event)
}

fn build_container_event(entry: &KeyNode, path: &Path) -> Option<TimelineEvent> {
    let recorded_at = entry.last_written()?;
    let values = values_by_name(entry);
    let friendly_name = get_string(&values, "FriendlyName").unwrap_or_else(|| entry.name());

    let mut event = TimelineEvent::new(
        recorded_at,
        ArtifactSource::Amcache,
        "amcache_device_container",
        format!("Device container recorded: {friendly_name}"),
        path.to_path_buf(),
    )
    .with_target(entry.name());

    for (field, key) in [
        ("manufacturer", "Manufacturer"),
        ("model_name", "ModelName"),
        ("model_number", "ModelNumber"),
        ("primary_category", "PrimaryCategory"),
        ("is_connected", "IsConnected"),
        ("is_active", "IsActive"),
        ("is_paired", "IsPaired"),
        ("is_networked", "IsNetworked"),
        ("is_machine_container", "IsMachineContainer"),
    ] {
        if let Some(v) = get_string(&values, key) {
            event = event.with_extra(field, v);
        }
    }
    Some(event)
}

pub struct AmcacheParser;

impl ArtifactParser for AmcacheParser {
    fn source_name(&self) -> &'static str {
        "amcache"
    }

    fn matches(&self, raw: &[u8]) -> bool {
        if raw.len() < 4 || &raw[0..4] != b"regf" {
            return false;
        }
        regf::parse_hive_root(raw)
            .map(|root| is_amcache_hive(&root))
            .unwrap_or(false)
    }

    fn parse(&self, raw: &[u8], path: &Path) -> Vec<TimelineEvent> {
        let Some(root) = regf::parse_hive_root(raw) else {
            return Vec::new();
        };
        let Some(root_key) = root.find_subkey("Root") else {
            return Vec::new();
        };
        if !is_amcache_hive(&root) {
            return Vec::new();
        }

        let mut events = Vec::new();
        let program_index = build_program_index(&root_key);

        if let Some(iaf) = root_key.find_subkey("InventoryApplicationFile") {
            for entry in iaf.subkeys() {
                events.extend(build_file_event(&entry, &program_index, path));
            }
        }
        if let Some(pnp) = root_key.find_subkey("InventoryDevicePnp") {
            for entry in pnp.subkeys() {
                if let Some(e) = build_pnp_event(&entry, path) {
                    events.push(e);
                }
            }
        }
        if let Some(containers) = root_key.find_subkey("InventoryDeviceContainer") {
            for entry in containers.subkeys() {
                if let Some(e) = build_container_event(&entry, path) {
                    events.push(e);
                }
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_hive_bytes_yield_nothing() {
        let parser = AmcacheParser;
        let raw = b"not a hive".to_vec();
        assert!(!parser.matches(&raw));
        assert!(parser.parse(&raw, Path::new("x")).is_empty());
    }

    #[test]
    fn link_date_parses_expected_format() {
        let dt = parse_link_date("12/08/2054 07:28:36").unwrap();
        assert_eq!(dt.year(), 2054);
        assert_eq!(dt.month(), 12);
        assert_eq!(dt.day(), 8);
    }

    #[test]
    fn strips_sha1_algorithm_prefix() {
        assert_eq!(
            strip_hash_prefix("0000d2246473a4a77b764fe6e022073a7c94fee15f5e"),
            "d2246473a4a77b764fe6e022073a7c94fee15f5e"
        );
    }

    #[test]
    fn real_amcache_hive_yields_known_entry() {
        let raw = std::fs::read("tests/fixtures/amcache/Amcache.hve")
            .expect("real Amcache.hve fixture missing");
        let parser = AmcacheParser;
        assert!(
            parser.matches(&raw),
            "should be recognized as an Amcache hive"
        );

        let events = parser.parse(&raw, Path::new("Amcache.hve"));
        let file_events: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == "amcache_file_inventory")
            .collect();

        // Ground truth: the real hive has exactly 123
        // InventoryApplicationFile subkeys (confirmed independently via
        // impacket's registry parser, not just our own code) — see
        // tests/fixtures/amcache/README.md.
        assert_eq!(file_events.len(), 123);

        let cmd = file_events
            .iter()
            .find(|e| e.target_path.as_deref() == Some("c:\\windows\\system32\\cmd.exe"))
            .expect("cmd.exe entry should be present");
        assert_eq!(
            cmd.extra.get("sha1").and_then(|v| v.as_str()),
            Some("2ed89b5430c775306b316ba3a926d7de4fe39fc7")
        );
        assert_eq!(
            cmd.extra.get("is_os_component").and_then(|v| v.as_bool()),
            Some(true)
        );
        // cmd.exe's ProgramId doesn't match any InventoryApplication
        // entry in this hive — confirmed via the same independent
        // cross-check — so it must resolve as unassociated.
        assert_eq!(
            cmd.extra.get("application_name").and_then(|v| v.as_str()),
            Some("Unassociated")
        );

        let pnp_events = events
            .iter()
            .filter(|e| e.event_type == "amcache_device_pnp")
            .count();
        assert_eq!(pnp_events, 40);

        let container_events = events
            .iter()
            .filter(|e| e.event_type == "amcache_device_container")
            .count();
        assert_eq!(container_events, 4);
    }
}
