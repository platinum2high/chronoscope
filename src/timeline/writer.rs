use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use super::TimelineEvent;

/// One JSON object per line, sorted by timestamp — easy to `jq` or feed
/// into another tool (e.g. IOC Hunter's `report` command) without
/// buffering the whole timeline into memory on read.
pub fn write_jsonl(events: &[TimelineEvent], out: &Path) -> Result<()> {
    let mut sorted: Vec<&TimelineEvent> = events.iter().collect();
    sorted.sort_by_key(|e| e.timestamp);

    let mut f =
        std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    for event in sorted {
        let line = serde_json::to_string(event)?;
        writeln!(f, "{line}")?;
    }
    Ok(())
}

/// Timeline Explorer-compatible-ish CSV: Timestamp, Source, EventType,
/// Description, ArtifactPath, TargetPath — the columns most triage
/// workflows expect at a glance.
pub fn write_csv(events: &[TimelineEvent], out: &Path) -> Result<()> {
    let mut sorted: Vec<&TimelineEvent> = events.iter().collect();
    sorted.sort_by_key(|e| e.timestamp);

    let mut wtr =
        csv::Writer::from_path(out).with_context(|| format!("creating {}", out.display()))?;
    wtr.write_record([
        "Timestamp",
        "Source",
        "EventType",
        "Description",
        "ArtifactPath",
        "TargetPath",
    ])?;
    for event in sorted {
        wtr.write_record([
            event.timestamp.to_rfc3339(),
            event.source.as_str().to_string(),
            event.event_type.clone(),
            event.description.clone(),
            event.artifact_path.display().to_string(),
            event.target_path.clone().unwrap_or_default(),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}
