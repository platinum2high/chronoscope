//! Unified timeline event model. Every artifact parser normalizes its
//! findings into `TimelineEvent`s so the CLI can merge, sort, and export
//! them through one code path regardless of source artifact.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod writer;
pub use writer::{write_csv, write_jsonl};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSource {
    Lnk,
    Prefetch,
    Evtx,
    Mft,
    Registry,
    Amcache,
}

impl ArtifactSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactSource::Lnk => "lnk",
            ArtifactSource::Prefetch => "prefetch",
            ArtifactSource::Evtx => "evtx",
            ArtifactSource::Mft => "mft",
            ArtifactSource::Registry => "registry",
            ArtifactSource::Amcache => "amcache",
        }
    }
}

/// One normalized point on the host timeline.
///
/// `timestamp` is always UTC — artifact parsers are responsible for
/// converting whatever native clock the format uses (FILETIME, Unix
/// epoch, DOS date/time, ...) before constructing this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub source: ArtifactSource,
    pub event_type: String,
    pub description: String,
    pub artifact_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    /// Format-specific fields that don't fit the common schema (e.g. LNK
    /// tracker MAC address, Prefetch run count) — kept structured so
    /// downstream tools (like IOC Hunter) can still query them.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty", default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl TimelineEvent {
    pub fn new(
        timestamp: DateTime<Utc>,
        source: ArtifactSource,
        event_type: impl Into<String>,
        description: impl Into<String>,
        artifact_path: PathBuf,
    ) -> Self {
        Self {
            timestamp,
            source,
            event_type: event_type.into(),
            description: description.into(),
            artifact_path,
            target_path: None,
            extra: serde_json::Map::new(),
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target_path = Some(target.into());
        self
    }

    pub fn with_extra(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }
}
