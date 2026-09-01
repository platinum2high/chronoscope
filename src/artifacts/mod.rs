pub mod evtx;
pub mod lnk;
pub mod mft;
pub mod prefetch;
pub mod reader;
pub mod xpress;

use std::path::Path;

use crate::timeline::TimelineEvent;

/// One artifact type's parser: raw bytes in, zero or more timeline
/// events out. Parsers never fail loudly on malformed input — a
/// corrupt/truncated artifact should yield partial (or zero) events,
/// not abort the whole collection run.
pub trait ArtifactParser {
    fn source_name(&self) -> &'static str;

    /// Cheap signature check so the collector can route a file to the
    /// right parser without depending on its extension.
    fn matches(&self, raw: &[u8]) -> bool;

    fn parse(&self, raw: &[u8], path: &Path) -> Vec<TimelineEvent>;
}
