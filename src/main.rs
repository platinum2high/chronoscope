// `chunks_exact(2)` here is decoding fixed-width UTF-16LE/other 2-byte
// fields; `as_chunks` (clippy's suggested replacement) stabilized only on
// some recent `stable` releases, and CI tracks a floating `stable`
// toolchain — pinning to the older, universally-stable API avoids a
// toolchain-version-dependent build break.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]

mod artifacts;
mod timeline;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use artifacts::evtx::EvtxParser;
use artifacts::lnk::LnkParser;
use artifacts::mft::MftParser;
use artifacts::prefetch::PrefetchParser;
use artifacts::ArtifactParser;
use timeline::TimelineEvent;

#[derive(Parser)]
#[command(
    name = "chronoscope",
    version,
    about = "DFIR triage collector — pulls forensic artifacts from a live host and builds a unified timeline."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Walk a directory (or a live artifact root) and build a timeline
    /// from every artifact Chronoscope knows how to parse.
    Collect {
        /// Directory to walk (e.g. a mounted triage image or a live
        /// C:\Users\... path).
        input: PathBuf,
        #[arg(short, long, default_value = "timeline.jsonl")]
        out: PathBuf,
        #[arg(long, value_enum, default_value = "jsonl")]
        format: OutputFormat,
    },
    /// Parse a single .lnk file and print its timeline event as JSON —
    /// useful for debugging one shortcut without a full collection run.
    ParseLnk { path: PathBuf },
    /// Parse a single .pf file and print its timeline event(s) as JSON —
    /// useful for debugging one prefetch file without a full collection run.
    ParsePrefetch { path: PathBuf },
}

#[derive(clap::ValueEnum, Clone)]
enum OutputFormat {
    Jsonl,
    Csv,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Collect { input, out, format } => collect(&input, &out, format),
        Command::ParseLnk { path } => parse_lnk(&path),
        Command::ParsePrefetch { path } => parse_prefetch(&path),
    }
}

fn collect(input: &PathBuf, out: &Path, format: OutputFormat) -> Result<()> {
    let parsers: Vec<Box<dyn ArtifactParser>> = vec![
        Box::new(LnkParser),
        Box::new(EvtxParser),
        Box::new(MftParser),
        Box::new(PrefetchParser),
    ];
    let mut events: Vec<TimelineEvent> = Vec::new();
    let mut files_seen = 0usize;

    for entry in walkdir::WalkDir::new(input)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let raw = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        files_seen += 1;
        for parser in &parsers {
            if parser.matches(&raw) {
                let new_events = parser.parse(&raw, entry.path());
                if !new_events.is_empty() {
                    eprintln!(
                        "  [{}] {} -> {} event(s)",
                        parser.source_name(),
                        entry.path().display(),
                        new_events.len()
                    );
                }
                events.extend(new_events);
                break;
            }
        }
    }

    match format {
        OutputFormat::Jsonl => timeline::write_jsonl(&events, out)?,
        OutputFormat::Csv => timeline::write_csv(&events, out)?,
    }

    eprintln!(
        "chronoscope: scanned {files_seen} files, extracted {} timeline events -> {}",
        events.len(),
        out.display()
    );
    Ok(())
}

fn parse_lnk(path: &PathBuf) -> Result<()> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parser = LnkParser;
    if !parser.matches(&raw) {
        anyhow::bail!("{} does not look like a .lnk file", path.display());
    }
    for event in parser.parse(&raw, path) {
        println!("{}", serde_json::to_string_pretty(&event)?);
    }
    Ok(())
}

fn parse_prefetch(path: &PathBuf) -> Result<()> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parser = PrefetchParser;
    if !parser.matches(&raw) {
        anyhow::bail!("{} does not look like a Prefetch file", path.display());
    }
    for event in parser.parse(&raw, path) {
        println!("{}", serde_json::to_string_pretty(&event)?);
    }
    Ok(())
}
