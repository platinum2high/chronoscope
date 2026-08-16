# Chronoscope

> DFIR triage collector. Pulls forensic artifacts from a live host and
> builds one normalized timeline — no installers, no runtime, one
> static binary you can drop on a box mid-incident and run.

![CI](https://github.com/platinum2high/chronoscope/actions/workflows/ci.yml/badge.svg)
![Rust](https://img.shields.io/badge/rust-stable-orange)
![License](https://img.shields.io/badge/license-AGPL--3.0-3fb950)

---

## Why

Live-response triage today means reaching for a handful of separate
tools (KAPE to collect, a parser per artifact type, Timeline Explorer or
Plaso to line them up) — each with its own install story, and most of
them .NET/Python tools that need a runtime you may not want to drop on
a client's production host.

Chronoscope is a single static Rust binary that does artifact
collection *and* timeline normalization in one pass: point it at a
directory (a mounted image, a live `C:\Users\...` path, an exported
artifact bundle) and it walks every file, hands each one to the parser
that recognizes its format, and emits a single sorted timeline —
JSONL or CSV.

It's the third piece of a small SOC toolchain: Chronoscope collects and
times the artifacts, [IOC Hunter](https://github.com/platinum2high/ioc-hunter)
enriches whatever indicators fall out of them against threat intel, and
[YARA Studio](https://github.com/platinum2high/yara-studio) writes the
detection rule once you know what you're looking for.

---

## Status

Early — one artifact parser is live, the rest are actively being
built out. Nothing here is a KAPE replacement yet; the architecture
(one trait, one timeline model, one CLI) is built so adding an
artifact is a self-contained module, not a rewrite.

| Artifact | Status |
| --- | --- |
| **LNK** (MS-SHLLINK) | ✅ target path, arguments, tracker-block provenance (builder machine ID + MAC) |
| **EVTX** (Windows Event Log) | ✅ full BinXML + template-instance substitution engine; tailored descriptions for logons, process creation, service installs, Kerberos tickets, log clearing, Sysmon 1/3, + generic fallback for every other EventID |
| **MFT** ($MFT) | ✅ $STANDARD_INFORMATION MACB timestamps + $FILE_NAME, update-sequence fixup, flags $SI/$FN creation-time mismatch (timestomp indicator) |
| **Prefetch** | planned |
| **Amcache / ShimCache** | planned |
| **Registry hives** (SYSTEM/SOFTWARE/SAM/NTUSER) | planned |
| **Jump Lists** | planned |
| **Browser history** | planned |

## Install

```bash
git clone https://github.com/platinum2high/chronoscope
cd chronoscope
cargo build --release
# binary at target/release/chronoscope
```

## Usage

```bash
# Walk a directory, extract everything Chronoscope recognizes, sort by time
chronoscope collect ./triage-export --out timeline.jsonl

# CSV instead, for Timeline Explorer-style workflows
chronoscope collect ./triage-export --out timeline.csv --format csv

# Debug a single shortcut
chronoscope parse-lnk suspicious.lnk
```

Example event:

```json
{
  "timestamp": "2023-06-01T00:00:00Z",
  "source": "lnk",
  "event_type": "lnk_target_referenced",
  "description": "Shortcut targets C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe with arguments: -enc SGVsbG8gV29ybGQ=",
  "artifact_path": "invoice.pdf.lnk",
  "target_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "extra": {
    "arguments": "-enc SGVsbG8gV29ybGQ=",
    "builder_machine_id": "ATTACKER1",
    "builder_mac_address": "aa:bb:cc:dd:ee:ff",
    "show_command": 7
  }
}
```

## Architecture

Every artifact parser implements one trait:

```rust
pub trait ArtifactParser {
    fn source_name(&self) -> &'static str;
    fn matches(&self, raw: &[u8]) -> bool;
    fn parse(&self, raw: &[u8], path: &Path) -> Vec<TimelineEvent>;
}
```

`collect` walks the input directory, routes each file to the first
parser whose `matches` fires, and merges every `TimelineEvent` those
parsers return into one sorted output. Malformed or truncated
artifacts degrade to partial (or zero) events — a single corrupt file
never aborts a collection run.

| Module | Role |
| --- | --- |
| `timeline/` | The normalized event model + JSONL/CSV writers |
| `artifacts/reader.rs` | Bounds-checked little-endian byte reader (offset-based `Reader` + sequential `Cursor`) shared by every parser |
| `artifacts/lnk.rs` | MS-SHLLINK parser |
| `artifacts/evtx.rs` | EVTX parser — file/chunk/record walking, full BinXML tokenizer, template-instance substitution |
| `artifacts/mft.rs` | $MFT parser — FILE record fixup, $STANDARD_INFORMATION / $FILE_NAME, timestomp detection |
| `main.rs` | CLI (`collect`, `parse-lnk`) |

## License

Dual-licensed: **AGPL-3.0** (open use, see [LICENSE](LICENSE)) + a
commercial license for closed-source embedding — see
[COMMERCIAL.md](COMMERCIAL.md).
