use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::events::{EventKind, TraceEvent};

#[derive(Clone, Serialize)]
pub struct ReportSummary {
    pub command: String,
    pub duration_secs: f64,
    pub duration_display: String,
    pub event_count: usize,
    pub heap_bytes: u64,
    pub mmap_bytes: u64,
    pub mmap_regions: usize,
    pub total_memory: u64,
    pub file_bytes_read: u64,
    pub file_bytes_written: u64,
    pub net_bytes_sent: u64,
    pub net_bytes_received: u64,
    pub files_read: usize,
    pub files_written: usize,
    pub connections: Vec<String>,
    pub subprocesses: Vec<String>,
    pub exit_status: String,
    pub page_faults: u64,
    pub page_fault_bytes: u64,
    pub perf_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_event_count: Option<usize>,
}

/// Coalesce consecutive same-pid same-type same-target I/O events into single events.
/// Non-I/O events pass through unchanged.
pub fn coalesce_events(events: &[TraceEvent]) -> Vec<TraceEvent> {
    let mut out: Vec<TraceEvent> = Vec::with_capacity(events.len());

    for ev in events {
        let merged = if let Some(last) = out.last_mut() {
            if last.pid != ev.pid {
                false
            } else {
                match (&mut last.kind, &ev.kind) {
                    (
                        &mut EventKind::Read {
                            ref mut bytes,
                            ref filename,
                            ref target,
                            ref mut count,
                        },
                        EventKind::Read {
                            bytes: rb,
                            filename: rf,
                            target: rt,
                            ..
                        },
                    ) if filename == rf && target == rt => {
                        *bytes += rb;
                        *count = Some(count.unwrap_or(1) + 1);
                        true
                    }
                    (
                        &mut EventKind::Write {
                            ref mut bytes,
                            ref filename,
                            ref target,
                            ref mut count,
                        },
                        EventKind::Write {
                            bytes: rb,
                            filename: rf,
                            target: rt,
                            ..
                        },
                    ) if filename == rf && target == rt => {
                        *bytes += rb;
                        *count = Some(count.unwrap_or(1) + 1);
                        true
                    }
                    (
                        &mut EventKind::Send {
                            ref mut bytes,
                            ref mut count,
                        },
                        EventKind::Send { bytes: rb, .. },
                    ) => {
                        *bytes += rb;
                        *count = Some(count.unwrap_or(1) + 1);
                        true
                    }
                    (
                        &mut EventKind::Recv {
                            ref mut bytes,
                            ref mut count,
                        },
                        EventKind::Recv { bytes: rb, .. },
                    ) => {
                        *bytes += rb;
                        *count = Some(count.unwrap_or(1) + 1);
                        true
                    }
                    _ => false,
                }
            }
        } else {
            false
        };

        if !merged {
            out.push(ev.clone());
        }
    }

    out
}

pub fn generate(events: &[TraceEvent], summary: &ReportSummary, path: &str) -> Result<()> {
    let events_json = serde_json::to_string(events).context("Failed to serialize events")?;
    let summary_json = serde_json::to_string(summary).context("Failed to serialize summary")?;

    let css = include_str!("report.css");
    let js = include_str!("report.js");

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compendium Trace Report</title>
<style>{css}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Compendium Trace Report</h1>
    <div class="subtitle"><span>{command}</span> &middot; {duration} &middot; {count} events</div>
  </div>
  <div class="cards" id="cards"></div>
  <div class="filters" id="filters"></div>
  <div class="timeline-section">
    <h2>Timeline</h2>
    <div id="timeline"></div>
  </div>
  <div class="table-section">
    <h2>Events</h2>
    <div class="table-header">
      <span>Time</span><span>PID</span><span>Category</span><span>Type</span><span>Details</span>
    </div>
    <div class="table-viewport" id="table-viewport"></div>
  </div>
</div>
<div class="hover-detail" id="hover-detail">
  <div class="hd-type"></div>
  <div class="hd-detail"></div>
</div>
<script>
window.TRACE_EVENTS = {events_json};
window.TRACE_SUMMARY = {summary_json};
</script>
<script>{js}</script>
</body>
</html>"##,
        css = css,
        command = html_escape(&summary.command),
        duration = &summary.duration_display,
        count = summary.event_count,
        events_json = events_json,
        summary_json = summary_json,
        js = js,
    );

    fs::write(Path::new(path), html)
        .with_context(|| format!("Failed to write report to {}", path))?;
    eprintln!("compendium: report written to {}", path);
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
