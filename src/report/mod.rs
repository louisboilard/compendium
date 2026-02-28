//! Self-contained HTML report generation.
//!
//! Produces a single `.html` file that embeds all CSS and JS inline (via
//! `include_str!`). The report includes an interactive timeline, a virtual-
//! scrolled event table, and summary cards.
//!
//! The [`coalesce_events`] pass merges consecutive same-pid same-target I/O
//! events before they reach the report, keeping the JSON payload small.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::events::{EventKind, TraceEvent};

/// Summary data serialized into the HTML report as `window.TRACE_SUMMARY`.
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
    pub ebpf_enabled: bool,
    pub sched_delays: u64,
    pub avg_sched_delay_ns: u64,
    pub max_sched_delay_ns: u64,
    pub block_io_ops: u64,
    pub avg_block_io_ns: u64,
    pub max_block_io_ns: u64,
    pub ebpf_dropped_events: u64,
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

/// Write the self-contained HTML report to `path`.
///
/// Events are serialized as JSON into `window.TRACE_EVENTS` and the summary
/// into `window.TRACE_SUMMARY`. CSS and JS are embedded inline.
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

/// Escape `&`, `<`, `>`, and `"` for safe embedding in HTML.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, IoTarget, TraceEvent};

    // html_escape tests

    #[test]
    fn html_escape_plain_text() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    #[test]
    fn html_escape_special_chars() {
        assert_eq!(
            html_escape("<script>&\"test\"</script>"),
            "&lt;script&gt;&amp;&quot;test&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn html_escape_empty() {
        assert_eq!(html_escape(""), "");
    }

    // coalesce_events tests

    #[test]
    fn coalesce_empty() {
        let result = coalesce_events(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn coalesce_consecutive_reads_same_pid_file() {
        let events = vec![
            TraceEvent {
                timestamp_secs: 0.1,
                pid: 100,
                kind: EventKind::Read {
                    bytes: 1024,
                    filename: "data.txt".to_string(),
                    target: IoTarget::File,
                    count: None,
                },
            },
            TraceEvent {
                timestamp_secs: 0.2,
                pid: 100,
                kind: EventKind::Read {
                    bytes: 2048,
                    filename: "data.txt".to_string(),
                    target: IoTarget::File,
                    count: None,
                },
            },
        ];
        let result = coalesce_events(&events);
        assert_eq!(result.len(), 1);
        match &result[0].kind {
            EventKind::Read { bytes, count, .. } => {
                assert_eq!(*bytes, 3072);
                assert_eq!(*count, Some(2));
            }
            _ => panic!("expected Read"),
        }
    }

    #[test]
    fn coalesce_different_pid_not_merged() {
        let events = vec![
            TraceEvent {
                timestamp_secs: 0.1,
                pid: 100,
                kind: EventKind::Read {
                    bytes: 1024,
                    filename: "data.txt".to_string(),
                    target: IoTarget::File,
                    count: None,
                },
            },
            TraceEvent {
                timestamp_secs: 0.2,
                pid: 200,
                kind: EventKind::Read {
                    bytes: 2048,
                    filename: "data.txt".to_string(),
                    target: IoTarget::File,
                    count: None,
                },
            },
        ];
        let result = coalesce_events(&events);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn coalesce_non_io_breaks_merge() {
        let events = vec![
            TraceEvent {
                timestamp_secs: 0.1,
                pid: 100,
                kind: EventKind::Send {
                    bytes: 100,
                    count: None,
                },
            },
            TraceEvent {
                timestamp_secs: 0.2,
                pid: 100,
                kind: EventKind::Open {
                    path: "/tmp/x".to_string(),
                    writable: false,
                },
            },
            TraceEvent {
                timestamp_secs: 0.3,
                pid: 100,
                kind: EventKind::Send {
                    bytes: 200,
                    count: None,
                },
            },
        ];
        let result = coalesce_events(&events);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn coalesce_mixed_types() {
        let events = vec![
            TraceEvent {
                timestamp_secs: 0.1,
                pid: 1,
                kind: EventKind::Read {
                    bytes: 10,
                    filename: "a".to_string(),
                    target: IoTarget::File,
                    count: None,
                },
            },
            TraceEvent {
                timestamp_secs: 0.2,
                pid: 1,
                kind: EventKind::Read {
                    bytes: 20,
                    filename: "a".to_string(),
                    target: IoTarget::File,
                    count: None,
                },
            },
            TraceEvent {
                timestamp_secs: 0.3,
                pid: 1,
                kind: EventKind::Write {
                    bytes: 50,
                    filename: "b".to_string(),
                    target: IoTarget::File,
                    count: None,
                },
            },
            TraceEvent {
                timestamp_secs: 0.4,
                pid: 1,
                kind: EventKind::Send {
                    bytes: 100,
                    count: None,
                },
            },
            TraceEvent {
                timestamp_secs: 0.5,
                pid: 1,
                kind: EventKind::Send {
                    bytes: 200,
                    count: None,
                },
            },
        ];
        let result = coalesce_events(&events);
        assert_eq!(result.len(), 3); // Read(merged), Write, Send(merged)
        match &result[0].kind {
            EventKind::Read { bytes, count, .. } => {
                assert_eq!(*bytes, 30);
                assert_eq!(*count, Some(2));
            }
            _ => panic!("expected Read"),
        }
        match &result[2].kind {
            EventKind::Send { bytes, count } => {
                assert_eq!(*bytes, 300);
                assert_eq!(*count, Some(2));
            }
            _ => panic!("expected Send"),
        }
    }

    // coalesce_events: eBPF events must pass through unmerged

    #[test]
    fn coalesce_sched_delay_not_merged() {
        let events = vec![
            TraceEvent {
                timestamp_secs: 0.1,
                pid: 100,
                kind: EventKind::SchedDelay { delay_ns: 50_000 },
            },
            TraceEvent {
                timestamp_secs: 0.2,
                pid: 100,
                kind: EventKind::SchedDelay { delay_ns: 80_000 },
            },
        ];
        let result = coalesce_events(&events);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn coalesce_block_io_not_merged() {
        let events = vec![
            TraceEvent {
                timestamp_secs: 0.1,
                pid: 100,
                kind: EventKind::BlockIo {
                    latency_ns: 1_000_000,
                    bytes: 4096,
                },
            },
            TraceEvent {
                timestamp_secs: 0.2,
                pid: 100,
                kind: EventKind::BlockIo {
                    latency_ns: 2_000_000,
                    bytes: 4096,
                },
            },
        ];
        let result = coalesce_events(&events);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn coalesce_block_io_group_not_merged() {
        let events = vec![
            TraceEvent {
                timestamp_secs: 0.1,
                pid: 100,
                kind: EventKind::BlockIoGroup {
                    count: 10,
                    bytes_per_op: 4096,
                    total_bytes: 40960,
                    avg_latency_ns: 500_000,
                    max_latency_ns: 1_000_000,
                },
            },
            TraceEvent {
                timestamp_secs: 0.2,
                pid: 100,
                kind: EventKind::BlockIoGroup {
                    count: 5,
                    bytes_per_op: 4096,
                    total_bytes: 20480,
                    avg_latency_ns: 300_000,
                    max_latency_ns: 800_000,
                },
            },
        ];
        let result = coalesce_events(&events);
        assert_eq!(result.len(), 2);
    }

    // generate test

    #[test]
    fn generate_writes_valid_html() {
        let dir = std::env::temp_dir().join("compendium_test_report");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_report.html");
        let path_str = path.to_str().unwrap();

        let events = vec![TraceEvent {
            timestamp_secs: 0.1,
            pid: 42,
            kind: EventKind::Open {
                path: "/tmp/test".to_string(),
                writable: false,
            },
        }];
        let summary = ReportSummary {
            command: "test-cmd".to_string(),
            duration_secs: 1.5,
            duration_display: "1.5s".to_string(),
            event_count: 1,
            heap_bytes: 0,
            mmap_bytes: 0,
            mmap_regions: 0,
            total_memory: 0,
            file_bytes_read: 0,
            file_bytes_written: 0,
            net_bytes_sent: 0,
            net_bytes_received: 0,
            files_read: 1,
            files_written: 0,
            connections: vec![],
            subprocesses: vec![],
            exit_status: "0".to_string(),
            page_faults: 0,
            page_fault_bytes: 0,
            perf_enabled: false,
            ebpf_enabled: false,
            sched_delays: 0,
            avg_sched_delay_ns: 0,
            max_sched_delay_ns: 0,
            block_io_ops: 0,
            avg_block_io_ns: 0,
            max_block_io_ns: 0,
            ebpf_dropped_events: 0,
            truncated: None,
            original_event_count: None,
        };

        generate(&events, &summary, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("<title>Compendium Trace Report</title>"));
        assert!(content.contains("TRACE_EVENTS"));
        assert!(content.contains("TRACE_SUMMARY"));
        assert!(content.contains("test-cmd"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
