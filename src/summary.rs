use std::collections::HashSet;

use crate::events::{EventKind, TraceEvent};
use crate::types::format_bytes;
use crate::{Tracer, report};

fn compute_summary(tracer: &Tracer) -> report::ReportSummary {
    let elapsed = tracer.start_time.elapsed().as_secs_f64();
    let total_heap: u64 = tracer.total_heap_bytes
        + tracer
            .processes
            .values()
            .map(|p| p.brk.heap_size())
            .sum::<u64>();
    let mmap_total: u64 = tracer.memory.values().map(|m| m.mmap_total).sum();
    let mmap_regions: usize = tracer.memory.values().map(|m| m.mmap_regions.len()).sum();

    let exit_status = if let Some(code) = tracer.summary.exit_code {
        format!("exit {}", code)
    } else if let Some(sig) = tracer.summary.exit_signal {
        format!("killed by {:?}", sig)
    } else {
        "unknown".to_string()
    };

    report::ReportSummary {
        command: tracer.cmd_display.clone(),
        duration_secs: elapsed,
        duration_display: format!("{:.2}s", elapsed),
        event_count: tracer.events.len(),
        heap_bytes: total_heap,
        mmap_bytes: mmap_total,
        mmap_regions,
        total_memory: total_heap + mmap_total,
        file_bytes_read: tracer.io.file_bytes_read,
        file_bytes_written: tracer.io.file_bytes_written,
        net_bytes_sent: tracer.io.net_bytes_sent,
        net_bytes_received: tracer.io.net_bytes_received,
        files_read: tracer.summary.files_read.len(),
        files_written: tracer.summary.files_written.len(),
        connections: tracer.summary.connections.clone(),
        subprocesses: tracer.summary.subprocesses.clone(),
        exit_status,
        page_faults: tracer.page_faults,
        page_fault_bytes: tracer.page_faults * tracer.page_size,
        perf_enabled: tracer.perf_enabled,
        truncated: None,
        original_event_count: None,
    }
}

pub(crate) fn print_final_summary(tracer: &mut Tracer) {
    let summary = compute_summary(tracer);

    tracer.output("");
    tracer.output("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    tracer.output(&format!(
        " FINAL: {} ({})",
        summary.command, summary.duration_display
    ));
    tracer.output("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    tracer.output(" Memory:");
    tracer.output(&format!("   Heap:  {}", format_bytes(summary.heap_bytes)));
    tracer.output(&format!(
        "   Mmap:  {} ({} regions)",
        format_bytes(summary.mmap_bytes),
        summary.mmap_regions
    ));
    tracer.output(&format!("   Total: {}", format_bytes(summary.total_memory)));

    if summary.perf_enabled {
        tracer.output(" Page faults (heap/anon):");
        tracer.output(&format!("   Count:     {}", summary.page_faults));
        tracer.output(&format!("   Page size: {} B", tracer.page_size));
        tracer.output(&format!(
            "   Total:     {}",
            format_bytes(summary.page_fault_bytes)
        ));
    }

    tracer.output(" I/O:");
    tracer.output(&format!(
        "   Files read:    {}",
        format_bytes(summary.file_bytes_read)
    ));
    tracer.output(&format!(
        "   Files written: {}",
        format_bytes(summary.file_bytes_written)
    ));
    tracer.output(&format!(
        "   Net sent:      {}",
        format_bytes(summary.net_bytes_sent)
    ));
    tracer.output(&format!(
        "   Net received:  {}",
        format_bytes(summary.net_bytes_received)
    ));

    if summary.files_read > 0 || summary.files_written > 0 {
        tracer.output(" Files:");
        tracer.output(&format!("   Opened for read:  {}", summary.files_read));
        tracer.output(&format!("   Opened for write: {}", summary.files_written));
    }

    if !summary.connections.is_empty() {
        tracer.output(" Network connections:");
        for conn in summary.connections.iter().take(10) {
            tracer.output(&format!("   {}", conn));
        }
        if summary.connections.len() > 10 {
            tracer.output(&format!(
                "   ... and {} more",
                summary.connections.len() - 10
            ));
        }
    }

    if !summary.subprocesses.is_empty() {
        let unique: HashSet<_> = summary.subprocesses.iter().collect();
        tracer.output(&format!(
            " Subprocesses: {:?}",
            unique.iter().take(10).collect::<Vec<_>>()
        ));
    }

    tracer.output(&format!(" Exit: {}", summary.exit_status));
    tracer.output("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Generate HTML report if requested
    if let Some(ref report_path) = tracer.report_path {
        let original_count = tracer.events.len();
        let coalesced = report::coalesce_events(&tracer.events);
        let max = tracer.max_report_events;

        let (report_events, report_summary) = if coalesced.len() > max {
            let mut capped: Vec<TraceEvent> = coalesced.into_iter().take(max).collect();
            let last_ts = capped.last().map(|e| e.timestamp_secs).unwrap_or(0.0);
            let last_pid = capped.last().map(|e| e.pid).unwrap_or(0);
            capped.push(TraceEvent {
                timestamp_secs: last_ts,
                pid: last_pid,
                kind: EventKind::Truncated {
                    original_count,
                    kept_count: max,
                },
            });
            let mut rs = summary.clone();
            rs.event_count = capped.len();
            rs.truncated = Some(true);
            rs.original_event_count = Some(original_count);
            eprintln!(
                "compendium: warning: report capped at {} events (originally {}, use --max-report-events to adjust)",
                max, original_count
            );
            (capped, rs)
        } else {
            let mut rs = summary.clone();
            rs.event_count = coalesced.len();
            (coalesced, rs)
        };

        if let Err(e) = report::generate(&report_events, &report_summary, report_path) {
            eprintln!("compendium: failed to generate report: {}", e);
        }
    }
}
