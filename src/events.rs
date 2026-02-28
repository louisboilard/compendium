//! Event types emitted during tracing and serialized into the HTML report.
//!
//! Each syscall handler produces an [`EventKind`] variant which is wrapped in a
//! [`TraceEvent`] (adding a timestamp and pid) by [`Tracer::record_event`](crate::Tracer::record_event).

use serde::Serialize;

/// A single timestamped event from the trace.
#[derive(Clone, Debug, Serialize)]
pub struct TraceEvent {
    pub timestamp_secs: f64,
    pub pid: i32,
    pub kind: EventKind,
}

/// The payload of a trace event, tagged by syscall category.
///
/// Serialized as JSON with `serde(tag = "type")` so the report JS can
/// switch on `event.type` directly.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    Open {
        path: String,
        writable: bool,
    },
    Connect {
        sock_type: String,
        remote_addr: String,
    },
    Brk {
        growth_bytes: u64,
    },
    Mmap {
        addr: String,
        end_addr: String,
        size: u64,
        prot: String,
        map_type: String,
    },
    Read {
        bytes: u64,
        filename: String,
        target: IoTarget,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
    },
    Write {
        bytes: u64,
        filename: String,
        target: IoTarget,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
    },
    Send {
        bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
    },
    Recv {
        bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
    },
    CopyFileRange {
        bytes: u64,
        src_name: String,
        dst_name: String,
    },
    Sendfile {
        bytes: u64,
        src_name: String,
        dst_name: String,
        to_network: bool,
    },
    SpawnProcess {
        child_pid: i32,
    },
    SpawnThread {
        child_tid: i32,
    },
    Exec {
        program: String,
    },
    ExitThread {
        exit_pid: i32,
        code: Option<i32>,
        signal: Option<String>,
    },
    Fault {
        addr: String,
        region_name: String,
        prot: String,
    },
    FaultGroup {
        count: u64,
        region_name: String,
        region_start: String,
        prot: String,
    },
    SchedDelay {
        delay_ns: u64,
    },
    BlockIo {
        latency_ns: u64,
        bytes: u64,
    },
    BlockIoGroup {
        count: u64,
        bytes_per_op: u64,
        total_bytes: u64,
        avg_latency_ns: u64,
        max_latency_ns: u64,
    },
    Truncated {
        original_count: usize,
        kept_count: usize,
    },
}

/// Whether an I/O event targeted a file or something else.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoTarget {
    File,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that eBPF event types serialize to the exact JSON field names
    /// that report.js expects. A field rename here would silently break the
    /// HTML report's timeline rendering and filter logic.
    #[test]
    fn sched_delay_json_shape() {
        let evt = TraceEvent {
            timestamp_secs: 1.5,
            pid: 42,
            kind: EventKind::SchedDelay { delay_ns: 50_000 },
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        assert_eq!(json["kind"]["type"], "sched_delay");
        assert_eq!(json["kind"]["delay_ns"], 50_000);
        assert_eq!(json["pid"], 42);
        assert!(json["timestamp_secs"].is_f64());
    }

    #[test]
    fn block_io_json_shape() {
        let evt = TraceEvent {
            timestamp_secs: 2.0,
            pid: 100,
            kind: EventKind::BlockIo {
                latency_ns: 1_000_000,
                bytes: 4096,
            },
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        assert_eq!(json["kind"]["type"], "block_io");
        assert_eq!(json["kind"]["latency_ns"], 1_000_000);
        assert_eq!(json["kind"]["bytes"], 4096);
    }

    #[test]
    fn block_io_group_json_shape() {
        let evt = TraceEvent {
            timestamp_secs: 3.0,
            pid: 100,
            kind: EventKind::BlockIoGroup {
                count: 10,
                bytes_per_op: 4096,
                total_bytes: 40960,
                avg_latency_ns: 500_000,
                max_latency_ns: 1_000_000,
            },
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        assert_eq!(json["kind"]["type"], "block_io_group");
        assert_eq!(json["kind"]["count"], 10);
        assert_eq!(json["kind"]["bytes_per_op"], 4096);
        assert_eq!(json["kind"]["total_bytes"], 40960);
        assert_eq!(json["kind"]["avg_latency_ns"], 500_000);
        assert_eq!(json["kind"]["max_latency_ns"], 1_000_000);
    }

    /// Verify count field is omitted when None (skip_serializing_if).
    #[test]
    fn read_event_omits_count_when_none() {
        let evt = EventKind::Read {
            bytes: 1024,
            filename: "test.txt".to_string(),
            target: IoTarget::File,
            count: None,
        };
        let json_str = serde_json::to_string(&evt).unwrap();
        assert!(!json_str.contains("count"));
    }

    /// Verify count field is present when Some.
    #[test]
    fn read_event_includes_count_when_some() {
        let evt = EventKind::Read {
            bytes: 1024,
            filename: "test.txt".to_string(),
            target: IoTarget::File,
            count: Some(5),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        assert_eq!(json["count"], 5);
    }
}
