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
