use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct TraceEvent {
    pub timestamp_secs: f64,
    pub pid: i32,
    pub kind: EventKind,
}

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

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum IoTarget {
    File,
    Socket,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum EventCategory {
    File,
    Network,
    Memory,
    Io,
    Process,
}

impl EventKind {
    #[allow(dead_code)]
    pub fn category(&self) -> EventCategory {
        match self {
            EventKind::Open { .. } => EventCategory::File,
            EventKind::Connect { .. } => EventCategory::Network,
            EventKind::Brk { .. } => EventCategory::Memory,
            EventKind::Mmap { .. } => EventCategory::Memory,
            EventKind::Read { .. } => EventCategory::Io,
            EventKind::Write { .. } => EventCategory::Io,
            EventKind::Send { .. } => EventCategory::Network,
            EventKind::Recv { .. } => EventCategory::Network,
            EventKind::CopyFileRange { .. } => EventCategory::Io,
            EventKind::Sendfile { .. } => EventCategory::Io,
            EventKind::SpawnProcess { .. } => EventCategory::Process,
            EventKind::SpawnThread { .. } => EventCategory::Process,
            EventKind::Exec { .. } => EventCategory::Process,
            EventKind::ExitThread { .. } => EventCategory::Process,
            EventKind::Fault { .. } => EventCategory::Memory,
            EventKind::FaultGroup { .. } => EventCategory::Memory,
            EventKind::Truncated { .. } => EventCategory::Process,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_mapping() {
        assert_eq!(
            EventKind::Open {
                path: String::new(),
                writable: false
            }
            .category(),
            EventCategory::File
        );
        assert_eq!(
            EventKind::Send {
                bytes: 0,
                count: None
            }
            .category(),
            EventCategory::Network
        );
        assert_eq!(
            EventKind::Mmap {
                addr: String::new(),
                end_addr: String::new(),
                size: 0,
                prot: String::new(),
                map_type: String::new(),
            }
            .category(),
            EventCategory::Memory
        );
        assert_eq!(
            EventKind::Read {
                bytes: 0,
                filename: String::new(),
                target: IoTarget::File,
                count: None,
            }
            .category(),
            EventCategory::Io
        );
        assert_eq!(
            EventKind::Exec {
                program: String::new()
            }
            .category(),
            EventCategory::Process
        );
    }
}
