use std::collections::{HashMap, HashSet};

use nix::sys::signal::Signal;
use nix::unistd::Pid;

/// Immutable configuration for the tracer
pub struct Config {
    pub verbose: bool,
    pub max_report_events: usize,
    pub report_path: Option<String>,
    pub cmd_display: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum FdKind {
    File {
        path: String,
        writable: bool,
    },
    Socket {
        sock_type: String,
        remote: Option<String>,
    },
    Pipe,
    Other,
}

#[derive(Clone, Default)]
pub(crate) struct FdTable {
    fds: HashMap<u64, FdKind>,
}

impl FdTable {
    pub(crate) fn add_file(&mut self, fd: u64, path: String, writable: bool) {
        self.fds.insert(fd, FdKind::File { path, writable });
    }

    pub(crate) fn add_socket(&mut self, fd: u64, sock_type: String) {
        self.fds.insert(
            fd,
            FdKind::Socket {
                sock_type,
                remote: None,
            },
        );
    }

    pub(crate) fn set_socket_remote(&mut self, fd: u64, remote: String) {
        if let Some(FdKind::Socket { remote: r, .. }) = self.fds.get_mut(&fd) {
            *r = Some(remote);
        }
    }

    pub(crate) fn add_pipe(&mut self, fd: u64) {
        self.fds.insert(fd, FdKind::Pipe);
    }

    pub(crate) fn remove(&mut self, fd: u64) {
        self.fds.remove(&fd);
    }

    pub(crate) fn dup(&mut self, old_fd: u64, new_fd: u64) {
        if let Some(kind) = self.fds.get(&old_fd).cloned() {
            self.fds.insert(new_fd, kind);
        }
    }

    pub(crate) fn get(&self, fd: u64) -> Option<&FdKind> {
        self.fds.get(&fd)
    }

    pub(crate) fn is_socket(&self, fd: u64) -> bool {
        matches!(self.fds.get(&fd), Some(FdKind::Socket { .. }))
    }

    pub(crate) fn is_file(&self, fd: u64) -> bool {
        matches!(self.fds.get(&fd), Some(FdKind::File { .. }))
    }

    pub(crate) fn file_path(&self, fd: u64) -> Option<&str> {
        match self.fds.get(&fd) {
            Some(FdKind::File { path, .. }) => Some(path.as_str()),
            _ => None,
        }
    }

    pub(crate) fn file_name(&self, fd: u64) -> Option<&str> {
        self.file_path(fd)
            .map(|p| p.split('/').next_back().unwrap_or(p))
    }
}

#[derive(Clone)]
pub(crate) struct MmapRegion {
    pub(crate) size: u64,
    pub(crate) name: String,
    pub(crate) prot: String,
}

#[derive(Default)]
pub(crate) struct MemoryStats {
    pub(crate) mmap_regions: HashMap<u64, MmapRegion>,
    pub(crate) mmap_total: u64,
}

impl MemoryStats {
    pub(crate) fn add_mmap(&mut self, addr: u64, size: u64, name: String, prot: String) {
        if addr > 0 && size > 0 {
            self.mmap_regions
                .insert(addr, MmapRegion { size, name, prot });
            self.mmap_total += size;
        }
    }

    pub(crate) fn remove_mmap(&mut self, addr: u64, size: u64) {
        if let Some(region) = self.mmap_regions.remove(&addr) {
            self.mmap_total = self.mmap_total.saturating_sub(region.size);
        } else {
            // Try to find by size if exact addr not found
            self.mmap_total = self.mmap_total.saturating_sub(size);
        }
    }

    /// Look up which region an address belongs to, returning (name, prot, region_start)
    pub(crate) fn lookup_addr_full(&self, addr: u64) -> Option<(&str, &str, u64)> {
        for (&region_addr, region) in &self.mmap_regions {
            if addr >= region_addr && addr < region_addr + region.size {
                return Some((&region.name, &region.prot, region_addr));
            }
        }

        None
    }
}

#[derive(Default)]
pub(crate) struct IoStats {
    pub(crate) file_bytes_read: u64,
    pub(crate) file_bytes_written: u64,
    pub(crate) net_bytes_sent: u64,
    pub(crate) net_bytes_received: u64,
}

#[derive(Default)]
pub(crate) struct Summary {
    pub(crate) files_read: HashSet<String>,
    pub(crate) files_written: HashSet<String>,
    pub(crate) connections: Vec<String>,
    pub(crate) subprocesses: Vec<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) exit_signal: Option<Signal>,
}

#[derive(Default)]
pub(crate) struct ProcessBrk {
    pub(crate) initial_brk: Option<u64>,
    pub(crate) current_brk: u64,
}

impl ProcessBrk {
    pub(crate) fn update(&mut self, new_brk: u64) -> Option<u64> {
        if self.initial_brk.is_none() && new_brk > 0 {
            self.initial_brk = Some(new_brk);
        }
        let old_brk = self.current_brk;
        if new_brk > 0 {
            self.current_brk = new_brk;
        }
        // Return growth if this isn't the first brk and heap grew
        if old_brk > 0 && new_brk > old_brk {
            Some(new_brk - old_brk)
        } else {
            None
        }
    }

    pub(crate) fn heap_size(&self) -> u64 {
        match self.initial_brk {
            Some(initial) if self.current_brk > initial => self.current_brk - initial,
            _ => 0,
        }
    }

    /// Reset brk tracking (called on exec when process image is replaced)
    pub(crate) fn reset(&mut self) {
        self.initial_brk = None;
        self.current_brk = 0;
    }
}

#[derive(Default)]
pub(crate) struct PerfState {
    pub(crate) enabled: bool,
    pub(crate) page_faults: u64,
    pub(crate) page_size: u64,
}

pub(crate) struct ProcessState {
    pub(crate) in_syscall: bool,
    pub(crate) last_syscall: Option<u64>,
    pub(crate) last_syscall_args: [u64; 6],
    pub(crate) fd_table: FdTable,
    pub(crate) brk: ProcessBrk,
    pub(crate) leader_pid: Pid,
}

pub(crate) fn format_bytes(bytes: u64) -> String {
    let s = if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    };
    format!("{:>8}", s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // format_bytes tests

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "     0 B");
    }

    #[test]
    fn format_bytes_bytes_range() {
        assert_eq!(format_bytes(999), "   999 B");
    }

    #[test]
    fn format_bytes_kb_boundary() {
        assert_eq!(format_bytes(1024), "  1.0 KB");
    }

    #[test]
    fn format_bytes_mb_boundary() {
        assert_eq!(format_bytes(1_048_576), "  1.0 MB");
    }

    #[test]
    fn format_bytes_gb_boundary() {
        assert_eq!(format_bytes(1_073_741_824), "  1.0 GB");
    }

    // ProcessBrk tests

    #[test]
    fn brk_first_update_sets_initial() {
        let mut brk = ProcessBrk::default();
        let result = brk.update(0x1000);
        assert_eq!(result, None);
        assert_eq!(brk.initial_brk, Some(0x1000));
        assert_eq!(brk.current_brk, 0x1000);
    }

    #[test]
    fn brk_second_update_returns_growth() {
        let mut brk = ProcessBrk::default();
        brk.update(0x1000);
        let result = brk.update(0x2000);
        assert_eq!(result, Some(0x1000));
    }

    #[test]
    fn brk_no_growth_returns_none() {
        let mut brk = ProcessBrk::default();
        brk.update(0x2000);
        let result = brk.update(0x2000);
        assert_eq!(result, None);
    }

    #[test]
    fn brk_heap_size() {
        let mut brk = ProcessBrk::default();
        brk.update(0x1000);
        brk.update(0x3000);
        assert_eq!(brk.heap_size(), 0x2000);
    }

    #[test]
    fn brk_reset_clears_state() {
        let mut brk = ProcessBrk::default();
        brk.update(0x1000);
        brk.update(0x2000);
        brk.reset();
        assert_eq!(brk.initial_brk, None);
        assert_eq!(brk.current_brk, 0);
        // After reset, next update sets new initial
        let result = brk.update(0x5000);
        assert_eq!(result, None);
        assert_eq!(brk.initial_brk, Some(0x5000));
    }

    // FdTable tests

    #[test]
    fn fd_table_add_file_and_query() {
        let mut fds = FdTable::default();
        fds.add_file(3, "/home/user/data.txt".to_string(), false);
        assert!(fds.is_file(3));
        assert!(!fds.is_socket(3));
        assert_eq!(fds.file_path(3), Some("/home/user/data.txt"));
        assert_eq!(fds.file_name(3), Some("data.txt"));
    }

    #[test]
    fn fd_table_add_socket_and_set_remote() {
        let mut fds = FdTable::default();
        fds.add_socket(4, "tcp4".to_string());
        assert!(fds.is_socket(4));
        assert!(!fds.is_file(4));
        fds.set_socket_remote(4, "93.184.216.34:443".to_string());
        match fds.get(4) {
            Some(FdKind::Socket { remote, .. }) => {
                assert_eq!(remote.as_deref(), Some("93.184.216.34:443"));
            }
            _ => panic!("expected socket"),
        }
    }

    #[test]
    fn fd_table_dup_and_remove() {
        let mut fds = FdTable::default();
        fds.add_file(3, "/tmp/foo".to_string(), true);
        fds.dup(3, 10);
        assert!(fds.is_file(10));
        assert_eq!(fds.file_path(10), Some("/tmp/foo"));
        fds.remove(3);
        assert!(fds.get(3).is_none());
        assert!(fds.is_file(10)); // dup'd fd still exists
    }

    #[test]
    fn fd_table_file_name_extracts_basename() {
        let mut fds = FdTable::default();
        fds.add_file(5, "/a/b/c/deep.txt".to_string(), false);
        assert_eq!(fds.file_name(5), Some("deep.txt"));
    }

    #[test]
    fn fd_table_nonexistent_fd() {
        let fds = FdTable::default();
        assert!(fds.get(99).is_none());
        assert!(!fds.is_file(99));
        assert!(!fds.is_socket(99));
        assert_eq!(fds.file_path(99), None);
        assert_eq!(fds.file_name(99), None);
    }

    // MemoryStats tests

    #[test]
    fn memory_stats_add_and_lookup() {
        let mut mem = MemoryStats::default();
        mem.add_mmap(0x7f000000, 4096, "libc.so".to_string(), "r-x".to_string());
        let result = mem.lookup_addr_full(0x7f000100);
        assert_eq!(result, Some(("libc.so", "r-x", 0x7f000000)));
        assert_eq!(mem.mmap_total, 4096);
    }

    #[test]
    fn memory_stats_lookup_outside_region() {
        let mut mem = MemoryStats::default();
        mem.add_mmap(0x7f000000, 4096, "libc.so".to_string(), "r-x".to_string());
        assert_eq!(mem.lookup_addr_full(0x80000000), None);
    }

    #[test]
    fn memory_stats_remove_mmap() {
        let mut mem = MemoryStats::default();
        mem.add_mmap(0x7f000000, 4096, "anon".to_string(), "rw-".to_string());
        mem.add_mmap(0x7f001000, 8192, "anon".to_string(), "rw-".to_string());
        assert_eq!(mem.mmap_total, 4096 + 8192);
        mem.remove_mmap(0x7f000000, 4096);
        assert_eq!(mem.mmap_total, 8192);
        assert!(mem.lookup_addr_full(0x7f000000).is_none());
        // Second region still present
        assert!(mem.lookup_addr_full(0x7f001000).is_some());
    }
}
