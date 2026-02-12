use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::events::{EventKind, IoTarget};
use crate::perf::PerfPageFaultTracker;
use crate::types::*;
use crate::{Tracer, memory, syscalls};

impl Tracer {
    pub(crate) fn handle_syscall(&mut self, pid: Pid) -> Result<()> {
        let regs = ptrace::getregs(pid).context("Failed to get registers")?;
        let in_syscall = self
            .processes
            .entry(pid)
            .or_insert_with(|| ProcessState {
                in_syscall: false,
                last_syscall: None,
                last_syscall_args: [0; 6],
                fd_table: FdTable::default(),
                brk: ProcessBrk::default(),
                leader_pid: pid,
            })
            .in_syscall;

        if !in_syscall {
            // Syscall ENTRY
            let syscall_num = regs.orig_rax;
            let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];

            if self.config.verbose {
                eprintln!("[{}] {}(...)", pid, syscalls::name(syscall_num));
            }

            // Handle execve at entry (doesn't return on success)
            if syscalls::name(syscall_num) == "execve"
                && (Some(pid) != self.initial_pid || !self.summary.subprocesses.is_empty())
                && let Ok(path) = memory::read_string(pid, args[0] as usize)
            {
                let cmd = path.split('/').next_back().unwrap_or(&path).to_string();
                if !cmd.is_empty() {
                    self.summary.subprocesses.push(cmd);
                }
            }

            if let Some(proc) = self.processes.get_mut(&pid) {
                proc.last_syscall = Some(syscall_num);
                proc.last_syscall_args = args;
                proc.in_syscall = true;
            }
        } else {
            // Syscall EXIT
            let ret = regs.rax as i64;

            let (last_syscall, last_args) = match self.processes.get(&pid) {
                Some(s) => (s.last_syscall, s.last_syscall_args),
                None => return Ok(()),
            };

            if let Some(syscall_num) = last_syscall {
                self.process_syscall_exit(pid, syscall_num, &last_args, ret);
            }

            if let Some(proc) = self.processes.get_mut(&pid) {
                proc.in_syscall = false;
            }
        }

        Ok(())
    }

    fn handle_file_open(&mut self, pid: Pid, fd: u64, path: String, writable: bool) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.fd_table.add_file(fd, path.clone(), writable);
        }

        if !should_ignore_path(&path) {
            self.output(&format!(
                "{} open {} ({})",
                self.event_prefix(pid),
                path,
                if writable { "write" } else { "read" }
            ));
            self.record_event(
                pid,
                EventKind::Open {
                    path: path.clone(),
                    writable,
                },
            );
            if writable {
                self.summary.files_written.insert(path);
            } else {
                self.summary.files_read.insert(path);
            }
        }
    }

    /// Handle a generic read or write I/O syscall on a file descriptor.
    /// `is_read` controls direction: true = read/recv, false = write/send.
    fn handle_fd_io(&mut self, pid: Pid, fd: u64, bytes: u64, is_read: bool) {
        let is_sock = self
            .processes
            .get(&pid)
            .is_some_and(|p| p.fd_table.is_socket(fd));
        let is_file = self
            .processes
            .get(&pid)
            .is_some_and(|p| p.fd_table.is_file(fd));

        if is_sock {
            if is_read {
                self.io.net_bytes_received += bytes;
                self.output(&format!(
                    "{} recv {}",
                    self.event_prefix(pid),
                    format_bytes(bytes)
                ));
                self.record_event(pid, EventKind::Recv { bytes, count: None });
            } else {
                self.io.net_bytes_sent += bytes;
                self.output(&format!(
                    "{} send {}",
                    self.event_prefix(pid),
                    format_bytes(bytes)
                ));
                self.record_event(pid, EventKind::Send { bytes, count: None });
            }
        } else if is_file {
            let name = self
                .processes
                .get(&pid)
                .and_then(|p| p.fd_table.file_name(fd))
                .unwrap_or("?")
                .to_string();
            if is_read {
                self.io.file_bytes_read += bytes;
                self.output(&format!(
                    "{} read {} from {}",
                    self.event_prefix(pid),
                    format_bytes(bytes),
                    name
                ));
                self.record_event(
                    pid,
                    EventKind::Read {
                        bytes,
                        filename: name,
                        target: IoTarget::File,
                        count: None,
                    },
                );
            } else {
                self.io.file_bytes_written += bytes;
                self.output(&format!(
                    "{} write {} to {}",
                    self.event_prefix(pid),
                    format_bytes(bytes),
                    name
                ));
                self.record_event(
                    pid,
                    EventKind::Write {
                        bytes,
                        filename: name,
                        target: IoTarget::File,
                        count: None,
                    },
                );
            }
        }
    }

    fn process_syscall_exit(&mut self, pid: Pid, syscall: u64, args: &[u64; 6], ret: i64) {
        let name = syscalls::name(syscall);
        match name {
            "openat" | "open" | "openat2" | "socket" | "pipe" | "pipe2" | "dup" | "dup2"
            | "dup3" | "fcntl" | "close" | "accept" | "accept4" | "connect" => {
                self.handle_fd_syscall(pid, name, args, ret);
            }
            "brk" | "mmap" | "munmap" => {
                self.handle_memory_syscall(pid, name, args, ret);
            }
            "read" | "pread64" | "readv" | "preadv" | "write" | "pwrite64" | "writev"
            | "pwritev" | "sendto" | "sendmsg" | "send" | "recvfrom" | "recvmsg" | "recv"
            | "copy_file_range" | "sendfile" => {
                self.handle_io_syscall(pid, name, args, ret);
            }
            _ => {}
        }
    }

    fn handle_fd_syscall(&mut self, pid: Pid, name: &str, args: &[u64; 6], ret: i64) {
        match name {
            "openat" if ret >= 0 => {
                let fd = ret as u64;
                if let Ok(path) = memory::read_string(pid, args[1] as usize) {
                    let flags = args[2] as i32;
                    let writable = flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0;
                    self.handle_file_open(pid, fd, path, writable);
                }
            }

            "open" if ret >= 0 => {
                let fd = ret as u64;
                if let Ok(path) = memory::read_string(pid, args[0] as usize) {
                    let flags = args[1] as i32;
                    let writable = flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0;
                    self.handle_file_open(pid, fd, path, writable);
                }
            }

            "openat2" if ret >= 0 => {
                let fd = ret as u64;
                if let Ok(path) = memory::read_string(pid, args[1] as usize) {
                    // Read open_how struct to get flags (u64 at offset 0)
                    let writable = if let Ok(buf) = memory::read_buffer(pid, args[2] as usize, 8) {
                        let flags =
                            u64::from_ne_bytes(buf[..8].try_into().unwrap_or([0; 8])) as i32;
                        flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0
                    } else {
                        false
                    };
                    self.handle_file_open(pid, fd, path, writable);
                }
            }

            "socket" if ret >= 0 => {
                let fd = ret as u64;
                let domain = args[0] as i32;
                let sock_type = args[1] as i32;

                let type_str = match (domain, sock_type & 0xf) {
                    (libc::AF_INET, libc::SOCK_STREAM) => "tcp4",
                    (libc::AF_INET, libc::SOCK_DGRAM) => "udp4",
                    (libc::AF_INET6, libc::SOCK_STREAM) => "tcp6",
                    (libc::AF_INET6, libc::SOCK_DGRAM) => "udp6",
                    (libc::AF_UNIX, _) => "unix",
                    _ => "other",
                };

                if let Some(proc) = self.processes.get_mut(&pid) {
                    proc.fd_table.add_socket(fd, type_str.to_string());
                }
            }

            "pipe" | "pipe2" if ret >= 0 => {
                // pipe() writes two fds to the int[2] array pointed to by args[0]
                let fds_ptr = args[0] as usize;
                if let Ok(buf) = memory::read_buffer(pid, fds_ptr, 8)
                    && buf.len() >= 8
                {
                    let fd0 = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
                    let fd1 = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
                    if let Some(proc) = self.processes.get_mut(&pid) {
                        proc.fd_table.add_pipe(fd0);
                        proc.fd_table.add_pipe(fd1);
                    }
                }
            }

            "dup" if ret >= 0 => {
                let old_fd = args[0];
                let new_fd = ret as u64;
                if let Some(proc) = self.processes.get_mut(&pid) {
                    proc.fd_table.dup(old_fd, new_fd);
                }
            }

            "dup2" | "dup3" if ret >= 0 => {
                let old_fd = args[0];
                let new_fd = args[1];
                if let Some(proc) = self.processes.get_mut(&pid) {
                    proc.fd_table.dup(old_fd, new_fd);
                }
            }

            "fcntl" if ret >= 0 => {
                let fd = args[0];
                let cmd = args[1] as i32;
                let new_fd = ret as u64;
                // F_DUPFD = 0, F_DUPFD_CLOEXEC = 1030
                if (cmd == 0 || cmd == 1030)
                    && let Some(proc) = self.processes.get_mut(&pid)
                {
                    proc.fd_table.dup(fd, new_fd);
                }
            }

            "close" if ret >= 0 => {
                let fd = args[0];
                if let Some(proc) = self.processes.get_mut(&pid) {
                    proc.fd_table.remove(fd);
                }
            }

            "accept" | "accept4" if ret >= 0 => {
                let new_fd = ret as u64;
                let listening_fd = args[0];
                let sock_type =
                    self.processes
                        .get(&pid)
                        .and_then(|p| match p.fd_table.get(listening_fd) {
                            Some(FdKind::Socket { sock_type, .. }) => Some(sock_type.clone()),
                            _ => None,
                        });
                if let Some(sock_type) = sock_type
                    && let Some(proc) = self.processes.get_mut(&pid)
                {
                    proc.fd_table.add_socket(new_fd, sock_type);
                }
            }

            "connect" if ret >= 0 || ret == -(libc::EINPROGRESS as i64) => {
                let fd = args[0];
                let addr_ptr = args[1] as usize;
                let addr_len = args[2] as usize;
                let prefix = self.event_prefix(pid);

                let mut output_msg = None;
                if let Some(proc) = self.processes.get_mut(&pid)
                    && let Some(FdKind::Socket { sock_type, .. }) = proc.fd_table.get(fd).cloned()
                    && (sock_type == "tcp4" || sock_type == "tcp6")
                    && let Ok(addr) = memory::read_sockaddr(pid, addr_ptr, addr_len)
                    && !addr.starts_with("AF_")
                    && !addr.contains("127.0.0.1")
                    && !addr.contains("127.0.0.53")
                {
                    output_msg = Some((
                        format!("{} connect {} → {}", prefix, sock_type, addr),
                        sock_type.clone(),
                        addr.clone(),
                    ));
                    proc.fd_table.set_socket_remote(fd, addr.clone());
                    let conn_str = format!("{} → {}", sock_type, addr);
                    if !self.summary.connections.iter().any(|c| c == &conn_str) {
                        self.summary.connections.push(conn_str);
                    }
                }
                if let Some((msg, sock_type, remote_addr)) = output_msg {
                    self.output(&msg);
                    self.record_event(
                        pid,
                        EventKind::Connect {
                            sock_type,
                            remote_addr,
                        },
                    );
                }
            }

            _ => {}
        }
    }

    fn handle_memory_syscall(&mut self, pid: Pid, name: &str, args: &[u64; 6], ret: i64) {
        match name {
            "brk" => {
                // brk returns the new program break on success
                // Each process has its own address space, so track per-process
                let new_brk = ret as u64;
                if ret > 0
                    && let Some(proc) = self.processes.get_mut(&pid)
                    && let Some(growth) = proc.brk.update(new_brk)
                    && growth > 4096
                {
                    self.output(&format!(
                        "{} brk +{}",
                        self.event_prefix(pid),
                        format_bytes(growth)
                    ));
                    self.record_event(
                        pid,
                        EventKind::Brk {
                            growth_bytes: growth,
                        },
                    );
                }
            }

            "mmap" if ret > 0 && ret != -1 => {
                let addr = ret as u64;
                let size = args[1];
                let prot = args[2] as i32;
                let flags = args[3] as i32;
                let fd = args[4] as i64;

                // Format protection flags as rwx
                let prot_str = format!(
                    "{}{}{}",
                    if prot & libc::PROT_READ != 0 {
                        "r"
                    } else {
                        "-"
                    },
                    if prot & libc::PROT_WRITE != 0 {
                        "w"
                    } else {
                        "-"
                    },
                    if prot & libc::PROT_EXEC != 0 {
                        "x"
                    } else {
                        "-"
                    }
                );

                // Determine mapping type
                let map_type = if flags & libc::MAP_ANONYMOUS != 0 {
                    "anon".to_string()
                } else if fd >= 0 {
                    // File-backed mapping - try to get filename from fd_table
                    self.processes
                        .get(&pid)
                        .and_then(|p| p.fd_table.get(fd as u64))
                        .and_then(|kind| match kind {
                            FdKind::File { path, .. } => {
                                Some(path.split('/').next_back().unwrap_or(path).to_string())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| format!("fd:{}", fd))
                } else {
                    "file".to_string()
                };

                self.memory_for(pid)
                    .add_mmap(addr, size, map_type.clone(), prot_str.clone());

                let end_addr = addr + size;
                self.output(&format!(
                    "{} mmap {:012x}-{:012x} {} {} {}",
                    self.event_prefix(pid),
                    addr,
                    end_addr,
                    prot_str,
                    format_bytes(size),
                    map_type
                ));
                self.record_event(
                    pid,
                    EventKind::Mmap {
                        addr: format!("{:012x}", addr),
                        end_addr: format!("{:012x}", end_addr),
                        size,
                        prot: prot_str,
                        map_type,
                    },
                );
            }

            "munmap" if ret >= 0 => {
                let addr = args[0];
                let size = args[1];
                self.memory_for(pid).remove_mmap(addr, size);
            }

            _ => {}
        }
    }

    fn handle_io_syscall(&mut self, pid: Pid, name: &str, args: &[u64; 6], ret: i64) {
        match name {
            "read" | "pread64" | "readv" | "preadv" if ret > 0 => {
                self.handle_fd_io(pid, args[0], ret as u64, true);
            }

            "write" | "pwrite64" | "writev" | "pwritev" if ret > 0 => {
                self.handle_fd_io(pid, args[0], ret as u64, false);
            }

            "sendto" | "sendmsg" | "send" if ret > 0 => {
                let bytes = ret as u64;
                self.io.net_bytes_sent += bytes;
                self.output(&format!(
                    "{} send {}",
                    self.event_prefix(pid),
                    format_bytes(bytes)
                ));
                self.record_event(pid, EventKind::Send { bytes, count: None });
            }

            "recvfrom" | "recvmsg" | "recv" if ret > 0 => {
                let bytes = ret as u64;
                self.io.net_bytes_received += bytes;
                self.output(&format!(
                    "{} recv {}",
                    self.event_prefix(pid),
                    format_bytes(bytes)
                ));
                self.record_event(pid, EventKind::Recv { bytes, count: None });
            }

            // copy_file_range(fd_in, off_in, fd_out, off_out, len, flags) - efficient in-kernel copy
            "copy_file_range" if ret > 0 => {
                let fd_in = args[0];
                let fd_out = args[2];
                let bytes = ret as u64;

                self.io.file_bytes_read += bytes;
                self.io.file_bytes_written += bytes;

                let src = self
                    .processes
                    .get(&pid)
                    .and_then(|p| p.fd_table.file_name(fd_in))
                    .unwrap_or("?")
                    .to_string();
                let dst = self
                    .processes
                    .get(&pid)
                    .and_then(|p| p.fd_table.file_name(fd_out))
                    .unwrap_or("?")
                    .to_string();
                self.output(&format!(
                    "{} copy {} from {} to {}",
                    self.event_prefix(pid),
                    format_bytes(bytes),
                    src,
                    dst
                ));
                self.record_event(
                    pid,
                    EventKind::CopyFileRange {
                        bytes,
                        src_name: src,
                        dst_name: dst,
                    },
                );
            }

            // sendfile(out_fd, in_fd, offset, count) - efficient file-to-socket or file-to-file transfer
            "sendfile" if ret > 0 => {
                let fd_out = args[0];
                let fd_in = args[1];
                let bytes = ret as u64;
                let out_is_socket = self
                    .processes
                    .get(&pid)
                    .is_some_and(|p| p.fd_table.is_socket(fd_out));

                self.io.file_bytes_read += bytes;
                if out_is_socket {
                    self.io.net_bytes_sent += bytes;
                    let src = self
                        .processes
                        .get(&pid)
                        .and_then(|p| p.fd_table.file_name(fd_in))
                        .unwrap_or("?")
                        .to_string();
                    self.output(&format!(
                        "{} sendfile {} from {} to net",
                        self.event_prefix(pid),
                        format_bytes(bytes),
                        src
                    ));
                    self.record_event(
                        pid,
                        EventKind::Sendfile {
                            bytes,
                            src_name: src,
                            dst_name: "net".to_string(),
                            to_network: true,
                        },
                    );
                } else {
                    self.io.file_bytes_written += bytes;
                    let src = self
                        .processes
                        .get(&pid)
                        .and_then(|p| p.fd_table.file_name(fd_in))
                        .unwrap_or("?")
                        .to_string();
                    let dst = self
                        .processes
                        .get(&pid)
                        .and_then(|p| p.fd_table.file_name(fd_out))
                        .unwrap_or("?")
                        .to_string();
                    self.output(&format!(
                        "{} sendfile {} from {} to {}",
                        self.event_prefix(pid),
                        format_bytes(bytes),
                        src,
                        dst
                    ));
                    self.record_event(
                        pid,
                        EventKind::Sendfile {
                            bytes,
                            src_name: src,
                            dst_name: dst,
                            to_network: false,
                        },
                    );
                }
            }

            _ => {}
        }
    }

    pub(crate) fn process_page_faults(&mut self, perf: &mut PerfPageFaultTracker) {
        let events = perf.read_events();
        if events.is_empty() {
            return;
        }

        // Group consecutive faults by region (identified by start address)
        struct FaultGroup {
            region_start: u64,
            region_name: String,
            region_prot: String,
            count: u64,
            first_addr: u64,
            pid: Pid,
        }

        let mut groups: Vec<FaultGroup> = Vec::new();

        for event in &events {
            let pid = Pid::from_raw(event.tid as i32);

            // Check if address is in heap (per-process) or anon mmap region
            let leader = self
                .processes
                .get(&pid)
                .map(|p| p.leader_pid)
                .unwrap_or(pid);
            let in_heap = self.processes.get(&pid).and_then(|proc| {
                let initial = proc.brk.initial_brk?;
                if event.addr >= initial && event.addr < proc.brk.current_brk {
                    Some(initial)
                } else {
                    None
                }
            });
            let region_info: Option<(String, String, u64)> = if let Some(initial) = in_heap {
                Some(("heap".to_string(), "rw-".to_string(), initial))
            } else {
                self.memory.get(&leader).and_then(|m| {
                    m.lookup_addr_full(event.addr)
                        .map(|(n, p, a)| (n.to_string(), p.to_string(), a))
                })
            };

            if let Some((region_name, region_prot, region_start)) = region_info {
                // Only track heap/anon
                if region_name != "heap" && region_name != "anon" {
                    continue;
                }

                self.page_faults += 1;

                // Check if this continues the current group
                if let Some(last) = groups.last_mut()
                    && last.region_start == region_start
                {
                    last.count += 1;
                    continue;
                }

                // Start new group
                groups.push(FaultGroup {
                    region_start,
                    region_name: region_name.to_string(),
                    region_prot: region_prot.to_string(),
                    count: 1,
                    first_addr: event.addr,
                    pid,
                });
            }
        }

        // Print grouped faults
        for group in groups {
            if group.count == 1 {
                self.output(&format!(
                    "{} fault {:012x} in {} ({})",
                    self.event_prefix(group.pid),
                    group.first_addr,
                    group.region_name,
                    group.region_prot
                ));
                self.record_event(
                    group.pid,
                    EventKind::Fault {
                        addr: format!("{:012x}", group.first_addr),
                        region_name: group.region_name,
                        prot: group.region_prot,
                    },
                );
            } else {
                self.output(&format!(
                    "{} {} faults in {} @ {:012x} ({})",
                    self.event_prefix(group.pid),
                    group.count,
                    group.region_name,
                    group.region_start,
                    group.region_prot
                ));
                self.record_event(
                    group.pid,
                    EventKind::FaultGroup {
                        count: group.count,
                        region_name: group.region_name,
                        region_start: format!("{:012x}", group.region_start),
                        prot: group.region_prot,
                    },
                );
            }
        }
    }
}

fn should_ignore_path(path: &str) -> bool {
    path.starts_with("/proc/")
        || path.starts_with("/sys/")
        || path.starts_with("/dev/")
        || path.contains("/ld.so")
        || path.contains("ld-linux")
        || path == "/etc/ld.so.cache"
        || (is_lib_dir(path) && (path.ends_with(".so") || path.contains(".so.")))
}

fn is_lib_dir(path: &str) -> bool {
    path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/lib64/")
        || path.starts_with("/nix/store/")
}

#[cfg(test)]
mod tests {
    use super::*;

    // should_ignore_path tests

    #[test]
    fn ignore_proc_sys_dev() {
        assert!(should_ignore_path("/proc/self/maps"));
        assert!(should_ignore_path("/sys/class/net"));
        assert!(should_ignore_path("/dev/null"));
    }

    #[test]
    fn ignore_ld_so_cache() {
        assert!(should_ignore_path("/etc/ld.so.cache"));
    }

    #[test]
    fn ignore_shared_libs() {
        assert!(should_ignore_path("/usr/lib/libc.so.6"));
        assert!(should_ignore_path("/lib/x86_64-linux-gnu/libm.so"));
        assert!(should_ignore_path("/nix/store/abc123/lib.so.3"));
    }

    #[test]
    fn do_not_ignore_user_files() {
        assert!(!should_ignore_path("/home/user/data.txt"));
        assert!(!should_ignore_path("/etc/hosts"));
        assert!(!should_ignore_path("/tmp/output.log"));
    }

    #[test]
    fn ignore_ld_linux() {
        assert!(should_ignore_path("/lib64/ld-linux-x86-64.so.2"));
    }

    // is_lib_dir tests

    #[test]
    fn lib_dirs_recognized() {
        assert!(is_lib_dir("/lib/something"));
        assert!(is_lib_dir("/lib64/something"));
        assert!(is_lib_dir("/usr/lib/something"));
        assert!(is_lib_dir("/usr/lib64/something"));
        assert!(is_lib_dir("/nix/store/abc/something"));
    }

    #[test]
    fn non_lib_dirs() {
        assert!(!is_lib_dir("/home/user/lib.so"));
        assert!(!is_lib_dir("/etc/config"));
        assert!(!is_lib_dir("/opt/app/lib.so"));
    }

    #[test]
    fn libfoo_not_lib_dir() {
        assert!(!is_lib_dir("/libfoo/bar"));
    }
}
