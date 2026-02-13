use nix::unistd::Pid;

use super::utils::should_ignore_path;
use crate::events::EventKind;
use crate::types::*;
use crate::{memory, Tracer};

impl Tracer {
    pub(super) fn handle_file_open(&mut self, pid: Pid, fd: u64, path: String, writable: bool) {
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

    pub(super) fn handle_fd_syscall(&mut self, pid: Pid, sys: i64, args: &[u64; 6], ret: i64) {
        match sys {
            libc::SYS_openat if ret >= 0 => {
                let fd = ret as u64;
                if let Ok(path) = memory::read_string(pid, args[1] as usize) {
                    let flags = args[2] as i32;
                    let writable = flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0;
                    self.handle_file_open(pid, fd, path, writable);
                }
            }

            libc::SYS_open if ret >= 0 => {
                let fd = ret as u64;
                if let Ok(path) = memory::read_string(pid, args[0] as usize) {
                    let flags = args[1] as i32;
                    let writable = flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0;
                    self.handle_file_open(pid, fd, path, writable);
                }
            }

            libc::SYS_openat2 if ret >= 0 => {
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

            libc::SYS_socket if ret >= 0 => {
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

            libc::SYS_pipe | libc::SYS_pipe2 if ret >= 0 => {
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

            libc::SYS_dup if ret >= 0 => {
                let old_fd = args[0];
                let new_fd = ret as u64;
                if let Some(proc) = self.processes.get_mut(&pid) {
                    proc.fd_table.dup(old_fd, new_fd);
                }
            }

            libc::SYS_dup2 | libc::SYS_dup3 if ret >= 0 => {
                let old_fd = args[0];
                let new_fd = args[1];
                if let Some(proc) = self.processes.get_mut(&pid) {
                    proc.fd_table.dup(old_fd, new_fd);
                }
            }

            libc::SYS_fcntl if ret >= 0 => {
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

            libc::SYS_close if ret >= 0 => {
                let fd = args[0];
                if let Some(proc) = self.processes.get_mut(&pid) {
                    proc.fd_table.remove(fd);
                }
            }

            libc::SYS_accept | libc::SYS_accept4 if ret >= 0 => {
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

            libc::SYS_connect if ret >= 0 || ret == -(libc::EINPROGRESS as i64) => {
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
}
