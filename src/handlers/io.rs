//! I/O syscall handlers: read, write, send, recv, sendfile, copy_file_range.

use nix::unistd::Pid;

use crate::events::{EventKind, IoTarget};
use crate::types::*;
use crate::Tracer;

impl Tracer {
    /// Handle a generic read or write I/O syscall on a file descriptor.
    /// `is_read` controls direction: true = read/recv, false = write/send.
    pub(super) fn handle_fd_io(&mut self, pid: Pid, fd: u64, bytes: u64, is_read: bool) {
        let Some(proc) = self.processes.get(&pid) else {
            return;
        };
        let is_sock = proc.fd_table.is_socket(fd);
        let is_file = proc.fd_table.is_file(fd);
        let file_name = proc.fd_table.file_name(fd).unwrap_or("?").to_string();

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
            if is_read {
                self.io.file_bytes_read += bytes;
                self.output(&format!(
                    "{} read {} from {}",
                    self.event_prefix(pid),
                    format_bytes(bytes),
                    file_name
                ));
                self.record_event(
                    pid,
                    EventKind::Read {
                        bytes,
                        filename: file_name,
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
                    file_name
                ));
                self.record_event(
                    pid,
                    EventKind::Write {
                        bytes,
                        filename: file_name,
                        target: IoTarget::File,
                        count: None,
                    },
                );
            }
        }
    }

    /// Handle I/O syscalls on exit, dispatching by syscall number.
    pub(super) fn handle_io_syscall(&mut self, pid: Pid, sys: i64, args: &[u64; 6], ret: i64) {
        match sys {
            libc::SYS_read | libc::SYS_pread64 | libc::SYS_readv | libc::SYS_preadv
                if ret > 0 =>
            {
                self.handle_fd_io(pid, args[0], ret as u64, true);
            }

            libc::SYS_write | libc::SYS_pwrite64 | libc::SYS_writev | libc::SYS_pwritev
                if ret > 0 =>
            {
                self.handle_fd_io(pid, args[0], ret as u64, false);
            }

            libc::SYS_sendto | libc::SYS_sendmsg if ret > 0 => {
                let bytes = ret as u64;
                self.io.net_bytes_sent += bytes;
                self.output(&format!(
                    "{} send {}",
                    self.event_prefix(pid),
                    format_bytes(bytes)
                ));
                self.record_event(pid, EventKind::Send { bytes, count: None });
            }

            libc::SYS_recvfrom | libc::SYS_recvmsg if ret > 0 => {
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
            libc::SYS_copy_file_range if ret > 0 => {
                let fd_in = args[0];
                let fd_out = args[2];
                let bytes = ret as u64;

                self.io.file_bytes_read += bytes;
                self.io.file_bytes_written += bytes;

                let proc = self.processes.get(&pid);
                let src = proc
                    .and_then(|p| p.fd_table.file_name(fd_in))
                    .unwrap_or("?")
                    .to_string();
                let dst = proc
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
            libc::SYS_sendfile if ret > 0 => {
                let fd_out = args[0];
                let fd_in = args[1];
                let bytes = ret as u64;
                let proc = self.processes.get(&pid);
                let out_is_socket = proc.is_some_and(|p| p.fd_table.is_socket(fd_out));
                let src = proc
                    .and_then(|p| p.fd_table.file_name(fd_in))
                    .unwrap_or("?")
                    .to_string();

                self.io.file_bytes_read += bytes;
                if out_is_socket {
                    self.io.net_bytes_sent += bytes;
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
                    let dst = proc
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
}
