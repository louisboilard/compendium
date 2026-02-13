//! Memory syscall handlers: brk, mmap, munmap.

use nix::unistd::Pid;

use crate::Tracer;
use crate::events::EventKind;
use crate::types::*;

impl Tracer {
    /// Handle memory-related syscalls on exit.
    pub(super) fn handle_memory_syscall(&mut self, pid: Pid, sys: i64, args: &[u64; 6], ret: i64) {
        match sys {
            libc::SYS_brk => {
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

            libc::SYS_mmap if ret > 0 && ret != -1 => {
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

            libc::SYS_munmap if ret >= 0 => {
                let addr = args[0];
                let size = args[1];
                self.memory_for(pid).remove_mmap(addr, size);
            }

            _ => {}
        }
    }
}
