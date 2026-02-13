//! Syscall handlers: dispatch and per-category processing.
//!
//! The entry point is [`Tracer::handle_syscall`], called on every ptrace
//! syscall-stop. It toggles the entry/exit state and, on exit, dispatches
//! to category-specific sub-handlers via `libc::SYS_*` constants:
//!
//! - [`fd`] — file descriptor lifecycle (open, socket, pipe, dup, close, accept, connect)
//! - [`io`] — data transfer (read, write, send, recv, sendfile, copy_file_range)
//! - [`mem`] — address space changes (brk, mmap, munmap)
//! - [`page_faults`] — perf-sampled page fault grouping

mod fd;
mod io;
mod mem;
mod page_faults;
mod utils;

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::types::*;
use crate::{Tracer, memory, syscalls};

impl Tracer {
    /// Handle a single ptrace syscall-stop (entry or exit).
    ///
    /// Ptrace reports entry and exit as separate SIGTRAP stops. We toggle
    /// `in_syscall` on each call: on entry we save the syscall number and
    /// args, on exit we dispatch to the appropriate sub-handler.
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
            if syscall_num as i64 == libc::SYS_execve
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

    /// Dispatch a completed syscall to the appropriate category handler.
    fn process_syscall_exit(&mut self, pid: Pid, syscall: u64, args: &[u64; 6], ret: i64) {
        let sys = syscall as i64;
        match sys {
            libc::SYS_openat
            | libc::SYS_open
            | libc::SYS_openat2
            | libc::SYS_socket
            | libc::SYS_pipe
            | libc::SYS_pipe2
            | libc::SYS_dup
            | libc::SYS_dup2
            | libc::SYS_dup3
            | libc::SYS_fcntl
            | libc::SYS_close
            | libc::SYS_accept
            | libc::SYS_accept4
            | libc::SYS_connect => self.handle_fd_syscall(pid, sys, args, ret),

            libc::SYS_brk | libc::SYS_mmap | libc::SYS_munmap => {
                self.handle_memory_syscall(pid, sys, args, ret)
            }

            libc::SYS_read
            | libc::SYS_pread64
            | libc::SYS_readv
            | libc::SYS_preadv
            | libc::SYS_write
            | libc::SYS_pwrite64
            | libc::SYS_writev
            | libc::SYS_pwritev
            | libc::SYS_sendto
            | libc::SYS_recvfrom
            | libc::SYS_sendmsg
            | libc::SYS_recvmsg
            | libc::SYS_copy_file_range
            | libc::SYS_sendfile => self.handle_io_syscall(pid, sys, args, ret),

            _ => {}
        }
    }
}
