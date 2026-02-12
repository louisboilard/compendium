mod fd;
mod io;
mod memory;
mod page_faults;
mod utils;

pub(crate) use utils::{is_lib_dir, should_ignore_path};

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::types::*;
use crate::{memory, syscalls, Tracer};

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
}
