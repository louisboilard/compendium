//! Ptrace lifecycle management: spawning, attaching, stop/event/exit handling.
//!
//! Contains the [`spawn_traced`] and [`attach_to_pid`] entry points plus
//! the `Tracer` methods that respond to waitpid statuses (ptrace-stops,
//! fork/clone/exec events, and process exits).

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork};
use std::ffi::CString;

use crate::Tracer;
use crate::events::EventKind;
use crate::types::*;

impl Tracer {
    /// Detach from all traced processes (used on Ctrl-C when attached).
    pub(crate) fn detach_all(&mut self) {
        self.output("\ncompendium: detaching from process...");
        let pids: Vec<Pid> = self.processes.keys().cloned().collect();
        for pid in pids {
            if let Some(proc) = self.processes.get(&pid) {
                self.total_heap_bytes += proc.brk.heap_size();
            }
            // If process isn't in ptrace-stop, interrupt it first
            if ptrace::detach(pid, None).is_err() {
                let _ = kill(pid, Signal::SIGSTOP);
                let _ = waitpid(pid, Some(WaitPidFlag::__WALL));
                let _ = ptrace::detach(pid, None);
            }
        }
        self.processes.clear();
    }

    /// Send SIGKILL to all traced processes and reap them (double Ctrl-C).
    pub(crate) fn force_kill_all(&mut self) {
        self.output("\ncompendium: force killing all processes...");
        for proc in self.processes.values() {
            self.total_heap_bytes += proc.brk.heap_size();
        }
        // ptrace::detach with SIGKILL resumes the stopped process with
        // an uncatchable signal — it dies immediately
        for &pid in self.processes.keys() {
            if ptrace::detach(pid, Signal::SIGKILL).is_err() {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = ptrace::detach(pid, None);
            }
        }
        // Reap all children
        loop {
            match waitpid(None, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, code)) if Some(pid) == self.initial_pid => {
                    self.summary.exit_code = Some(code);
                }
                Ok(WaitStatus::Signaled(pid, sig, _)) if Some(pid) == self.initial_pid => {
                    self.summary.exit_signal = Some(sig);
                }
                Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        if self.summary.exit_code.is_none() && self.summary.exit_signal.is_none() {
            self.summary.exit_signal = Some(Signal::SIGKILL);
        }
        self.processes.clear();
    }

    /// Handle a ptrace-stop event (Stopped status from waitpid).
    /// Returns Ok(true) if the signal was forwarded and resume already happened,
    /// Ok(false) if the caller should resume with ptrace::syscall(pid, None).
    pub(crate) fn handle_ptrace_stop(
        &mut self,
        pid: Pid,
        sig: Signal,
        options: ptrace::Options,
    ) -> Result<bool> {
        if !self.processes.contains_key(&pid) {
            self.add_process(pid);
            let _ = ptrace::setoptions(pid, options);
        }

        match sig {
            Signal::SIGTRAP => {
                if let Err(e) = self.handle_syscall(pid) {
                    if self.interrupt_count > 0 {
                        self.processes.remove(&pid);
                        return Ok(true); // Already handled, skip resume
                    }
                    return Err(e);
                }
            }
            Signal::SIGSTOP => {}
            _ => {
                // Forward the signal to the tracee
                if ptrace::syscall(pid, Some(sig)).is_err() && self.interrupt_count > 0 {
                    self.processes.remove(&pid);
                }
                return Ok(true); // Already resumed with signal forwarding
            }
        }

        // Resume the process (SIGTRAP or SIGSTOP cases)
        if ptrace::syscall(pid, None).is_err() && self.interrupt_count > 0 {
            self.processes.remove(&pid);
        }
        Ok(true)
    }

    /// Handle a PTRACE_EVENT (fork/vfork/clone/exec).
    pub(crate) fn handle_ptrace_event(&mut self, pid: Pid, event: i32) {
        if event == (ptrace::Event::PTRACE_EVENT_FORK as i32)
            || event == (ptrace::Event::PTRACE_EVENT_VFORK as i32)
        {
            if let Ok(new_pid) = ptrace::getevent(pid) {
                let new_pid = Pid::from_raw(new_pid as i32);
                self.add_process(new_pid);
                if let Some(ref ebpf) = self.ebpf_tracker {
                    ebpf.add_pid(new_pid.as_raw() as u32);
                }
                self.output(&format!(
                    "{} spawn process {}",
                    self.event_prefix(pid),
                    new_pid
                ));
                self.record_event(
                    pid,
                    EventKind::SpawnProcess {
                        child_pid: new_pid.as_raw(),
                    },
                );
            }
        } else if event == (ptrace::Event::PTRACE_EVENT_CLONE as i32) {
            if let Ok(new_tid) = ptrace::getevent(pid) {
                let new_tid = Pid::from_raw(new_tid as i32);
                // Clone shares address space with parent
                let parent_leader = self
                    .processes
                    .get(&pid)
                    .map(|p| p.leader_pid)
                    .unwrap_or(pid);
                self.add_process(new_tid);
                if let Some(ref ebpf) = self.ebpf_tracker {
                    ebpf.add_pid(new_tid.as_raw() as u32);
                }
                if let Some(proc) = self.processes.get_mut(&new_tid) {
                    proc.leader_pid = parent_leader;
                }
                self.output(&format!(
                    "{} spawn thread {}",
                    self.event_prefix(pid),
                    new_tid
                ));
                self.record_event(
                    pid,
                    EventKind::SpawnThread {
                        child_tid: new_tid.as_raw(),
                    },
                );
            }
        } else if event == (ptrace::Event::PTRACE_EVENT_EXEC as i32) {
            // Program image replaced - the actual program is now starting
            // Reset brk, fd_table, and mmap regions since address space is
            // completely new and CLOEXEC fds are closed by the kernel
            let leader = self
                .processes
                .get(&pid)
                .map(|p| p.leader_pid)
                .unwrap_or(pid);
            if let Some(mem) = self.memory.get_mut(&leader) {
                *mem = MemoryStats::default();
            }
            if let Some(proc) = self.processes.get_mut(&pid) {
                proc.brk.reset();
                proc.fd_table = FdTable::default();
            }
            let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            self.output(&format!("{} ─── {} exec ───", self.event_prefix(pid), comm));
            self.record_event(pid, EventKind::Exec { program: comm });
        }
        if ptrace::syscall(pid, None).is_err() && self.interrupt_count > 0 {
            self.processes.remove(&pid);
        }
    }

    /// Handle process exit or signal death. Returns true if tracing should stop.
    pub(crate) fn handle_process_exit(
        &mut self,
        pid: Pid,
        exit_code: Option<i32>,
        exit_signal: Option<Signal>,
    ) -> bool {
        if Some(pid) == self.initial_pid {
            if let Some(code) = exit_code {
                self.summary.exit_code = Some(code);
            }
            if let Some(sig) = exit_signal {
                self.summary.exit_signal = Some(sig);
            }
        } else {
            // Thread/child process exited
            let (code_opt, signal_opt) = match (exit_code, exit_signal) {
                (Some(code), _) => (Some(code), None),
                (_, Some(sig)) => (None, Some(format!("{:?}", sig))),
                _ => (None, None),
            };
            let description = if let Some(code) = exit_code {
                format!("code {}", code)
            } else if let Some(sig) = exit_signal {
                format!("signal {:?}", sig)
            } else {
                "unknown".to_string()
            };
            self.output(&format!(
                "{} exit thread {} ({})",
                self.event_prefix(pid),
                pid,
                description
            ));
            self.record_event(
                pid,
                EventKind::ExitThread {
                    exit_pid: pid.as_raw(),
                    code: code_opt,
                    signal: signal_opt,
                },
            );
        }
        if let Some(ref ebpf) = self.ebpf_tracker {
            ebpf.remove_pid(pid.as_raw() as u32);
        }
        if let Some(proc) = self.processes.get(&pid) {
            self.total_heap_bytes += proc.brk.heap_size();
        }
        self.processes.remove(&pid);
        self.processes.is_empty()
    }
}

/// Fork and exec a command under ptrace.
///
/// The child calls `PTRACE_TRACEME` then `execvp`. The parent waits for
/// the initial stop and returns the child's pid.
pub(crate) fn spawn_traced(command: &str, args: &[String]) -> Result<Pid> {
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            waitpid(child, None)?;
            Ok(child)
        }
        ForkResult::Child => {
            ptrace::traceme().expect("ptrace(TRACEME) failed");
            let cmd = CString::new(command).unwrap();
            let mut argv: Vec<CString> = vec![cmd.clone()];
            argv.extend(args.iter().map(|a| CString::new(a.as_str()).unwrap()));
            // execvp returns Result<Infallible, Errno> — on success the process
            // image is replaced and this code never continues. The empty match on
            // the uninhabited Ok(Infallible) proves to the compiler that the
            // success path can never reach here, satisfying the Result<Pid> return type.
            match execvp(&cmd, &argv) {
                Ok(void) => match void {},
                Err(e) => panic!("execvp failed: {e}"),
            }
        }
    }
}

/// Attach to an already-running process via `PTRACE_ATTACH`.
///
/// Gives a clear error message when `EPERM` is returned (common due to
/// `ptrace_scope` restrictions).
pub(crate) fn attach_to_pid(pid: i32) -> Result<Pid> {
    let pid = Pid::from_raw(pid);
    if let Err(e) = ptrace::attach(pid) {
        if e == nix::errno::Errno::EPERM {
            anyhow::bail!(
                "Permission denied attaching to PID {}.\n\n\
                This is likely due to kernel ptrace security settings.\n\
                Try one of:\n  \
                  1. Run as root: sudo compendium --pid {}\n  \
                  2. Relax ptrace_scope: sudo sysctl kernel.yama.ptrace_scope=0\n\n\
                Current ptrace_scope can be checked with:\n  \
                  cat /proc/sys/kernel/yama/ptrace_scope\n  \
                  (0=permissive, 1=restricted to parent, 2=admin-only, 3=disabled)",
                pid,
                pid
            );
        }
        return Err(e).context("Failed to attach to process");
    }
    waitpid(pid, None)?;
    Ok(pid)
}
