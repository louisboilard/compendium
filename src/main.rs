use anyhow::{Context, Result};
use clap::Parser;
use nix::sys::ptrace;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::time::Instant;

mod events;
mod handlers;
mod memory;
mod perf;
mod ptrace_ops;
mod report;
mod summary;
mod syscalls;
mod types;

use events::{EventKind, TraceEvent};
use perf::PerfPageFaultTracker;
use types::{Config, FdTable, IoStats, MemoryStats, PerfState, ProcessBrk, ProcessState, Summary};

#[derive(Parser, Debug)]
#[command(name = "compendium")]
#[command(about = "A user-friendly strace for x86 Linux with HTML reports")]
struct Args {
    /// Command to run
    #[arg(required_unless_present = "pid")]
    command: Option<String>,

    /// Arguments to pass to the command
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,

    /// Attach to existing PID instead of spawning
    #[arg(short, long)]
    pid: Option<i32>,

    /// Show raw syscalls as they happen (verbose mode)
    #[arg(short, long)]
    verbose: bool,

    /// Track page faults in heap/anon regions (requires sudo + perf permissions)
    #[arg(long = "faults", visible_alias = "page-faults")]
    faults: bool,

    /// Also write output to file (in addition to stderr)
    #[arg(short, long)]
    output: Option<String>,

    /// Generate an HTML timeline report (defaults to report.html)
    #[arg(long, default_missing_value = "report.html", num_args = 0..=1)]
    report: Option<String>,

    /// Maximum events in the HTML report (coalesced I/O counted as one)
    #[arg(long, default_value = "75000")]
    max_report_events: usize,
}

// ============================================================================
// Tracer
// ============================================================================

pub(crate) struct Tracer {
    pub(crate) config: Config,
    pub(crate) processes: HashMap<Pid, ProcessState>,
    pub(crate) memory: HashMap<Pid, MemoryStats>,
    pub(crate) io: IoStats,
    pub(crate) summary: Summary,
    pub(crate) initial_pid: Option<Pid>,
    pub(crate) start_time: Instant,
    pub(crate) perf: PerfState,
    pub(crate) output_file: Option<File>,
    pub(crate) events: Vec<TraceEvent>,
    pub(crate) total_heap_bytes: u64,
    pub(crate) interrupt_count: u8,
}

impl Tracer {
    fn new(
        verbose: bool,
        cmd_display: String,
        output_path: Option<&str>,
        report_path: Option<String>,
        max_report_events: usize,
    ) -> Result<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let output_file = match output_path {
            Some(path) => Some(File::create(path).context("Failed to create output file")?),
            None => None,
        };
        Ok(Tracer {
            config: Config {
                verbose,
                max_report_events,
                report_path,
                cmd_display,
            },
            processes: HashMap::new(),
            memory: HashMap::new(),
            io: IoStats::default(),
            summary: Summary::default(),
            initial_pid: None,
            start_time: Instant::now(),
            perf: PerfState {
                enabled: false,
                page_faults: 0,
                page_size,
            },
            output_file,
            events: Vec::new(),
            total_heap_bytes: 0,
            interrupt_count: 0,
        })
    }

    pub(crate) fn record_event(&mut self, pid: Pid, kind: EventKind) {
        self.events.push(TraceEvent {
            timestamp_secs: self.start_time.elapsed().as_secs_f64(),
            pid: pid.as_raw(),
            kind,
        });
    }

    /// Output a line to stderr and optionally to the output file
    pub(crate) fn output(&mut self, msg: &str) {
        eprintln!("{}", msg);
        if let Some(ref mut f) = self.output_file {
            let _ = writeln!(f, "{}", msg);
        }
    }

    /// Format the event prefix: "[+0.001s]" or "[+0.001s] [1234]" if multiple tasks
    pub(crate) fn event_prefix(&self, pid: Pid) -> String {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if self.processes.len() > 1 {
            format!("[+{:.3}s] [{}]", elapsed, pid)
        } else {
            format!("[+{:.3}s]", elapsed)
        }
    }

    pub(crate) fn add_process(&mut self, pid: Pid) {
        self.processes.insert(
            pid,
            ProcessState {
                in_syscall: false,
                last_syscall: None,
                last_syscall_args: [0; 6],
                fd_table: FdTable::default(),
                brk: ProcessBrk::default(),
                leader_pid: pid,
            },
        );
    }

    /// Get the MemoryStats for the address space that `pid` belongs to
    pub(crate) fn memory_for(&mut self, pid: Pid) -> &mut MemoryStats {
        let leader = self
            .processes
            .get(&pid)
            .map(|p| p.leader_pid)
            .unwrap_or(pid);
        self.memory.entry(leader).or_default()
    }

    fn run(&mut self, initial_pid: Pid, track_faults: bool, attached: bool) -> Result<()> {
        self.initial_pid = Some(initial_pid);
        self.start_time = Instant::now();
        self.add_process(initial_pid);

        // Print initial program start separator (only when spawning, not attaching)
        if !attached {
            let comm = std::fs::read_to_string(format!("/proc/{}/comm", initial_pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            self.output(&format!(
                "{} ─── {} exec ───",
                self.event_prefix(initial_pid),
                comm
            ));
            self.record_event(initial_pid, EventKind::Exec { program: comm });
        }

        // Set up page fault tracking if requested
        let mut perf_tracker = if track_faults {
            match PerfPageFaultTracker::new(initial_pid) {
                Ok(tracker) => {
                    self.perf.enabled = true;
                    Some(tracker)
                }
                Err(e) => {
                    eprintln!(
                        "Note: Page fault tracking failed ({}). To enable, run with sudo and:",
                        e
                    );
                    eprintln!("      echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid");
                    None
                }
            }
        } else {
            None
        };

        // Set up signalfd for SIGCHLD to use poll() for proper event ordering
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGCHLD);
        mask.add(Signal::SIGINT);
        mask.thread_block().context("Failed to block signals")?;
        let signal_fd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)
            .context("Failed to create signalfd")?;

        let options = ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEEXEC;
        ptrace::setoptions(initial_pid, options)?;
        ptrace::syscall(initial_pid, None)?;

        loop {
            // Build poll fds
            let mut poll_fds = vec![libc::pollfd {
                fd: signal_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];

            if let Some(ref perf) = perf_tracker {
                poll_fds.push(libc::pollfd {
                    fd: perf.raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }

            // Wait for either SIGCHLD (tracee event) or perf event
            let ret =
                unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, -1) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err).context("poll failed");
            }

            // Check for page fault events first (they may have happened before the syscall)
            if poll_fds.len() > 1
                && poll_fds[1].revents & libc::POLLIN != 0
                && let Some(ref mut perf) = perf_tracker
            {
                self.process_page_faults(perf);
            }

            // Check for tracee events
            if poll_fds[0].revents & libc::POLLIN != 0 {
                // Drain all pending signals from signalfd
                let mut got_sigchld = false;
                while let Ok(Some(sig)) = signal_fd.read_signal() {
                    if sig.ssi_signo == libc::SIGINT as u32 {
                        self.interrupt_count += 1;
                        if attached {
                            self.detach_all();
                            return Ok(());
                        } else if self.interrupt_count == 1 {
                            self.output(
                                "\ncompendium: interrupted, waiting for process to exit \
                                 (Ctrl-C again to force kill)...",
                            );
                        } else {
                            self.force_kill_all();
                            return Ok(());
                        }
                    } else {
                        got_sigchld = true;
                    }
                }
                if !got_sigchld {
                    continue; // Only got SIGINT, no waitpid events yet
                }

                // Process all available wait statuses
                loop {
                    match waitpid(None, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::StillAlive) => break,
                        Ok(WaitStatus::Stopped(pid, sig)) => {
                            self.handle_ptrace_stop(pid, sig, options)?;
                        }
                        Ok(WaitStatus::PtraceEvent(pid, _, event)) => {
                            self.handle_ptrace_event(pid, event);
                        }
                        Ok(WaitStatus::Exited(pid, code)) => {
                            if self.handle_process_exit(pid, Some(code), None) {
                                return Ok(());
                            }
                        }
                        Ok(WaitStatus::Signaled(pid, sig, _)) => {
                            if self.handle_process_exit(pid, None, Some(sig)) {
                                return Ok(());
                            }
                        }
                        Ok(_) => {}
                        Err(nix::errno::Errno::ECHILD) => {
                            for proc in self.processes.values() {
                                self.total_heap_bytes += proc.brk.heap_size();
                            }
                            self.processes.clear();
                            return Ok(());
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (pid, cmd_display, attached) = if let Some(attach_pid) = args.pid {
        eprintln!("compendium: attaching to PID {}...", attach_pid);
        let pid = ptrace_ops::attach_to_pid(attach_pid)?;
        (pid, format!("pid {}", attach_pid), true)
    } else if let Some(ref command) = args.command {
        let full_cmd = if args.args.is_empty() {
            command.clone()
        } else {
            format!("{} {}", command, args.args.join(" "))
        };
        eprintln!("compendium: tracing {}", full_cmd);
        let pid = ptrace_ops::spawn_traced(command, &args.args)?;
        (pid, full_cmd, false)
    } else {
        anyhow::bail!("Must provide either a command or --pid");
    };

    let mut tracer = Tracer::new(
        args.verbose,
        cmd_display,
        args.output.as_deref(),
        args.report,
        args.max_report_events,
    )?;
    tracer.run(pid, args.faults, attached)?;

    // Unblock SIGINT so Ctrl-C works normally during summary/report generation
    let mut unblock = SigSet::empty();
    unblock.add(Signal::SIGINT);
    let _ = unblock.thread_unblock();

    summary::print_final_summary(&mut tracer);

    Ok(())
}
