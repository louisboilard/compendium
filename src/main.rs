//! Compendium: a user-friendly strace for x86 Linux with HTML reports.
//!
//! Traces syscalls via ptrace and optionally tracks page faults via perf_event.
//! Produces a human-readable summary on stderr and, when `--report` is given,
//! a self-contained HTML timeline.

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

mod ebpf;
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
use types::{
    Config, EbpfStats, FdTable, IoStats, MemoryStats, PendingBlockIoGroup, PerfState, ProcessBrk,
    ProcessState, Summary, format_bytes, format_ns,
};

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

    /// Track scheduler latency and block I/O latency via eBPF (requires CAP_BPF or root)
    #[arg(long = "ebpf")]
    ebpf: bool,

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

/// Central tracing state machine.
///
/// Holds per-process state, aggregated I/O and memory stats, the event log
/// (when `--report` is enabled), and the output sink. Methods on `Tracer` are
/// spread across `handlers/`, `ptrace_ops`, and `summary`.
pub(crate) struct Tracer {
    pub(crate) config: Config,
    pub(crate) processes: HashMap<Pid, ProcessState>,
    pub(crate) memory: HashMap<Pid, MemoryStats>,
    pub(crate) io: IoStats,
    pub(crate) summary: Summary,
    pub(crate) initial_pid: Option<Pid>,
    pub(crate) start_time: Instant,
    pub(crate) perf: PerfState,
    pub(crate) ebpf_tracker: Option<ebpf::EbpfTracker>,
    pub(crate) ebpf_stats: EbpfStats,
    pub(crate) pending_block_io: Option<PendingBlockIoGroup>,
    pub(crate) ktime_base_ns: u64,
    pub(crate) output_file: Option<File>,
    pub(crate) events: Vec<TraceEvent>,
    pub(crate) event_count: usize,
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
            ebpf_tracker: None,
            ebpf_stats: EbpfStats::default(),
            pending_block_io: None,
            ktime_base_ns: 0,
            output_file,
            events: Vec::new(),
            event_count: 0,
            total_heap_bytes: 0,
            interrupt_count: 0,
        })
    }

    /// Record a trace event for the HTML report.
    ///
    /// Always increments the total event counter. The event is only stored
    /// when `--report` is active and the buffer has not yet reached
    /// `max_report_events`, preventing unbounded memory growth.
    pub(crate) fn record_event(&mut self, pid: Pid, kind: EventKind) {
        self.event_count += 1;
        if self.config.report_path.is_some() && self.events.len() < self.config.max_report_events {
            self.events.push(TraceEvent {
                timestamp_secs: self.start_time.elapsed().as_secs_f64(),
                pid: pid.as_raw(),
                kind,
            });
        }
    }

    /// Output a line to stderr and optionally to the output file
    pub(crate) fn output(&mut self, msg: &str) {
        eprintln!("{}", msg);
        if let Some(ref mut f) = self.output_file {
            let _ = writeln!(f, "{}", msg);
        }
    }

    /// Format the event prefix using the current wall-clock time.
    ///
    /// Used for ptrace and perf events where we observe the event at the
    /// moment it happens. For eBPF events (which carry kernel timestamps),
    /// use [`event_prefix_at`](Self::event_prefix_at) instead.
    pub(crate) fn event_prefix(&self, pid: Pid) -> String {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if self.processes.len() > 1 {
            format!("[+{:.3}s] [{}]", elapsed, pid)
        } else {
            format!("[+{:.3}s]", elapsed)
        }
    }

    /// Convert a kernel `bpf_ktime_get_ns()` timestamp to tracer-relative seconds.
    ///
    /// Both `bpf_ktime_get_ns()` and Rust's `Instant` use `CLOCK_MONOTONIC`,
    /// so subtracting the base sampled at tracer start gives the correct offset.
    pub(crate) fn ktime_to_secs(&self, ktime_ns: u64) -> f64 {
        ktime_ns.saturating_sub(self.ktime_base_ns) as f64 / 1_000_000_000.0
    }

    /// Format event prefix using a kernel-provided timestamp.
    ///
    /// Used for eBPF events where the actual event time is known from
    /// `bpf_ktime_get_ns()`, which may differ from when userspace drains it.
    pub(crate) fn event_prefix_at(&self, pid: Pid, timestamp_secs: f64) -> String {
        if self.processes.len() > 1 {
            format!("[+{:.3}s] [{}]", timestamp_secs, pid)
        } else {
            format!("[+{:.3}s]", timestamp_secs)
        }
    }

    /// Record a trace event with a kernel-provided timestamp.
    ///
    /// Used for eBPF events. For ptrace/perf events observed in real time,
    /// use [`record_event`](Self::record_event) instead.
    pub(crate) fn record_event_at(&mut self, pid: Pid, kind: EventKind, timestamp_secs: f64) {
        self.event_count += 1;
        if self.config.report_path.is_some() && self.events.len() < self.config.max_report_events {
            self.events.push(TraceEvent {
                timestamp_secs,
                pid: pid.as_raw(),
                kind,
            });
        }
    }

    /// Flush any pending block I/O group accumulated across poll iterations.
    ///
    /// Called before ptrace event processing so grouped eBPF output appears
    /// before the next ptrace event, and at the end of tracing.
    pub(crate) fn flush_block_io_group(&mut self) {
        if let Some(g) = self.pending_block_io.take() {
            if g.count == 1 {
                self.output(&format!(
                    "{} block I/O {} ({})",
                    self.event_prefix_at(g.pid, g.first_ts),
                    format_ns(g.total_latency_ns),
                    format_bytes(g.bytes_per_op),
                ));
                self.record_event_at(
                    g.pid,
                    EventKind::BlockIo {
                        latency_ns: g.total_latency_ns,
                        bytes: g.bytes_per_op,
                    },
                    g.first_ts,
                );
            } else {
                let avg_ns = g.total_latency_ns / g.count;
                self.output(&format!(
                    "{} block I/O {} avg, {} max ({} x{}, {} total)",
                    self.event_prefix_at(g.pid, g.first_ts),
                    format_ns(avg_ns),
                    format_ns(g.max_latency_ns),
                    format_bytes(g.bytes_per_op),
                    g.count,
                    format_bytes(g.bytes_per_op.saturating_mul(g.count)),
                ));
                self.record_event_at(
                    g.pid,
                    EventKind::BlockIoGroup {
                        count: g.count,
                        bytes_per_op: g.bytes_per_op,
                        total_bytes: g.bytes_per_op.saturating_mul(g.count),
                        avg_latency_ns: avg_ns,
                        max_latency_ns: g.max_latency_ns,
                    },
                    g.first_ts,
                );
            }
        }
    }

    /// Register a new process/thread for tracking.
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

    fn run(
        &mut self,
        initial_pid: Pid,
        track_faults: bool,
        track_ebpf: bool,
        attached: bool,
    ) -> Result<()> {
        self.initial_pid = Some(initial_pid);
        self.start_time = Instant::now();
        // Sample CLOCK_MONOTONIC (same clock as bpf_ktime_get_ns) alongside
        // start_time so we can convert kernel timestamps to tracer-relative seconds.
        self.ktime_base_ns = {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            assert!(
                ret == 0,
                "clock_gettime(CLOCK_MONOTONIC) failed: {}",
                std::io::Error::last_os_error()
            );
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        };
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

        // Set up eBPF tracing if requested
        if track_ebpf {
            match ebpf::EbpfTracker::new(initial_pid.as_raw() as u32) {
                Ok(tracker) => {
                    eprintln!("compendium: eBPF tracing enabled (sched latency + block I/O)");
                    self.ebpf_tracker = Some(tracker);
                    self.ebpf_stats.enabled = true;
                }
                Err(e) => {
                    eprintln!(
                        "Note: eBPF tracing failed ({}). Run with sudo or grant CAP_BPF+CAP_PERFMON.",
                        e
                    );
                }
            }
        }

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

        'poll: loop {
            // Build poll fds — track indices so we check the right revents
            let mut poll_fds = vec![libc::pollfd {
                fd: signal_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];

            let perf_poll_idx = if let Some(ref perf) = perf_tracker {
                let idx = poll_fds.len();
                poll_fds.push(libc::pollfd {
                    fd: perf.raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
                Some(idx)
            } else {
                None
            };

            let ebpf_poll_idx = if let Some(ref tracker) = self.ebpf_tracker {
                let idx = poll_fds.len();
                poll_fds.push(libc::pollfd {
                    fd: tracker.poll_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
                Some(idx)
            } else {
                None
            };

            // Wait for either SIGCHLD (tracee event), perf event, or eBPF event
            let ret =
                unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, -1) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err).context("poll failed");
            }

            // Drain eBPF ring buffer first — these events carry kernel timestamps
            // (bpf_ktime_get_ns) that are always earlier than the current wall-clock
            // time used by perf and ptrace events below, so printing them first
            // preserves chronological order within each poll iteration.
            //
            // Note: eBPF events that fire *during* ptrace processing accumulate in
            // the ring buffer and are only drained in the next iteration, so they
            // may print after ptrace events that are chronologically later. The
            // timestamps on each line are still accurate; only the line ordering
            // can be slightly off in that cross-iteration case. The HTML report
            // (--report) is not affected — events are sorted by timestamp before
            // the report is generated.
            if let Some(idx) = ebpf_poll_idx {
                if poll_fds[idx].revents & libc::POLLIN != 0 {
                    let events = self.ebpf_tracker.as_ref().unwrap().consume_and_drain();
                    if !events.is_empty() {
                        self.process_ebpf_events(&events);
                    }
                }
                if poll_fds[idx].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                    eprintln!(
                        "compendium: warning: eBPF ring buffer fd error/hangup, disabling eBPF"
                    );
                    // Final drain before disabling — take tracker to avoid borrow conflict
                    if let Some(tracker) = self.ebpf_tracker.take() {
                        let events = tracker.consume_and_drain();
                        let dropped = tracker.dropped_count();
                        if !events.is_empty() {
                            self.process_ebpf_events(&events);
                        }
                        self.ebpf_stats.dropped_events = dropped;
                    }
                    self.flush_block_io_group();
                    // ebpf_tracker is already None from take()
                }
            }

            // Page fault events (perf_event fd)
            if let Some(idx) = perf_poll_idx
                && poll_fds[idx].revents & libc::POLLIN != 0
                && let Some(ref mut perf) = perf_tracker
            {
                self.process_page_faults(perf);
            }

            // Check for tracee events
            if poll_fds[0].revents & libc::POLLIN != 0 {
                // Flush any accumulated block I/O group before ptrace output
                self.flush_block_io_group();
                // Drain all pending signals from signalfd
                let mut got_sigchld = false;
                while let Ok(Some(sig)) = signal_fd.read_signal() {
                    if sig.ssi_signo == libc::SIGINT as u32 {
                        self.interrupt_count += 1;
                        if attached {
                            self.detach_all();
                            break 'poll;
                        } else if self.interrupt_count == 1 {
                            self.output(
                                "\ncompendium: interrupted, waiting for process to exit \
                                 (Ctrl-C again to force kill)...",
                            );
                        } else {
                            self.force_kill_all();
                            break 'poll;
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
                                break 'poll;
                            }
                        }
                        Ok(WaitStatus::Signaled(pid, sig, _)) => {
                            if self.handle_process_exit(pid, None, Some(sig)) {
                                break 'poll;
                            }
                        }
                        Ok(_) => {}
                        Err(nix::errno::Errno::ECHILD) => {
                            for proc in self.processes.values() {
                                self.total_heap_bytes += proc.brk.heap_size();
                            }
                            self.processes.clear();
                            break 'poll;
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        // Final drain of eBPF ring buffer — events may have accumulated
        // between the last poll iteration and process exit.
        // Take the tracker temporarily to avoid borrow conflict with process_ebpf_events.
        if let Some(tracker) = self.ebpf_tracker.take() {
            let events = tracker.consume_and_drain();
            let dropped = tracker.dropped_count();
            if !events.is_empty() {
                self.process_ebpf_events(&events);
            }
            self.ebpf_stats.dropped_events = dropped;
            self.ebpf_tracker = Some(tracker);
        }
        self.flush_block_io_group();

        Ok(())
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
    tracer.run(pid, args.faults, args.ebpf, attached)?;

    // Unblock SIGINT so Ctrl-C works normally during summary/report generation
    let mut unblock = SigSet::empty();
    unblock.add(Signal::SIGINT);
    let _ = unblock.thread_unblock();

    summary::print_final_summary(&mut tracer);

    Ok(())
}
