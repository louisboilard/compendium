//! eBPF event processing: scheduler delays and block I/O latency.

use nix::unistd::Pid;

use crate::Tracer;
use crate::ebpf::EbpfEvent;
use crate::events::EventKind;
use crate::types::{PendingBlockIoGroup, format_bytes, format_ns};

impl Tracer {
    /// Process parsed eBPF events: update stats, print, and record for reports.
    ///
    /// In non-verbose mode, consecutive block I/O events from the same PID
    /// with the same per-op byte size are accumulated into
    /// [`pending_block_io`](Self::pending_block_io). The group is flushed by
    /// [`flush_block_io_group`](Self::flush_block_io_group) before ptrace
    /// events are processed, or when the byte size / PID changes.
    pub(crate) fn process_ebpf_events(&mut self, events: &[EbpfEvent]) {
        for event in events {
            match event {
                EbpfEvent::SchedDelay(evt) => {
                    self.flush_block_io_group();

                    let pid = Pid::from_raw(evt.pid as i32);
                    let ts = self.ktime_to_secs(evt.timestamp_ns);

                    self.ebpf_stats.sched_delays += 1;
                    self.ebpf_stats.total_sched_delay_ns += evt.delay_ns;
                    if evt.delay_ns > self.ebpf_stats.max_sched_delay_ns {
                        self.ebpf_stats.max_sched_delay_ns = evt.delay_ns;
                    }

                    if evt.delay_ns >= 100_000 {
                        self.output(&format!(
                            "{} sched delay {}",
                            self.event_prefix_at(pid, ts),
                            format_ns(evt.delay_ns),
                        ));
                    }

                    self.record_event_at(
                        pid,
                        EventKind::SchedDelay {
                            delay_ns: evt.delay_ns,
                        },
                        ts,
                    );
                }
                EbpfEvent::BlockIo(evt) => {
                    let pid = Pid::from_raw(evt.pid as i32);
                    let ts = self.ktime_to_secs(evt.timestamp_ns);

                    self.ebpf_stats.block_io_ops += 1;
                    self.ebpf_stats.total_block_io_ns += evt.latency_ns;
                    if evt.latency_ns > self.ebpf_stats.max_block_io_ns {
                        self.ebpf_stats.max_block_io_ns = evt.latency_ns;
                    }

                    if self.config.verbose {
                        self.output(&format!(
                            "{} block I/O {} ({})",
                            self.event_prefix_at(pid, ts),
                            format_ns(evt.latency_ns),
                            format_bytes(evt.bytes),
                        ));
                        self.record_event_at(
                            pid,
                            EventKind::BlockIo {
                                latency_ns: evt.latency_ns,
                                bytes: evt.bytes,
                            },
                            ts,
                        );
                    } else {
                        // Accumulate into persistent group across poll iterations
                        let matches = matches!(
                            &self.pending_block_io,
                            Some(g) if g.pid == pid && g.bytes_per_op == evt.bytes
                        );
                        if matches {
                            let g = self.pending_block_io.as_mut().unwrap();
                            g.count += 1;
                            g.total_latency_ns += evt.latency_ns;
                            if evt.latency_ns > g.max_latency_ns {
                                g.max_latency_ns = evt.latency_ns;
                            }
                        } else {
                            self.flush_block_io_group();
                            self.pending_block_io = Some(PendingBlockIoGroup {
                                pid,
                                first_ts: ts,
                                count: 1,
                                total_latency_ns: evt.latency_ns,
                                max_latency_ns: evt.latency_ns,
                                bytes_per_op: evt.bytes,
                            });
                        }
                    }
                }
            }
        }
    }
}
