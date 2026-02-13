//! Page fault tracking via `perf_event_open(2)`.
//!
//! Uses the `perf-event` crate to sample `SOFTWARE/PAGE_FAULTS_MIN` events
//! from the tracee. The sampler ring buffer is polled alongside the signalfd
//! in the main event loop.

use nix::unistd::Pid;
use perf_event::events::Software;
use perf_event::{Builder, SampleFlag, Sampler};
use std::io;
use std::os::unix::io::AsRawFd;

/// A single minor page fault observed from the tracee.
pub struct PageFaultEvent {
    pub tid: u32,
    pub addr: u64,
}

/// Samples minor page faults from a traced process via perf_event.
///
/// Created once at startup when `--faults` is given. The raw fd is
/// registered with `poll(2)` so faults can be read without blocking.
pub struct PerfPageFaultTracker {
    sampler: Sampler,
}

impl PerfPageFaultTracker {
    /// Set up page fault sampling for the given pid (and all its threads).
    pub fn new(pid: Pid) -> io::Result<Self> {
        let counter = Builder::new(Software::PAGE_FAULTS_MIN)
            .observe_pid(pid.as_raw())
            .any_cpu()
            .sample_period(1) // Every fault
            .sample(SampleFlag::TID)
            .sample(SampleFlag::ADDR)
            .exclude_kernel(true)
            .exclude_hv(true)
            .wakeup_events(1)
            .build()?;

        let mut sampler = counter.sampled(8192)?; // 8KB ring buffer
        sampler.enable()?;

        Ok(Self { sampler })
    }

    /// Returns the file descriptor for use with `poll(2)`.
    pub fn raw_fd(&self) -> i32 {
        self.sampler.as_raw_fd()
    }

    /// Drain all pending page fault records from the ring buffer.
    pub fn read_events(&mut self) -> Vec<PageFaultEvent> {
        let mut events = Vec::new();

        while let Some(record) = self.sampler.next_record() {
            if let Ok(perf_event::data::Record::Sample(sample)) = record.parse_record() {
                events.push(PageFaultEvent {
                    tid: sample.tid().unwrap_or(0),
                    addr: sample.addr().unwrap_or(0),
                });
            }
        }

        events
    }
}
