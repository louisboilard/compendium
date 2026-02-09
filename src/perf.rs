use nix::unistd::Pid;
use perf_event::events::Software;
use perf_event::{Builder, SampleFlag, Sampler};
use std::io;
use std::os::unix::io::AsRawFd;

pub struct PageFaultEvent {
    #[allow(dead_code)]
    pub pid: u32,
    pub tid: u32,
    pub addr: u64,
}

pub struct PerfPageFaultTracker {
    sampler: Sampler,
}

impl PerfPageFaultTracker {
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

    pub fn raw_fd(&self) -> i32 {
        self.sampler.as_raw_fd()
    }

    pub fn read_events(&mut self) -> Vec<PageFaultEvent> {
        let mut events = Vec::new();

        while let Some(record) = self.sampler.next_record() {
            if let Ok(perf_event::data::Record::Sample(sample)) = record.parse_record() {
                events.push(PageFaultEvent {
                    pid: sample.pid().unwrap_or(0),
                    tid: sample.tid().unwrap_or(0),
                    addr: sample.addr().unwrap_or(0),
                });
            }
        }

        events
    }
}
