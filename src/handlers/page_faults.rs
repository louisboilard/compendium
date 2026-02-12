use nix::unistd::Pid;

use crate::events::EventKind;
use crate::perf::PerfPageFaultTracker;
use crate::Tracer;

impl Tracer {
    pub(crate) fn process_page_faults(&mut self, perf: &mut PerfPageFaultTracker) {
        let events = perf.read_events();
        if events.is_empty() {
            return;
        }

        // Group consecutive faults by region (identified by start address)
        struct FaultGroup {
            region_start: u64,
            region_name: String,
            region_prot: String,
            count: u64,
            first_addr: u64,
            pid: Pid,
        }

        let mut groups: Vec<FaultGroup> = Vec::new();

        for event in &events {
            let pid = Pid::from_raw(event.tid as i32);

            // Check if address is in heap (per-process) or anon mmap region
            let leader = self
                .processes
                .get(&pid)
                .map(|p| p.leader_pid)
                .unwrap_or(pid);
            let in_heap = self.processes.get(&pid).and_then(|proc| {
                let initial = proc.brk.initial_brk?;
                if event.addr >= initial && event.addr < proc.brk.current_brk {
                    Some(initial)
                } else {
                    None
                }
            });
            let region_info: Option<(String, String, u64)> = if let Some(initial) = in_heap {
                Some(("heap".to_string(), "rw-".to_string(), initial))
            } else {
                self.memory.get(&leader).and_then(|m| {
                    m.lookup_addr_full(event.addr)
                        .map(|(n, p, a)| (n.to_string(), p.to_string(), a))
                })
            };

            if let Some((region_name, region_prot, region_start)) = region_info {
                // Only track heap/anon
                if region_name != "heap" && region_name != "anon" {
                    continue;
                }

                self.page_faults += 1;

                // Check if this continues the current group
                if let Some(last) = groups.last_mut()
                    && last.region_start == region_start
                {
                    last.count += 1;
                    continue;
                }

                // Start new group
                groups.push(FaultGroup {
                    region_start,
                    region_name: region_name.to_string(),
                    region_prot: region_prot.to_string(),
                    count: 1,
                    first_addr: event.addr,
                    pid,
                });
            }
        }

        // Print grouped faults
        for group in groups {
            if group.count == 1 {
                self.output(&format!(
                    "{} fault {:012x} in {} ({})",
                    self.event_prefix(group.pid),
                    group.first_addr,
                    group.region_name,
                    group.region_prot
                ));
                self.record_event(
                    group.pid,
                    EventKind::Fault {
                        addr: format!("{:012x}", group.first_addr),
                        region_name: group.region_name,
                        prot: group.region_prot,
                    },
                );
            } else {
                self.output(&format!(
                    "{} {} faults in {} @ {:012x} ({})",
                    self.event_prefix(group.pid),
                    group.count,
                    group.region_name,
                    group.region_start,
                    group.region_prot
                ));
                self.record_event(
                    group.pid,
                    EventKind::FaultGroup {
                        count: group.count,
                        region_name: group.region_name,
                        region_start: format!("{:012x}", group.region_start),
                        prot: group.region_prot,
                    },
                );
            }
        }
    }
}
