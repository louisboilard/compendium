//! eBPF-based tracing: scheduler latency and block I/O latency.
//!
//! Loads a pre-compiled BPF object (`bpf/compendium.bpf.o`) via `libbpf-rs`,
//! attaches 4 tracepoint programs, and reads events from a ring buffer.
//! Requires `CAP_BPF` + `CAP_PERFMON` or root.

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{Link, MapCore, MapFlags, MapHandle, ObjectBuilder, RingBuffer, RingBufferBuilder};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::rc::Rc;

/// Event type discriminants matching the BPF C side.
const EVENT_SCHED_DELAY: u8 = 1;
const EVENT_BLOCK_IO: u8 = 2;

/// Sched delay event from the BPF ring buffer (matches C struct layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SchedDelayEvent {
    pub(crate) event_type: u8,
    pub(crate) _pad: [u8; 3],
    pub(crate) pid: u32,
    pub(crate) delay_ns: u64,
    pub(crate) timestamp_ns: u64,
}

/// Block I/O event from the BPF ring buffer (matches C struct layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BlockIoEvent {
    pub(crate) event_type: u8,
    pub(crate) _pad: [u8; 3],
    pub(crate) pid: u32,
    pub(crate) latency_ns: u64,
    pub(crate) bytes: u64,
    pub(crate) timestamp_ns: u64,
}

/// Parsed event from the BPF ring buffer.
pub(crate) enum EbpfEvent {
    SchedDelay(SchedDelayEvent),
    BlockIo(BlockIoEvent),
}

/// eBPF tracker: loads BPF programs, manages the PID filter map, reads events.
pub(crate) struct EbpfTracker {
    _links: Vec<Link>,
    ring_buf: RingBuffer<'static>,
    tracked_pids: MapHandle,
    bss: Option<MapHandle>,
    pending: Rc<RefCell<Vec<EbpfEvent>>>,
    // Keep the object alive so maps/programs aren't dropped
    _object: &'static mut libbpf_rs::Object,
}

impl EbpfTracker {
    /// Load the BPF object, attach tracepoints, and seed the PID map.
    pub(crate) fn new(initial_pid: u32) -> Result<Self> {
        let obj_bytes = include_bytes!("../bpf/compendium.bpf.o");

        let open_obj = ObjectBuilder::default()
            .name("compendium")
            .context("Failed to set BPF object name")?
            .open_memory(obj_bytes)
            .context("Failed to open BPF object")?;

        let obj = open_obj.load().context("Failed to load BPF object")?;

        // Leak to 'static so RingBuffer callbacks (which require 'static) can
        // reference maps owned by the Object. This is acceptable for a CLI tool
        // that runs once and exits — the OS reclaims all memory on process exit.
        // The alternative (unsafe self-referential struct or Pin trickery) would
        // add significant complexity for zero practical benefit.
        let obj: &'static mut libbpf_rs::Object = Box::leak(Box::new(obj));

        // Attach all 4 tracepoint programs
        let mut links = Vec::new();
        let prog_names: &[&str] = &[
            "handle_sched_wakeup",
            "handle_sched_switch",
            "handle_block_rq_issue",
            "handle_block_rq_complete",
        ];
        for name in prog_names {
            let prog = obj
                .progs_mut()
                .find(|p| p.name() == OsStr::new(name))
                .ok_or_else(|| anyhow!("BPF program '{}' not found", name))?;
            let link = prog
                .attach()
                .with_context(|| format!("Failed to attach BPF program '{}'", name))?;
            links.push(link);
        }

        // Get an owned MapHandle for TRACKED_PIDS so we can update it later
        let tracked_pids_map = obj
            .maps()
            .find(|m| m.name() == OsStr::new("TRACKED_PIDS"))
            .ok_or_else(|| anyhow!("TRACKED_PIDS map not found"))?;
        let tracked_pids = MapHandle::try_from(&tracked_pids_map)
            .context("Failed to create MapHandle for TRACKED_PIDS")?;

        // Look up the .bss map for reading the dropped_events counter.
        // Optional — missing .bss doesn't prevent eBPF from working.
        let bss = obj
            .maps()
            .find(|m| {
                m.name()
                    .to_str()
                    .map(|n| n.ends_with(".bss"))
                    .unwrap_or(false)
            })
            .and_then(|m| MapHandle::try_from(&m).ok());

        // Seed the initial PID
        tracked_pids
            .update(&initial_pid.to_ne_bytes(), &[1u8], MapFlags::ANY)
            .context("Failed to seed initial PID")?;

        // Ring buffer consumer
        let pending: Rc<RefCell<Vec<EbpfEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let pending_clone = pending.clone();

        let events_map = obj
            .maps()
            .find(|m| m.name() == OsStr::new("EVENTS"))
            .ok_or_else(|| anyhow!("EVENTS ring buffer map not found"))?;

        let mut builder = RingBufferBuilder::new();
        builder
            .add(&events_map, move |data: &[u8]| {
                if data.is_empty() {
                    return 0;
                }
                match data[0] {
                    EVENT_SCHED_DELAY if data.len() >= std::mem::size_of::<SchedDelayEvent>() => {
                        let evt: SchedDelayEvent =
                            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                        pending_clone.borrow_mut().push(EbpfEvent::SchedDelay(evt));
                    }
                    EVENT_BLOCK_IO if data.len() >= std::mem::size_of::<BlockIoEvent>() => {
                        let evt: BlockIoEvent =
                            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                        pending_clone.borrow_mut().push(EbpfEvent::BlockIo(evt));
                    }
                    _ => {}
                }
                0
            })
            .context("Failed to add ring buffer callback")?;
        let ring_buf = builder.build().context("Failed to build ring buffer")?;

        Ok(Self {
            _links: links,
            ring_buf,
            tracked_pids,
            bss,
            pending,
            _object: obj,
        })
    }

    /// Returns the epoll fd for the ring buffer, suitable for `poll()`.
    pub(crate) fn poll_fd(&self) -> i32 {
        self.ring_buf.epoll_fd()
    }

    /// Add a PID to the tracked set (called on fork/clone).
    pub(crate) fn add_pid(&self, pid: u32) {
        if let Err(e) = self
            .tracked_pids
            .update(&pid.to_ne_bytes(), &[1u8], MapFlags::ANY)
        {
            eprintln!("compendium: eBPF: failed to add pid {}: {}", pid, e);
        }
    }

    /// Remove a PID from the tracked set (called on exit).
    pub(crate) fn remove_pid(&self, pid: u32) {
        // delete may fail if PID was never added (e.g., race); not an error
        let _ = self.tracked_pids.delete(&pid.to_ne_bytes());
    }

    /// Non-blocking consume from ring buffer, then drain collected events.
    pub(crate) fn consume_and_drain(&self) -> Vec<EbpfEvent> {
        if let Err(e) = self.ring_buf.consume() {
            eprintln!("compendium: eBPF: ring buffer consume error: {}", e);
        }
        std::mem::take(&mut *self.pending.borrow_mut())
    }

    /// Read the dropped event count from the BPF .bss global variable.
    ///
    /// Returns 0 if the .bss map is unavailable or the read fails.
    pub(crate) fn dropped_count(&self) -> u64 {
        let Some(ref bss) = self.bss else {
            return 0;
        };
        // The .bss map is an array with a single element (key=0).
        // The dropped_events u64 is the first 8 bytes of the value.
        match bss.lookup(&0u32.to_ne_bytes(), MapFlags::ANY) {
            Ok(Some(val)) if val.len() >= 8 => u64::from_ne_bytes(val[..8].try_into().unwrap()),
            _ => 0,
        }
    }
}
