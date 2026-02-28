// SPDX-License-Identifier: GPL-2.0
// compendium eBPF programs: scheduler latency + block I/O latency
//
// Build (rare — only when this file changes, .o is checked into git):
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibpf -c bpf/compendium.bpf.c -o bpf/compendium.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// ---- Event types sent to userspace via ring buffer ----

#define EVENT_SCHED_DELAY 1
#define EVENT_BLOCK_IO    2

struct sched_delay_event {
    __u8  event_type;
    __u8  _pad[3];
    __u32 pid;
    __u64 delay_ns;
    __u64 timestamp_ns;
};

struct block_io_event {
    __u8  event_type;
    __u8  _pad[3];
    __u32 pid;
    __u64 latency_ns;
    __u64 bytes;
    __u64 timestamp_ns;
};

// ---- Key for in-flight block I/O ----

// NOTE(louis): (dev, sector) is not globally unique: two concurrent I/Os to the
// same sector on the same device will collide and the second insert
// overwrites the first. This is rare in practice (requires two in-flight
// requests targeting the exact same sector) and the worst case is a
// slightly wrong latency for the affected pair.
struct io_key {
    __u32 dev;
    __u32 _pad;
    __u64 sector;
};

struct issue_info {
    __u64 ts;
    __u32 pid;
    __u32 _pad;
    __u64 bytes;
};

// ---- Maps ----

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} TRACKED_PIDS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} WAKEUP_TS SEC(".maps");

// NOTE(louis): INFLIGHT_IO entries are inserted on block_rq_issue and deleted on
// block_rq_complete. If a completion is never delivered (e.g., canceled I/O),
// the entry leaks. The map is bounded at 4096 entries (~96 KB), so the leak
// is capped and all entries are freed when the BPF program is detached on
// process exit.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct io_key);
    __type(value, struct issue_info);
} INFLIGHT_IO SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} EVENTS SEC(".maps");

// Minimum scheduler delay to report (10 microseconds)
#define MIN_SCHED_DELAY_NS 10000ULL

// Counter for events dropped due to ring buffer exhaustion.
// Read from userspace via the .bss map to surface in the summary.
__u64 dropped_events = 0;

// ---- Scheduler tracepoints ----

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 pid = ctx->pid;
    __u8 *tracked = bpf_map_lookup_elem(&TRACKED_PIDS, &pid);
    if (!tracked)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&WAKEUP_TS, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 next_pid = ctx->next_pid;

    __u64 *wakeup_ts = bpf_map_lookup_elem(&WAKEUP_TS, &next_pid);
    if (!wakeup_ts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delay = now - *wakeup_ts;
    bpf_map_delete_elem(&WAKEUP_TS, &next_pid);

    if (delay < MIN_SCHED_DELAY_NS)
        return 0;

    struct sched_delay_event *evt =
        bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
    if (!evt) {
        __sync_fetch_and_add(&dropped_events, 1);
        return 0;
    }

    evt->event_type = EVENT_SCHED_DELAY;
    evt->_pad[0] = 0;
    evt->_pad[1] = 0;
    evt->_pad[2] = 0;
    evt->pid = next_pid;
    evt->delay_ns = delay;
    evt->timestamp_ns = now;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ---- Block I/O tracepoints ----

// NOTE(louis): uses current TID (matches sched tracepoints which also use TID).
// Buffered writeback I/O issued by kworker threads will not match TRACKED_PIDS.
SEC("tp/block/block_rq_issue")
int handle_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    __u8 *tracked = bpf_map_lookup_elem(&TRACKED_PIDS, &pid);
    if (!tracked)
        return 0;

    struct io_key key = {};
    key.dev = ctx->dev;
    key.sector = ctx->sector;

    struct issue_info info = {};
    info.ts = bpf_ktime_get_ns();
    info.pid = pid;
    info.bytes = ctx->nr_sector * 512ULL;

    bpf_map_update_elem(&INFLIGHT_IO, &key, &info, BPF_ANY);
    return 0;
}

SEC("tp/block/block_rq_complete")
int handle_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
{
    struct io_key key = {};
    key.dev = ctx->dev;
    key.sector = ctx->sector;

    struct issue_info *info = bpf_map_lookup_elem(&INFLIGHT_IO, &key);
    if (!info)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 latency = now - info->ts;
    __u32 pid = info->pid;
    __u64 bytes = info->bytes;

    bpf_map_delete_elem(&INFLIGHT_IO, &key);

    struct block_io_event *evt =
        bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
    if (!evt) {
        __sync_fetch_and_add(&dropped_events, 1);
        return 0;
    }

    evt->event_type = EVENT_BLOCK_IO;
    evt->_pad[0] = 0;
    evt->_pad[1] = 0;
    evt->_pad[2] = 0;
    evt->pid = pid;
    evt->latency_ns = latency;
    evt->bytes = bytes;
    evt->timestamp_ns = now;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
