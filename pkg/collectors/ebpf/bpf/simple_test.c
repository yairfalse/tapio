//go:build ignore

#include "headers/vmlinux.h"
#include "common.h"

// Define minimal BPF helpers we need
static long (*bpf_ktime_get_ns)(void) = (void *) 5;
static long (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;

#define BPF_F_CURRENT_CPU 0xffffffffULL

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} test_events __attribute__((section(".maps"), used));

__attribute__((section("tracepoint/sched/sched_process_exec"), used))
int trace_exec(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    bpf_perf_event_output(ctx, &test_events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";