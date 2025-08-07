#include "../../bpf_common/vmlinux_minimal.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// File operation types
#define OP_OPEN   1
#define OP_READ   2
#define OP_WRITE  3
#define OP_FSYNC  4
#define OP_CLOSE  5

// Configuration struct matching Go fsConfig
struct fs_config {
    __u32 min_latency_us;
    __u32 track_kubelet_only;
    __u32 track_volumes_only; 
    __u32 enabled;
};

// Event structure matching Go rawFsEvent
struct fs_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u8 operation;
    __u8 _pad[3];
    __u32 fd;
    __s32 ret_code;
    __u64 latency_ns;
    __u64 bytes_requested;
    __u64 bytes_actual;
    char comm[16];
    char filename[64];
    char full_path[256];
};

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fs_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} fs_events SEC(".maps");

// Temporary storage for tracking operations
struct op_context {
    __u64 start_ns;
    __u64 bytes_requested;
    char filename[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct op_context);
    __uint(max_entries, 10240);
} op_contexts SEC(".maps");

// Helper to get current configuration
static __always_inline struct fs_config* get_config() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

// Helper to check if monitoring is enabled
static __always_inline int is_enabled() {
    struct fs_config *cfg = get_config();
    return cfg && cfg->enabled;
}

// Helper to check if we should track this process
static __always_inline int should_track_process() {
    struct fs_config *cfg = get_config();
    if (!cfg) return 1;
    
    if (cfg->track_kubelet_only) {
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        
        // Check if process name contains "kubelet"
        #pragma unroll
        for (int i = 0; i <= 8; i++) {
            if (comm[i] == 'k' && comm[i+1] == 'u' && comm[i+2] == 'b' &&
                comm[i+3] == 'e' && comm[i+4] == 'l' && comm[i+5] == 'e' &&
                comm[i+6] == 't') {
                return 1;
            }
        }
        return 0;
    }
    
    return 1;
}

// Openat entry
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!is_enabled() || !should_track_process()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context op_ctx = {};
    
    op_ctx.start_ns = bpf_ktime_get_ns();
    
    // Get filename from syscall args
    char *filename_ptr = (char *)ctx->args[1];
    bpf_probe_read_user_str(op_ctx.filename, sizeof(op_ctx.filename), filename_ptr);
    
    bpf_map_update_elem(&op_contexts, &pid_tgid, &op_ctx, BPF_ANY);
    return 0;
}

// Openat exit
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_enabled()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context *op_ctx = bpf_map_lookup_elem(&op_contexts, &pid_tgid);
    if (!op_ctx) {
        return 0;
    }
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&op_contexts, &pid_tgid);
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->operation = OP_OPEN;
    event->fd = ctx->ret;
    event->ret_code = ctx->ret;
    event->latency_ns = event->timestamp - op_ctx->start_ns;
    event->bytes_requested = 0;
    event->bytes_actual = 0;
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, op_ctx->filename, sizeof(event->filename));
    // full_path would require more complex logic to resolve
    event->full_path[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&op_contexts, &pid_tgid);
    
    return 0;
}

// Read entry
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!is_enabled() || !should_track_process()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context op_ctx = {};
    
    op_ctx.start_ns = bpf_ktime_get_ns();
    op_ctx.bytes_requested = ctx->args[2]; // count parameter
    
    bpf_map_update_elem(&op_contexts, &pid_tgid, &op_ctx, BPF_ANY);
    return 0;
}

// Read exit  
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_enabled()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context *op_ctx = bpf_map_lookup_elem(&op_contexts, &pid_tgid);
    if (!op_ctx) {
        return 0;
    }
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&op_contexts, &pid_tgid);
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->operation = OP_READ;
    event->fd = 0; // FD not available in exit context
    event->ret_code = ctx->ret;
    event->latency_ns = event->timestamp - op_ctx->start_ns;
    event->bytes_requested = op_ctx->bytes_requested;
    event->bytes_actual = ctx->ret > 0 ? ctx->ret : 0;
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    event->full_path[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&op_contexts, &pid_tgid);
    
    return 0;
}

// Write entry
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!is_enabled() || !should_track_process()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context op_ctx = {};
    
    op_ctx.start_ns = bpf_ktime_get_ns();
    op_ctx.bytes_requested = ctx->args[2]; // count parameter
    
    bpf_map_update_elem(&op_contexts, &pid_tgid, &op_ctx, BPF_ANY);
    return 0;
}

// Write exit
SEC("tracepoint/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_enabled()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context *op_ctx = bpf_map_lookup_elem(&op_contexts, &pid_tgid);
    if (!op_ctx) {
        return 0;
    }
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&op_contexts, &pid_tgid);
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->operation = OP_WRITE;
    event->fd = 0; // FD not available in exit context
    event->ret_code = ctx->ret;
    event->latency_ns = event->timestamp - op_ctx->start_ns;
    event->bytes_requested = op_ctx->bytes_requested;
    event->bytes_actual = ctx->ret > 0 ? ctx->ret : 0;
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    event->full_path[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&op_contexts, &pid_tgid);
    
    return 0;
}

// Fsync entry
SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_fsync_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!is_enabled() || !should_track_process()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context op_ctx = {};
    
    op_ctx.start_ns = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&op_contexts, &pid_tgid, &op_ctx, BPF_ANY);
    return 0;
}

// Fsync exit
SEC("tracepoint/syscalls/sys_exit_fsync")
int trace_fsync_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_enabled()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context *op_ctx = bpf_map_lookup_elem(&op_contexts, &pid_tgid);
    if (!op_ctx) {
        return 0;
    }
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&op_contexts, &pid_tgid);
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->operation = OP_FSYNC;
    event->fd = 0;
    event->ret_code = ctx->ret;
    event->latency_ns = event->timestamp - op_ctx->start_ns;
    event->bytes_requested = 0;
    event->bytes_actual = 0;
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    event->full_path[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&op_contexts, &pid_tgid);
    
    return 0;
}

// Close entry
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!is_enabled() || !should_track_process()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context op_ctx = {};
    
    op_ctx.start_ns = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&op_contexts, &pid_tgid, &op_ctx, BPF_ANY);
    return 0;
}

// Close exit
SEC("tracepoint/syscalls/sys_exit_close")
int trace_close_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_enabled()) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct op_context *op_ctx = bpf_map_lookup_elem(&op_contexts, &pid_tgid);
    if (!op_ctx) {
        return 0;
    }
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&op_contexts, &pid_tgid);
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->operation = OP_CLOSE;
    event->fd = 0;
    event->ret_code = ctx->ret;
    event->latency_ns = event->timestamp - op_ctx->start_ns;
    event->bytes_requested = 0;
    event->bytes_actual = 0;
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    event->full_path[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&op_contexts, &pid_tgid);
    
    return 0;
}

char _license[] SEC("license") = "GPL";