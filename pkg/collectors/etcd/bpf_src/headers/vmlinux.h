#ifndef __VMLINUX_MINIMAL_H__
#define __VMLINUX_MINIMAL_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

// Basic types
typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

// Network byte order types
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

// Checksum type
typedef __u32 __wsum;

// Boolean type
typedef _Bool bool;
#define true 1
#define false 0

// BPF map types
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,
    BPF_MAP_TYPE_CPUMAP,
    BPF_MAP_TYPE_XSKMAP,
    BPF_MAP_TYPE_SOCKHASH,
    BPF_MAP_TYPE_CGROUP_STORAGE,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    BPF_MAP_TYPE_QUEUE,
    BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_DEVMAP_HASH,
    BPF_MAP_TYPE_STRUCT_OPS,
    BPF_MAP_TYPE_RINGBUF,
};

typedef unsigned long long __kernel_dev_t;
typedef __kernel_dev_t dev_t;
typedef __u32 uid_t;
typedef __u32 gid_t;
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;
typedef __kernel_long_t __kernel_time_t;
typedef long long __kernel_loff_t;
typedef __kernel_loff_t loff_t;
typedef unsigned int __kernel_mode_t;
typedef __kernel_mode_t mode_t;
typedef __kernel_ulong_t size_t;

// Forward declarations for complex kernel structs
struct ns_common {
    unsigned int inum;
};

struct net {
    struct ns_common ns;
};

struct nsproxy {
    struct net *net_ns;
};

struct trace_event_raw_sys_enter {
    unsigned long args[6];
};

struct task_struct {
    int pid;
    int tgid;
    char comm[16];
    struct task_struct *real_parent;
    struct task_struct *parent;
    struct nsproxy *nsproxy;
};

struct sock_common {
    unsigned short skc_family;
    unsigned short skc_num;
    unsigned int skc_daddr;
    unsigned int skc_rcv_saddr;
    unsigned short skc_dport;
    unsigned short skc_sport;
};

struct sock {
    struct sock_common __sk_common;
};

struct pt_regs {
    unsigned long di, si, dx, cx, r8, r9;
    unsigned long r10, r11, r12, r13, r14, r15;
    unsigned long bp, bx;
    unsigned long ax;
    unsigned long ip, cs, flags, sp, ss;
};

// Network structures
struct in_addr {
    __u32 s_addr;
};

struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

// File system structures
struct file {
    unsigned int f_flags;
    mode_t f_mode;
    loff_t f_pos;
    unsigned int f_count;
};

struct dentry {
    unsigned int d_flags;
    char *d_name;
};

struct inode {
    mode_t i_mode;
    uid_t i_uid;
    gid_t i_gid;
    dev_t i_rdev;
    loff_t i_size;
};

// Memory management
struct mm_struct {
    unsigned long start_code, end_code, start_data, end_data;
    unsigned long start_brk, brk, start_stack;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_MINIMAL_H__ */