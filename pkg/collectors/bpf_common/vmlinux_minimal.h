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

struct trace_event_raw_sys_exit {
    long ret;
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

// Network protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// BPF map update flags
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

// TC action codes
#define TC_ACT_OK         0
#define TC_ACT_SHOT       2
#define TC_ACT_STOLEN     4
#define TC_ACT_QUEUED     5
#define TC_ACT_REPEAT     6
#define TC_ACT_REDIRECT   7

// Network structures for DNS monitoring
struct iphdr {
    __u8    ihl:4,
            version:4;
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __be32  saddr;
    __be32  daddr;
};

struct udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __u16   check;
};

struct tcphdr {
    __be16  source;
    __be16  dest;
    __be32  seq;
    __be32  ack_seq;
    __u16   res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
    __be16  window;
    __u16   check;
    __be16  urg_ptr;
};

// SK_BUFF for TC programs
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_MINIMAL_H__ */