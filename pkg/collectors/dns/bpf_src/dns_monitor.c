//go:build ignore

#include "../../bpf_common/vmlinux_minimal.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_DATA_SIZE 256
#define DNS_PORT 53

// DNS packet types
#define DNS_TYPE_QUERY    1
#define DNS_TYPE_RESPONSE 2
#define DNS_TYPE_ERROR    3

// DNS response codes
#define DNS_RCODE_NOERROR  0
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_TIMEOUT  4

// DNS event structure
struct dns_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u8 event_type;
    __u8 protocol; // 6=TCP, 17=UDP
    __u16 _pad;
    
    __u32 src_ip;
    __u32 dst_ip; 
    __u16 src_port;
    __u16 dst_port;
    
    __u8 dns_opcode;
    __u8 dns_rcode;
    __u16 dns_flags;
    
    __u32 data_len;
    __u8 query_name[64];  // DNS query name
    __u8 data[MAX_DATA_SIZE];
} __attribute__((packed));

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Per-CPU map to avoid stack overflow with large dns_event struct
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_event);
    __uint(max_entries, 1);
} dns_event_buffer SEC(".maps");

// Temporary map to correlate outgoing queries with responses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // Transaction ID + src_port hash
    __type(value, struct dns_event);
    __uint(max_entries, 10240);
} dns_queries SEC(".maps");

// Helper to extract DNS header fields
static __always_inline int parse_dns_header(void *data, void *data_end, 
                                           struct dns_event *event) {
    if (data + 12 > data_end) // DNS header is 12 bytes minimum
        return -1;
        
    // DNS header structure:
    // 0-2: Transaction ID
    // 2-4: Flags (QR, opcode, AA, TC, RD, RA, Z, RCODE)
    // 4-6: QDCOUNT, 6-8: ANCOUNT, 8-10: NSCOUNT, 10-12: ARCOUNT
    
    __u16 *dns_hdr = (__u16 *)data;
    __u16 transaction_id = bpf_ntohs(dns_hdr[0]);
    __u16 flags = bpf_ntohs(dns_hdr[1]);
    
    // Extract QR bit (bit 15): 0=query, 1=response
    __u8 qr = (flags >> 15) & 0x1;
    event->dns_opcode = (flags >> 11) & 0xf;  // Opcode (bits 11-14)
    event->dns_rcode = flags & 0xf;           // Response code (bits 0-3)
    event->dns_flags = flags;
    
    if (qr == 0) {
        event->event_type = DNS_TYPE_QUERY;
    } else {
        event->event_type = DNS_TYPE_RESPONSE;
        // Check for DNS errors
        if (event->dns_rcode != DNS_RCODE_NOERROR) {
            event->event_type = DNS_TYPE_ERROR;
        }
    }
    
    return transaction_id;
}

// Helper to extract query name from DNS packet
static __always_inline void extract_query_name(void *data, void *data_end,
                                              struct dns_event *event) {
    if (data + 12 > data_end) // Skip DNS header
        return;
        
    __u8 *query_start = (__u8 *)data + 12;
    __u8 *query_ptr = query_start;
    int name_pos = 0;
    
    // Parse DNS name (label format)
    #pragma unroll
    for (int i = 0; i < 32 && query_ptr < (__u8 *)data_end && name_pos < 63; i++) {
        __u8 len = *query_ptr;
        if (len == 0) break; // End of name
        if (len > 63) break;  // Invalid length or compression
        
        query_ptr++;
        if (query_ptr + len > (__u8 *)data_end) break;
        
        // Add dot separator (except for first label)
        if (name_pos > 0 && name_pos < 62) {
            event->query_name[name_pos++] = '.';
        }
        
        // Copy label
        #pragma unroll
        for (int j = 0; j < len && j < 31 && name_pos < 63; j++) {
            if (query_ptr + j >= (__u8 *)data_end) break;
            event->query_name[name_pos++] = query_ptr[j];
        }
        
        query_ptr += len;
    }
    
    event->query_name[name_pos] = '\0';
}

// Common function to process DNS packets
static __always_inline int process_dns_packet(struct __sk_buff *skb, __u8 protocol) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse Ethernet header (14 bytes)
    if (data + 14 > data_end)
        return 0;
    data += 14;
    
    // Parse IP header (assume IPv4, 20 bytes minimum)
    if (data + 20 > data_end)
        return 0;
        
    struct iphdr *ip = (struct iphdr *)data;
    if (ip->version != 4 || ip->protocol != protocol)
        return 0;
        
    data += ip->ihl * 4; // IP header length
    
    // Parse transport header
    __u16 src_port, dst_port;
    if (protocol == IPPROTO_UDP) {
        if (data + 8 > data_end) // UDP header is 8 bytes
            return 0;
        struct udphdr *udp = (struct udphdr *)data;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        data += 8;
    } else if (protocol == IPPROTO_TCP) {
        if (data + 20 > data_end) // TCP header minimum 20 bytes
            return 0;
        struct tcphdr *tcp = (struct tcphdr *)data;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        data += tcp->doff * 4;
    } else {
        return 0;
    }
    
    // Check if it's DNS traffic (port 53)
    if (src_port != DNS_PORT && dst_port != DNS_PORT)
        return 0;
        
    // Get per-CPU buffer for DNS event to avoid stack overflow
    __u32 zero = 0;
    struct dns_event *event = bpf_map_lookup_elem(&dns_event_buffer, &zero);
    if (!event)
        return 0;
    
    // Initialize DNS event
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xffffffff;
    event->protocol = protocol;
    
    event->src_ip = bpf_ntohl(ip->saddr);
    event->dst_ip = bpf_ntohl(ip->daddr);
    event->src_port = src_port;
    event->dst_port = dst_port;
    
    // Parse DNS packet
    int transaction_id = parse_dns_header(data, data_end, event);
    if (transaction_id < 0)
        return 0;
        
    // Extract query name for correlation
    if (event->event_type == DNS_TYPE_QUERY) {
        extract_query_name(data, data_end, event);
    }
    
    // Calculate data length to copy
    __u32 dns_len = (__u32)((char *)data_end - (char *)data);
    if (dns_len > MAX_DATA_SIZE)
        dns_len = MAX_DATA_SIZE;
    event->data_len = dns_len;
    
    // Copy DNS packet data
    if (dns_len > 0) {
        bpf_probe_read_kernel(event->data, dns_len, data);
    }
    
    // Handle query vs response correlation
    __u32 correlation_key = (__u32)transaction_id ^ (__u32)src_port;
    
    if (event->event_type == DNS_TYPE_QUERY && dst_port == DNS_PORT) {
        // Outgoing query - store for correlation
        bpf_map_update_elem(&dns_queries, &correlation_key, event, BPF_ANY);
    } else if (event->event_type == DNS_TYPE_RESPONSE || event->event_type == DNS_TYPE_ERROR) {
        // Incoming response - try to correlate with stored query
        struct dns_event *query = bpf_map_lookup_elem(&dns_queries, &correlation_key);
        if (query) {
            // Copy query name to response event for context
            __builtin_memcpy(event->query_name, query->query_name, 64);
            // Remove from correlation map
            bpf_map_delete_elem(&dns_queries, &correlation_key);
        }
    }
    
    // Send event to userspace (focus on failures and responses)
    if (event->event_type == DNS_TYPE_ERROR || 
        (event->event_type == DNS_TYPE_RESPONSE && event->dns_rcode != DNS_RCODE_NOERROR)) {
        bpf_ringbuf_output(&events, event, sizeof(*event), 0);
    }
    
    return 0;
}

// Attach to network ingress to monitor DNS responses
SEC("tc")
int monitor_dns_ingress(struct __sk_buff *skb) {
    // Monitor both UDP and TCP DNS traffic
    process_dns_packet(skb, IPPROTO_UDP);
    process_dns_packet(skb, IPPROTO_TCP);
    return TC_ACT_OK;
}

// Attach to network egress to monitor DNS queries  
SEC("tc")
int monitor_dns_egress(struct __sk_buff *skb) {
    // Monitor both UDP and TCP DNS traffic
    process_dns_packet(skb, IPPROTO_UDP);
    process_dns_packet(skb, IPPROTO_TCP);
    return TC_ACT_OK;
}

// Alternative tracepoint-based monitoring for socket operations
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_dns_query(struct trace_event_raw_sys_enter *ctx) {
    // Monitor sendto syscalls that might be DNS queries
    // This provides more context about the process making DNS queries
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom") 
int trace_dns_response(struct trace_event_raw_sys_exit *ctx) {
    // Monitor recvfrom syscalls that might be DNS responses
    // This can help detect DNS timeouts when combined with query tracking
    return 0;
}

char __license[] SEC("license") = "GPL";