package bpf

// Generate eBPF programs for DNS monitoring
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" -target amd64,arm64 dnsMonitor ../bpf_src/dns_monitor.c -- -I../bpf_src
