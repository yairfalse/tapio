package bpf

// Generate eBPF programs for filesystem monitoring
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" -target amd64,arm64 fsMonitor ../bpf_src/fs_monitor.c -- -I../bpf_src
