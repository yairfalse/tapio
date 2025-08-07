package bpf

// Generate eBPF objects for kernel monitoring
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" -target amd64,arm64 kernelmonitor c/kernel_monitor.c -- -I./c
