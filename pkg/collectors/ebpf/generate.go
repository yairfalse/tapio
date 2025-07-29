package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 memorytracker bpf/memory_tracker.c -- -I./bpf -I./bpf/headers
