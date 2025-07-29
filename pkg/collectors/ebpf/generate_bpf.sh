#!/bin/bash
# Generate Go bindings for eBPF programs using bpf2go

set -e

echo "Installing bpf2go if needed..."
go install github.com/cilium/ebpf/cmd/bpf2go@latest

echo "Generating Go bindings for eBPF programs..."

# Function to generate bindings for a single program
generate_program() {
    local prog=$1
    local name=$2
    
    echo "Generating bindings for $prog..."
    
    # Use bpf2go to generate Go bindings
    go run github.com/cilium/ebpf/cmd/bpf2go \
        -cc clang \
        -cflags "-O2 -g -Wall -target bpf -I./bpf -I./bpf/headers" \
        -target amd64,arm64 \
        -type "network_event" \
        -type "connection_key" \
        -type "connection_stats" \
        $name bpf/$prog.c -- -I./bpf/headers
}

# Generate bindings for each program
generate_program "network_monitor" "networkMonitor"
generate_program "memory_tracker" "memoryTracker"
generate_program "http_tracer" "httpTracer"
generate_program "grpc_tracer" "grpcTracer"
generate_program "dns_monitor" "dnsMonitor"
generate_program "protocol_analyzer" "protocolAnalyzer"
generate_program "packet_analyzer" "packetAnalyzer"
generate_program "oom_detector" "oomDetector"

echo "Go bindings generated successfully!"

# List generated files
echo "Generated files:"
ls -la *_bpfel_*.go *_bpfel_*.o 2>/dev/null || echo "No files generated yet"