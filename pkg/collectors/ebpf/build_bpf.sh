#!/bin/bash
# Build script for eBPF programs

set -e

echo "Building eBPF programs..."

# Check if we're in the right directory
if [ ! -f "bpf/network_monitor.c" ]; then
    echo "Error: Must run from pkg/collectors/ebpf directory"
    exit 1
fi

# Create output directory
mkdir -p bin

# Build for both x86_64 and arm64
ARCHS=("x86" "arm64")

for arch in "${ARCHS[@]}"; do
    echo "Building for $arch..."
    
    # Network monitor
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_${arch} \
        -I./bpf/headers \
        -c bpf/network_monitor.c \
        -o bin/network_monitor_bpfel_${arch}.o

    # Memory tracker
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_${arch} \
        -I./bpf/headers \
        -c bpf/memory_tracker.c \
        -o bin/memory_tracker_bpfel_${arch}.o

    # OOM detector
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_${arch} \
        -I./bpf/headers \
        -c bpf/oom_detector.c \
        -o bin/oom_detector_bpfel_${arch}.o
done

echo "BPF programs built successfully!"
echo "Output files in ./bin/"
ls -la bin/