#!/bin/bash
# Simple BPF generation script for Colima

set -e

echo "🔨 Generating BPF files for all collectors..."

# Change to project root
cd "$(dirname "$0")/.."

# eBPF collector
echo "Processing eBPF collector..."
cd pkg/collectors/ebpf/bpf
go generate ./...
cd ../../../..

# Systemd collector
echo "Processing Systemd collector..."
cd pkg/collectors/systemd/bpf
go generate ./...
cd ../../../..

# CNI collector
echo "Processing CNI collector..."
cd pkg/collectors/cni/bpf
go generate ./...
cd ../../../..

# etcd collector
echo "Processing etcd collector..."
cd pkg/collectors/etcd/bpf
go generate ./...
cd ../../../..

echo "✅ All BPF files generated!"

# Test build
echo "Testing collector builds..."
go build ./pkg/collectors/...
echo "✅ All collectors build successfully!"