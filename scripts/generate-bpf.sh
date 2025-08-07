#!/bin/bash
# Script to generate BPF files for all collectors
# Run this inside Colima or a Linux environment

set -e

echo "🔨 Generating BPF files for all collectors..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to project root
cd "$(dirname "$0")/.."

echo -e "${YELLOW}Starting BPF generation...${NC}"

# Function to generate BPF for a collector
generate_bpf() {
    local collector=$1
    local dir=$2
    local file=$3
    
    echo -e "${GREEN}Generating BPF for ${collector}...${NC}"
    
    cd "$dir"
    
    # Generate BPF using bpf2go
    if [ -f "generate.go" ]; then
        go generate ./...
    elif [ -f "../generate.go" ]; then
        cd ..
        go generate ./...
    else
        echo -e "${RED}No generate.go found for ${collector}${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ ${collector} BPF generated${NC}"
    cd - > /dev/null
}

# eBPF collector
if [ -d "pkg/collectors/ebpf/bpf" ]; then
    echo -e "${GREEN}Processing eBPF collector...${NC}"
    cd pkg/collectors/ebpf/bpf
    go generate ./...
    cd - > /dev/null
    echo -e "${GREEN}✓ eBPF BPF generated${NC}"
fi

# Systemd collector
if [ -d "pkg/collectors/systemd/bpf" ]; then
    echo -e "${GREEN}Processing Systemd collector...${NC}"
    cd pkg/collectors/systemd/bpf
    go generate ./...
    cd - > /dev/null
    echo -e "${GREEN}✓ Systemd BPF generated${NC}"
fi

# CNI collector
if [ -d "pkg/collectors/cni/bpf" ]; then
    echo -e "${GREEN}Processing CNI collector...${NC}"
    cd pkg/collectors/cni/bpf
    go generate ./...
    cd - > /dev/null
    echo -e "${GREEN}✓ CNI BPF generated${NC}"
fi

# etcd collector
if [ -d "pkg/collectors/etcd/bpf" ]; then
    echo -e "${GREEN}Processing etcd collector...${NC}"
    cd pkg/collectors/etcd/bpf
    go generate ./...
    cd - > /dev/null
    echo -e "${GREEN}✓ etcd BPF generated${NC}"
fi

# Kubelet filesystem monitor - check if it has a generate.go
if [ -f "pkg/collectors/kubelet/generate.go" ]; then
    echo -e "${GREEN}Processing Kubelet FS collector...${NC}"
    cd pkg/collectors/kubelet
    go generate ./...
    cd - > /dev/null
    echo -e "${GREEN}✓ Kubelet FS BPF generated${NC}"
elif [ -f "pkg/collectors/kubelet/bpf/generate.go" ]; then
    echo -e "${GREEN}Processing Kubelet FS collector...${NC}"
    cd pkg/collectors/kubelet/bpf
    go generate ./...
    cd - > /dev/null
    echo -e "${GREEN}✓ Kubelet FS BPF generated${NC}"
fi

# DNS collector (if it has BPF)
if [ -d "pkg/collectors/dns/bpf" ] && [ -f "pkg/collectors/dns/bpf_src/dns_monitor.c" ]; then
    echo -e "${GREEN}Processing DNS collector...${NC}"
    cd pkg/collectors/dns/bpf
    go generate ./...
    cd - > /dev/null
    echo -e "${GREEN}✓ DNS BPF generated${NC}"
fi

echo -e "${GREEN}✅ All BPF files generated successfully!${NC}"

# Now test building all collectors
echo -e "${YELLOW}Testing collector builds...${NC}"

go build ./pkg/collectors/...

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ All collectors build successfully!${NC}"
else
    echo -e "${RED}❌ Some collectors failed to build${NC}"
    exit 1
fi