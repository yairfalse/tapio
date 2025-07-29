#!/bin/bash
# Test script for eBPF CNI monitoring in Colima

echo "Testing eBPF CNI monitoring in Colima Linux VM..."

# Check if running in Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "Error: This script must be run inside a Linux environment (e.g., Colima VM)"
    echo "To enter Colima VM, run: colima ssh"
    exit 1
fi

# Check kernel version (eBPF requires 4.x+)
KERNEL_VERSION=$(uname -r | cut -d. -f1)
if [[ $KERNEL_VERSION -lt 4 ]]; then
    echo "Warning: Kernel version $(uname -r) may not fully support eBPF"
fi

# Check for required capabilities
if ! command -v bpftool &> /dev/null; then
    echo "Warning: bpftool not found. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y linux-tools-common linux-tools-generic
    elif command -v yum &> /dev/null; then
        sudo yum install -y bpftool
    fi
fi

# Check if eBPF is supported
echo "Checking eBPF support..."
if [[ -d /sys/fs/bpf ]]; then
    echo "✓ BPF filesystem is mounted"
else
    echo "✗ BPF filesystem not found. Mounting..."
    sudo mount -t bpf bpf /sys/fs/bpf
fi

# Check for CNI directories
echo -e "\nChecking CNI directories..."
for dir in /opt/cni/bin /etc/cni/net.d; do
    if [[ -d $dir ]]; then
        echo "✓ Found: $dir"
        ls -la $dir | head -5
    else
        echo "✗ Not found: $dir"
    fi
done

# Test creating a network namespace (simulates CNI activity)
echo -e "\nTesting network namespace operations..."
NS_NAME="test-cni-$$"
if sudo ip netns add $NS_NAME 2>/dev/null; then
    echo "✓ Created network namespace: $NS_NAME"
    
    # Create veth pair (common CNI operation)
    if sudo ip link add veth0 type veth peer name veth1 2>/dev/null; then
        echo "✓ Created veth pair"
        sudo ip link delete veth0 2>/dev/null
    fi
    
    sudo ip netns delete $NS_NAME
    echo "✓ Cleaned up network namespace"
else
    echo "✗ Failed to create network namespace (may need sudo)"
fi

# Check for running CNI plugins
echo -e "\nChecking for CNI plugin processes..."
ps aux | grep -E "(cilium|calico|flannel|bridge|cni)" | grep -v grep | head -5

echo -e "\neBPF CNI monitoring should work in this environment!"
echo "To test the CNI collector with eBPF:"
echo "1. Build the collector: go build ./cmd/collector"
echo "2. Run with sudo: sudo ./collector --config config_example.yaml"