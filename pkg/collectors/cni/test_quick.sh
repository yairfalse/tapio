#!/bin/bash
# Quick test script for CNI collector in Colima

echo "Quick CNI Collector Test"
echo "========================"

# Setup
colima exec -- sudo mkdir -p /opt/cni/bin /etc/cni/net.d 2>/dev/null

# Run collector for 10 seconds
echo -e "\n1. Starting CNI collector with timeout..."
timeout 10 colima exec -- sudo /tmp/cni-test/cni-test &
PID=$!

# Wait a bit for it to start
sleep 3

# Create test events
echo -e "\n2. Creating test network namespace..."
colima exec -- sudo ip netns add test-cni-demo 2>/dev/null
colima exec -- sudo ip link add veth-demo type veth peer name veth-peer 2>/dev/null

echo -e "\n3. Creating test CNI config file..."
colima exec -- "echo '{\"cniVersion\": \"0.3.1\", \"name\": \"test\", \"type\": \"bridge\"}' | sudo tee /tmp/test-cni.conf"

# Wait for events
sleep 3

# Cleanup
echo -e "\n4. Cleaning up..."
colima exec -- sudo ip link delete veth-demo 2>/dev/null
colima exec -- sudo ip netns delete test-cni-demo 2>/dev/null
colima exec -- sudo rm -f /tmp/test-cni.conf

# Wait for collector to finish
wait $PID 2>/dev/null

echo -e "\n✅ Quick test completed! Check above for any captured events."