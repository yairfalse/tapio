#!/bin/bash
# Inline test for CNI collector

echo "Testing CNI Collector Monitors..."
echo "================================="

# Start collector in background and capture output
colima exec -- sudo /tmp/cni-test/cni-test > collector.log 2>&1 &
PID=$!

# Give it time to start
sleep 3

# Show it's running
echo "Collector started with PID in VM"

# Create test events
echo -e "\n📦 Creating network namespace (triggers eBPF)..."
colima exec -- sudo ip netns add test-cni-inline 2>/dev/null && echo "✓ Created namespace"

echo -e "\n🔗 Creating veth pair (triggers eBPF)..."
colima exec -- sudo ip link add veth-inline type veth peer name veth-peer-inline 2>/dev/null && echo "✓ Created veth pair"

echo -e "\n📄 Creating CNI config (triggers inotify)..."
echo '{"cniVersion": "0.3.1", "name": "test-inline", "type": "bridge"}' > test.conf
docker run --rm -v $(pwd):/src -v /tmp:/tmp alpine cp /src/test.conf /tmp/test-inline.conf
echo "✓ Created config file"

# Let events process
echo -e "\n⏳ Waiting for events to be captured..."
sleep 5

# Kill collector
colima exec -- sudo kill $PID 2>/dev/null

# Show last 50 lines of output
echo -e "\n📊 Collector Output:"
echo "===================="
tail -50 collector.log

# Cleanup
colima exec -- sudo ip link delete veth-inline 2>/dev/null
colima exec -- sudo ip netns delete test-cni-inline 2>/dev/null
rm -f test.conf collector.log