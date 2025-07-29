#!/bin/bash
# Run eBPF tests in Colima VM

set -e

echo "Running eBPF tests in Colima..."

# Check if colima is running
if ! colima status 2>&1 | grep -q "is running"; then
    echo "Error: Colima is not running. Please start it with: colima start"
    exit 1
fi

# Build test binary for Linux
echo "Building test binary for Linux..."
GOOS=linux GOARCH=amd64 go test -c -o ebpf-tests .

# Copy test binary to Colima
echo "Copying test binary to Colima..."
colima ssh -- mkdir -p /tmp/tapio-ebpf-tests
scp -o StrictHostKeyChecking=no -P 60006 ebpf-tests lima@127.0.0.1:/tmp/tapio-ebpf-tests/ 2>/dev/null || \
colima cp ebpf-tests /tmp/tapio-ebpf-tests/ebpf-tests

# Run different test suites
echo "Running tests in Colima..."

# Basic tests
echo "=== Running basic tests ==="
colima ssh -- "cd /tmp/tapio-ebpf-tests && sudo ./ebpf-tests -test.run TestRateLimiter -test.v"

# Map Manager tests (requires root for eBPF)
echo "=== Running MapManager tests ==="
colima ssh -- "cd /tmp/tapio-ebpf-tests && sudo ./ebpf-tests -test.run TestMapManager -test.v"

# Perf Event Manager tests
echo "=== Running PerfEventManager tests ==="
colima ssh -- "cd /tmp/tapio-ebpf-tests && sudo ./ebpf-tests -test.run TestPerfEventManager -test.v"

# Integration tests
echo "=== Running Integration tests ==="
colima ssh -- "cd /tmp/tapio-ebpf-tests && sudo ./ebpf-tests -test.run TestCollector_Integration -test.v"

# Benchmark tests (optional)
if [[ "$1" == "--bench" ]]; then
    echo "=== Running Benchmark tests ==="
    colima ssh -- "cd /tmp/tapio-ebpf-tests && sudo ./ebpf-tests -test.bench=. -test.run=^$ -test.v"
fi

echo "All tests completed!"

# Cleanup
rm -f ebpf-tests