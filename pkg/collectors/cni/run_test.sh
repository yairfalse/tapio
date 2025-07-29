#!/bin/bash
# Simple test runner for CNI efficient monitoring in Colima

echo "🚀 CNI Efficient Monitoring Test Runner"
echo "======================================"
echo

# Check if Colima is running
if ! colima status &>/dev/null; then
    echo "❌ Colima is not running. Please start it with: colima start"
    exit 1
fi

echo "✅ Colima is running"

# Build the test
echo
echo "📦 Building test program for Linux ARM64..."
cd test
GOOS=linux GOARCH=arm64 go build -o test-monitors .

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Checking dependencies..."
    cd ..
    go mod tidy
    cd test
    GOOS=linux GOARCH=arm64 go build -o test-monitors .
fi

if [ ! -f test-monitors ]; then
    echo "❌ Failed to build test program"
    exit 1
fi

echo "✅ Build successful"

# Run directly using docker inside colima
echo
echo "🎯 Running test in Colima container..."
echo "==========================================="
echo

# Create a temporary directory and copy the binary
TEMP_DIR=$(mktemp -d)
cp test-monitors "$TEMP_DIR/"

# Run using docker inside colima
docker run --rm \
    -v "$TEMP_DIR:/app" \
    -v /tmp:/tmp \
    --privileged \
    alpine:latest \
    sh -c "
        echo '🔧 Setting up environment...'
        mkdir -p /opt/cni/bin /tmp
        cd /app
        chmod +x test-monitors
        echo
        echo '🚀 Starting test...'
        ./test-monitors
    "

# Cleanup
echo
echo "🧹 Cleaning up..."
rm -rf "$TEMP_DIR"
rm -f test-monitors
cd ..

echo
echo "✅ Test run complete!"
echo
echo "💡 Tips:"
echo "  • For eBPF monitoring, the container needs --privileged flag"
echo "  • The test monitors /tmp directory for CNI config changes"
echo "  • Check the output above for captured events"