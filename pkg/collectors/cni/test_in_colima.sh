#!/bin/bash

echo "🚀 Running CNI Monitoring Test in Colima"
echo "========================================"
echo

# Build first
echo "📦 Building for Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -o test-monitors ./test/main.go

if [ ! -f test-monitors ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful ($(ls -lh test-monitors | awk '{print $5}'))"
echo

# Run in docker container with Colima's docker
echo "🎯 Starting test..."
docker run --rm \
    -v "$(pwd)/test-monitors:/test-monitors" \
    -v "/tmp:/tmp" \
    --privileged \
    --network host \
    alpine:latest \
    /test-monitors

# Cleanup
rm -f test-monitors

echo
echo "✅ Test completed!"