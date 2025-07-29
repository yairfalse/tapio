#!/bin/bash
# Script to run CNI collector test in Colima

echo "Setting up and testing CNI collector in Colima..."

# Create CNI directories
colima exec -- sudo mkdir -p /opt/cni/bin /etc/cni/net.d
colima exec -- sudo chmod 755 /opt/cni/bin /etc/cni/net.d

# Add the test directory to inotify watch paths
colima exec -- mkdir -p /tmp/cni-configs

# Run the test program
echo -e "\n🚀 Starting CNI collector test...\n"
colima exec -- sudo /tmp/cni-test/cni-test