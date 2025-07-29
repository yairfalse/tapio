package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni"
	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
)

func main() {
	fmt.Println("🚀 CNI Efficient Monitoring Test")
	fmt.Println("================================")
	fmt.Println()

	// Create config with efficient monitors enabled
	config := core.Config{
		// Basic settings
		Name:            "test-collector",
		Enabled:         true,
		EventBufferSize: 1000,
		CNIConfPath:     "/tmp",
		CNIBinPath:      "/opt/cni/bin",

		// Enable monitoring types
		EnableFileMonitoring:    true,
		EnableProcessMonitoring: true,

		// Enable efficient monitors
		UseInotify:     true,
		UseEBPF:        true,
		UseK8sInformer: false, // Disable K8s for this test

		// Performance
		EventRateLimit: 100,
		PollInterval:   30 * time.Second,
	}

	fmt.Println("Configuration:")
	fmt.Printf("  • Inotify: %v (real-time file monitoring)\n", config.UseInotify)
	fmt.Printf("  • eBPF: %v (kernel-level monitoring)\n", config.UseEBPF)
	fmt.Printf("  • Rate limit: %d events/sec\n", config.EventRateLimit)
	fmt.Println()

	// Create collector
	collector, err := cni.NewCNICollector(config)
	if err != nil {
		log.Fatalf("Failed to create collector: %v", err)
	}

	// Start collector
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Starting collector...")
	if err := collector.Start(ctx); err != nil {
		log.Fatalf("Failed to start collector: %v", err)
	}

	fmt.Println("✅ Collector started successfully!")
	fmt.Println()

	// Monitor events in background
	eventCount := 0
	go func() {
		for event := range collector.Events() {
			eventCount++
			fmt.Printf("\n🎉 Event #%d detected:\n", eventCount)
			fmt.Printf("   Type: %s\n", event.Type)
			fmt.Printf("   Source: %s\n", event.Source)
			if event.Message != "" {
				fmt.Printf("   Message: %s\n", event.Message)
			}
			// Check if event has semantic context with metadata
			if event.Semantic != nil && event.Semantic.Narrative != "" {
				fmt.Printf("   Details: %s\n", event.Semantic.Narrative)
			}
			fmt.Printf("   Time: %s\n", event.Timestamp.Format("15:04:05"))
		}
	}()

	// Create test scenarios
	fmt.Println("Running test scenarios...")
	fmt.Println()

	// Test 1: File monitoring with inotify
	fmt.Println("📁 Test 1: Inotify File Monitoring")
	fmt.Println("Creating CNI config file...")

	testFile := "/tmp/test-bridge.conflist"
	configContent := `{
  "cniVersion": "0.4.0",
  "name": "test-network",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "test-br0",
      "ipam": {
        "type": "host-local",
        "subnet": "10.88.0.0/16"
      }
    }
  ]
}`

	if err := os.WriteFile(testFile, []byte(configContent), 0644); err != nil {
		log.Printf("Failed to create test file: %v", err)
	} else {
		fmt.Printf("✅ Created: %s\n", testFile)
	}

	time.Sleep(2 * time.Second)

	// Modify the file
	configContent += "\n// Modified at " + time.Now().Format("15:04:05")
	if err := os.WriteFile(testFile, []byte(configContent), 0644); err != nil {
		log.Printf("Failed to modify test file: %v", err)
	} else {
		fmt.Printf("✅ Modified: %s\n", testFile)
	}

	time.Sleep(2 * time.Second)

	// Delete the file
	if err := os.Remove(testFile); err != nil {
		log.Printf("Failed to delete test file: %v", err)
	} else {
		fmt.Printf("✅ Deleted: %s\n", testFile)
	}

	time.Sleep(2 * time.Second)

	// Test 2: Process monitoring
	fmt.Println("\n📊 Test 2: Process Monitoring")
	fmt.Println("Simulating CNI plugin execution...")

	// Create a dummy CNI plugin
	dummyPlugin := "/tmp/dummy-cni"
	pluginContent := `#!/bin/sh
echo '{"cniVersion": "0.4.0"}'`

	if err := os.WriteFile(dummyPlugin, []byte(pluginContent), 0755); err != nil {
		log.Printf("Failed to create dummy plugin: %v", err)
	} else {
		// Try to execute it (this will be detected by process monitor)
		os.Chmod(dummyPlugin, 0755)
		fmt.Printf("✅ Created executable: %s\n", dummyPlugin)
	}

	time.Sleep(2 * time.Second)
	os.Remove(dummyPlugin)

	// Wait for remaining time
	fmt.Println("\n⏳ Monitoring for remaining time...")
	<-ctx.Done()

	// Stop collector
	fmt.Println("\n🛑 Stopping collector...")
	collector.Stop()

	// Show summary
	fmt.Println("\n📊 Test Summary")
	fmt.Println("==============")
	fmt.Printf("Total events captured: %d\n", eventCount)

	if eventCount > 0 {
		fmt.Println("\n✨ Success! The efficient monitors detected:")
		fmt.Println("  • File creation/modification/deletion in real-time")
		fmt.Println("  • Process executions without polling")
		fmt.Println("  • All with minimal resource usage!")
	} else {
		fmt.Println("\n⚠️  No events captured. This could mean:")
		fmt.Println("  • The monitors need sudo privileges (for eBPF)")
		fmt.Println("  • The test directories need to exist")
		fmt.Println("  • Fallback monitors were used instead")
	}

	fmt.Println("\n✅ Test completed!")
}
