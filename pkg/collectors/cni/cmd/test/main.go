package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni"
	"github.com/yairfalse/tapio/pkg/domain"
)

func main() {
	fmt.Println("CNI Collector Test - Efficient Monitoring")
	fmt.Println("=========================================")

	// Check if running as root (needed for eBPF)
	if os.Geteuid() != 0 {
		fmt.Println("⚠️  Warning: Not running as root. eBPF monitoring will use fallback.")
	}

	// Create a development configuration
	config := cni.GetConfigPreset(cni.PresetDevelopment)

	// Enable all efficient monitors
	config.UseEBPF = true
	config.UseInotify = true
	config.UseK8sInformer = false // Skip K8s for this test

	// Focus on process and file monitoring for the test
	config.EnableLogMonitoring = false
	config.EnableProcessMonitoring = true
	config.EnableEventMonitoring = false
	config.EnableFileMonitoring = true

	fmt.Printf("\nConfiguration:\n")
	fmt.Printf("- eBPF enabled: %v\n", config.UseEBPF)
	fmt.Printf("- Inotify enabled: %v\n", config.UseInotify)
	fmt.Printf("- Process monitoring: %v\n", config.EnableProcessMonitoring)
	fmt.Printf("- File monitoring: %v\n", config.EnableFileMonitoring)

	// Create collector
	collector, err := cni.NewCNICollector(config)
	if err != nil {
		log.Fatalf("Failed to create collector: %v", err)
	}

	// Start collector
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("\nStarting collector...")
	if err := collector.Start(ctx); err != nil {
		log.Fatalf("Failed to start collector: %v", err)
	}

	// Monitor events
	go func() {
		eventCount := 0
		for event := range collector.Events() {
			eventCount++
			printEvent(eventCount, &event)
		}
	}()

	// Monitor health
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				health := collector.Health()
				fmt.Printf("\n[Health] Status: %v\n", health.Status())

				stats := collector.Statistics()
				fmt.Printf("[Stats] Events collected: %d, dropped: %d\n",
					stats.EventsCollected, stats.EventsDropped)
			}
		}
	}()

	// Create a test namespace to trigger eBPF events
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("\n🧪 Creating test network namespace to trigger eBPF events...")

		cmd := "sudo ip netns add test-cni-monitor 2>/dev/null && " +
			"sudo ip link add veth-test type veth peer name veth-peer 2>/dev/null && " +
			"sleep 2 && " +
			"sudo ip link delete veth-test 2>/dev/null && " +
			"sudo ip netns delete test-cni-monitor 2>/dev/null"

		if err := runCommand(cmd); err != nil {
			fmt.Printf("Test command failed: %v\n", err)
		}
	}()

	// Create a test CNI config file to trigger inotify
	go func() {
		time.Sleep(10 * time.Second)
		fmt.Println("\n🧪 Creating test CNI config to trigger inotify events...")

		testConfig := `{
			"cniVersion": "0.3.1",
			"name": "test-network",
			"type": "bridge",
			"bridge": "cni-test0",
			"ipam": {
				"type": "host-local",
				"subnet": "10.99.0.0/16"
			}
		}`

		// Try to write to /tmp as a test location
		testPath := "/tmp/test-cni.conf"
		if err := os.WriteFile(testPath, []byte(testConfig), 0644); err != nil {
			fmt.Printf("Failed to write test config: %v\n", err)
		} else {
			fmt.Printf("Created test config at %s\n", testPath)

			// Modify it after 2 seconds
			time.Sleep(2 * time.Second)
			testConfig = testConfig + "\n// Modified"
			os.WriteFile(testPath, []byte(testConfig), 0644)

			// Delete it after another 2 seconds
			time.Sleep(2 * time.Second)
			os.Remove(testPath)
		}
	}()

	// Wait for interrupt
	fmt.Println("\n✅ Collector is running. Press Ctrl+C to stop.")
	fmt.Println("📊 Waiting for CNI events...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n\nShutting down...")
	cancel()

	if err := collector.Stop(); err != nil {
		log.Printf("Error stopping collector: %v", err)
	}

	// Print final statistics
	stats := collector.Statistics()
	fmt.Printf("\nFinal Statistics:\n")
	fmt.Printf("- Total events collected: %d\n", stats.EventsCollected)
	fmt.Printf("- Events dropped: %d\n", stats.EventsDropped)
	fmt.Printf("- CNI operations: %d\n", stats.CNIOperationsTotal)
	fmt.Printf("- Monitoring errors: %d\n", stats.MonitoringErrors)
}

func printEvent(count int, event *domain.UnifiedEvent) {
	fmt.Printf("\n[Event #%d] %s\n", count, time.Now().Format("15:04:05"))
	fmt.Printf("  ID: %s\n", event.ID)
	fmt.Printf("  Type: %s\n", event.Type)
	fmt.Printf("  Source: %s\n", event.Source)
	fmt.Printf("  Category: %s\n", event.Category)
	fmt.Printf("  Severity: %s\n", event.Severity)

	// Print message if available
	if event.Message != "" {
		fmt.Printf("  Message: %s\n", event.Message)
	}

	// Print network data if CNI-related
	if event.Network != nil {
		fmt.Printf("  Network Data Available - Protocol: %s\n", event.Network.Protocol)
		if event.Network.SourceIP != "" {
			fmt.Printf("    Source: %s:%d\n", event.Network.SourceIP, event.Network.SourcePort)
		}
	}

	// Print tags (will contain monitor type and plugin info)
	if len(event.Tags) > 0 {
		fmt.Printf("  Tags: %v\n", event.Tags)
	}
}

// Helper to run shell commands
func runCommand(cmd string) error {
	c := exec.Command("sh", "-c", cmd)
	return c.Run()
}
