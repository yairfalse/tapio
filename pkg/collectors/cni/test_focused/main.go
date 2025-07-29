package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni"
	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
)

func main() {
	fmt.Println("🧪 Testing CNI Efficient Monitors")
	fmt.Println("=================================")
	fmt.Println()

	// Quick environment check
	fmt.Println("📋 Environment Check:")
	checkEnvironment()
	fmt.Println()

	// Create minimal config
	config := core.Config{
		Name:                    "test",
		Enabled:                 true,
		EventBufferSize:         100,
		CNIConfPath:             "/tmp",
		EnableFileMonitoring:    true,
		EnableProcessMonitoring: true,
		UseInotify:              true,
		UseEBPF:                 false, // Disable eBPF for simpler test
		EventRateLimit:          100,
	}

	// Create collector
	collector, err := cni.NewCNICollector(config)
	if err != nil {
		log.Fatalf("Failed to create collector: %v", err)
	}

	// Start collector
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		log.Fatalf("Failed to start collector: %v", err)
	}

	fmt.Println("✅ Collector started!")
	fmt.Println()

	// Monitor events
	eventChan := make(chan string, 10)
	go func() {
		for event := range collector.Events() {
			msg := fmt.Sprintf("🎉 Event: Type=%s, Message=%s",
				event.Type, event.Message)
			select {
			case eventChan <- msg:
			default:
			}
		}
	}()

	// Test file operations
	fmt.Println("📁 Testing File Monitor...")
	testFile := "/tmp/test-cni.conf"

	// Create
	fmt.Print("   Creating CNI config... ")
	os.WriteFile(testFile, []byte(`{"type": "bridge", "name": "test-net"}`), 0644)
	fmt.Println("✅")
	time.Sleep(500 * time.Millisecond)

	// Check for events
	select {
	case msg := <-eventChan:
		fmt.Println("   " + msg)
	case <-time.After(100 * time.Millisecond):
		fmt.Println("   (No event captured)")
	}

	// Modify
	fmt.Print("   Modifying CNI config... ")
	os.WriteFile(testFile, []byte(`{"type": "bridge", "name": "modified"}`), 0644)
	fmt.Println("✅")
	time.Sleep(500 * time.Millisecond)

	// Check for events
	select {
	case msg := <-eventChan:
		fmt.Println("   " + msg)
	case <-time.After(100 * time.Millisecond):
		fmt.Println("   (No event captured)")
	}

	// Delete
	fmt.Print("   Deleting CNI config... ")
	os.Remove(testFile)
	fmt.Println("✅")
	time.Sleep(500 * time.Millisecond)

	// Check for events
	select {
	case msg := <-eventChan:
		fmt.Println("   " + msg)
	case <-time.After(100 * time.Millisecond):
		fmt.Println("   (No event captured)")
	}

	// Wait a bit more
	fmt.Println()
	fmt.Println("⏳ Waiting for any remaining events...")
	time.Sleep(2 * time.Second)

	// Drain any remaining events
	eventCount := 0
	for {
		select {
		case msg := <-eventChan:
			eventCount++
			fmt.Println("   " + msg)
		default:
			goto done
		}
	}
done:

	// Stop collector
	collector.Stop()

	// Summary
	fmt.Println()
	fmt.Println("📊 Test Summary:")
	if eventCount > 0 {
		fmt.Printf("   ✅ Captured %d additional events\n", eventCount)
		fmt.Println("   ✅ Efficient monitoring is working!")
	} else {
		fmt.Println("   ⚠️  No events captured")
		fmt.Println("   This could mean:")
		fmt.Println("   • Inotify needs permissions")
		fmt.Println("   • Fallback to polling mode")
		fmt.Println("   • Events are being rate-limited")
	}
	fmt.Println()
	fmt.Println("✅ Test completed!")
}

func checkEnvironment() {
	// Check kernel
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		fmt.Printf("   Kernel: %s", out)
	}

	// Check inotify
	if _, err := os.Stat("/proc/sys/fs/inotify/max_user_watches"); err == nil {
		fmt.Println("   ✅ Inotify available")
	} else {
		fmt.Println("   ❌ Inotify not available")
	}

	// Check /tmp
	if info, err := os.Stat("/tmp"); err == nil && info.IsDir() {
		fmt.Println("   ✅ /tmp directory exists")
	}
}
