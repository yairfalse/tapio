package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni"
)

func main() {
	fmt.Println("Simple CNI Collector Test")
	fmt.Println("========================")

	// Create simple config
	config := cni.GetConfigPreset(cni.PresetMinimal)
	config.EnableFileMonitoring = true
	config.UseInotify = true
	config.UseEBPF = false      // Disable eBPF for now
	config.CNIConfPath = "/tmp" // Watch /tmp for testing

	fmt.Println("\nStarting collector...")

	collector, err := cni.NewCNICollector(config)
	if err != nil {
		log.Fatalf("Failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		log.Fatalf("Failed to start collector: %v", err)
	}

	fmt.Println("✅ Collector started! Monitoring /tmp for CNI config files...")
	fmt.Println("📊 Waiting for events...")

	// Monitor events
	eventCount := 0
	go func() {
		for event := range collector.Events() {
			eventCount++
			fmt.Printf("\n🎉 Event #%d captured!\n", eventCount)
			fmt.Printf("   Type: %s\n", event.Type)
			fmt.Printf("   Source: %s\n", event.Source)
			fmt.Printf("   Message: %s\n", event.Message)
		}
	}()

	// Wait for timeout
	<-ctx.Done()

	fmt.Printf("\n\n📈 Test completed. Events captured: %d\n", eventCount)

	collector.Stop()
}
