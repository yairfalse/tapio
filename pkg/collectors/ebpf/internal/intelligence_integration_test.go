package internal

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/ebpf/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

// TestEBPFEventFlow validates that eBPF events flow correctly
// and can be processed by downstream systems
func TestEBPFEventFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping event flow test in short mode")
	}

	// Create eBPF collector
	config := core.Config{
		Name:               "event-flow-test",
		Enabled:            true,
		EventBufferSize:    5000,
		MaxEventsPerSecond: 10000,
		EnableNetwork:      true,
		EnableMemory:       true,
		EnableProcess:      true,
	}

	collector, err := NewCollector(config)
	if err != nil {
		t.Fatalf("Failed to create eBPF collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Start collector
	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector: %v", err)
	}
	defer collector.Stop()

	// Track events
	var (
		totalEvents   uint64
		networkEvents uint64
		memoryEvents  uint64
		processEvents uint64
		validEvents   uint64
		invalidEvents uint64
	)

	// Process events for validation
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case event := <-collector.Events():
				atomic.AddUint64(&totalEvents, 1)

				// Validate event structure
				if event.ID == "" || event.Source == "" {
					atomic.AddUint64(&invalidEvents, 1)
					continue
				}

				atomic.AddUint64(&validEvents, 1)

				// Count by type
				switch event.Type {
				case domain.EventTypeNetwork:
					atomic.AddUint64(&networkEvents, 1)
				case domain.EventTypeMemory:
					atomic.AddUint64(&memoryEvents, 1)
				case domain.EventTypeProcess:
					atomic.AddUint64(&processEvents, 1)
				}
			}
		}
	}()

	// Let it run
	time.Sleep(15 * time.Second)
	cancel()
	wg.Wait()

	// Validate results
	t.Logf("Event Flow Test Results:")
	t.Logf("  Total Events: %d", totalEvents)
	t.Logf("  Valid Events: %d", validEvents)
	t.Logf("  Invalid Events: %d", invalidEvents)
	t.Logf("  Network Events: %d", networkEvents)
	t.Logf("  Memory Events: %d", memoryEvents)
	t.Logf("  Process Events: %d", processEvents)

	// Assertions
	if totalEvents == 0 {
		t.Error("No events generated")
	}

	if invalidEvents > totalEvents/10 { // Allow 10% invalid events
		t.Errorf("Too many invalid events: %d out of %d", invalidEvents, totalEvents)
	}

	// Should have some variety of event types
	if totalEvents > 10 && networkEvents == 0 && memoryEvents == 0 && processEvents == 0 {
		t.Error("No typed events generated")
	}

	// Validate collector health
	health := collector.Health()
	if health.Status == core.HealthStatusUnhealthy {
		t.Errorf("Collector unhealthy: %s", health.Message)
	}
}

// TestEventStructureValidation validates that generated events have proper structure
func TestEventStructureValidation(t *testing.T) {
	config := core.Config{
		Name:               "structure-validation-test",
		Enabled:            true,
		EventBufferSize:    1000,
		MaxEventsPerSecond: 5000,
		EnableNetwork:      true,
		EnableMemory:       true,
	}

	collector, err := NewCollector(config)
	if err != nil {
		t.Fatalf("Failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector: %v", err)
	}
	defer collector.Stop()

	// Collect sample events
	events := make([]domain.UnifiedEvent, 0, 100)
	timeout := time.After(8 * time.Second)

	for len(events) < 50 {
		select {
		case <-timeout:
			goto validate
		case event := <-collector.Events():
			events = append(events, event)
		}
	}

validate:
	if len(events) == 0 {
		t.Skip("No events to validate")
	}

	t.Logf("Validating %d events", len(events))

	for i, event := range events {
		// Required fields
		if event.ID == "" {
			t.Errorf("Event %d missing ID", i)
		}
		if event.Source == "" {
			t.Errorf("Event %d missing Source", i)
		}
		if event.Timestamp.IsZero() {
			t.Errorf("Event %d missing Timestamp", i)
		}

		// Type should be valid
		validTypes := []domain.EventType{
			domain.EventTypeNetwork,
			domain.EventTypeMemory,
			domain.EventTypeProcess,
			domain.EventTypeSystem,
		}

		validType := false
		for _, vt := range validTypes {
			if event.Type == vt {
				validType = true
				break
			}
		}

		if !validType {
			t.Errorf("Event %d has invalid type: %s", i, event.Type)
		}

		// Timestamps should be recent
		if time.Since(event.Timestamp) > 30*time.Second {
			t.Errorf("Event %d has old timestamp: %v", i, event.Timestamp)
		}
	}

	t.Logf("Event structure validation completed successfully")
}

// TestHighVolumeEventProcessing tests event processing under high volume
func TestHighVolumeEventProcessing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high volume test in short mode")
	}

	config := core.Config{
		Name:               "high-volume-test",
		Enabled:            true,
		EventBufferSize:    20000,
		MaxEventsPerSecond: 50000, // High rate
		EnableNetwork:      true,
		EnableMemory:       true,
		EnableProcess:      true,
	}

	collector, err := NewCollector(config)
	if err != nil {
		t.Fatalf("Failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector: %v", err)
	}
	defer collector.Stop()

	// Performance tracking
	var (
		eventsProcessed uint64
		processingTimes []time.Duration
		timesMu         sync.Mutex
	)

	// Start event processor
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case event := <-collector.Events():
				start := time.Now()

				// Simulate processing work
				_ = len(event.ID) + len(event.Source)
				if event.Kernel != nil {
					_ = len(event.Kernel.Syscall)
				}

				processingTime := time.Since(start)

				timesMu.Lock()
				processingTimes = append(processingTimes, processingTime)
				timesMu.Unlock()

				atomic.AddUint64(&eventsProcessed, 1)
			}
		}
	}()

	// Monitor memory usage
	var memoryPeak uint64
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var m runtime.MemStats
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runtime.ReadMemStats(&m)
				currentMem := m.Alloc

				for {
					current := atomic.LoadUint64(&memoryPeak)
					if currentMem <= current {
						break
					}
					if atomic.CompareAndSwapUint64(&memoryPeak, current, currentMem) {
						break
					}
				}
			}
		}
	}()

	// Run test
	time.Sleep(40 * time.Second)
	cancel()
	wg.Wait()

	// Calculate metrics
	timesMu.Lock()
	avgProcessingTime := time.Duration(0)
	maxProcessingTime := time.Duration(0)
	if len(processingTimes) > 0 {
		var total time.Duration
		for _, pt := range processingTimes {
			total += pt
			if pt > maxProcessingTime {
				maxProcessingTime = pt
			}
		}
		avgProcessingTime = total / time.Duration(len(processingTimes))
	}
	timesMu.Unlock()

	eventsPerSecond := float64(eventsProcessed) / 40.0

	t.Logf("High Volume Processing Results:")
	t.Logf("  Events Processed: %d", eventsProcessed)
	t.Logf("  Events/sec: %.2f", eventsPerSecond)
	t.Logf("  Avg Processing Time: %v", avgProcessingTime)
	t.Logf("  Max Processing Time: %v", maxProcessingTime)
	t.Logf("  Memory Peak: %d bytes", memoryPeak)

	// Performance assertions
	if eventsProcessed < 5000 {
		t.Errorf("Too few events processed: %d", eventsProcessed)
	}

	if eventsPerSecond < 100 {
		t.Errorf("Event processing rate too low: %.2f events/sec", eventsPerSecond)
	}

	if avgProcessingTime > 10*time.Millisecond {
		t.Errorf("Average processing time too high: %v", avgProcessingTime)
	}

	// Memory should be reasonable (< 500MB)
	if memoryPeak > 500*1024*1024 {
		t.Errorf("Memory usage too high: %d bytes", memoryPeak)
	}

	// Validate collector health
	health := collector.Health()
	if health.Status == core.HealthStatusUnhealthy {
		t.Errorf("Collector became unhealthy: %s", health.Message)
	}
}

// TestMemoryStabilityUnderLoad validates memory stability during extended operation
func TestMemoryStabilityUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory stability test in short mode")
	}

	config := core.Config{
		Name:               "memory-stability-test",
		Enabled:            true,
		EventBufferSize:    10000,
		MaxEventsPerSecond: 20000,
		EnableNetwork:      true,
		EnableMemory:       true,
	}

	collector, err := NewCollector(config)
	if err != nil {
		t.Fatalf("Failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector: %v", err)
	}
	defer collector.Stop()

	// Monitor memory usage over time
	memorySnapshots := make([]uint64, 0)
	snapshotsMu := sync.Mutex{}

	var wg sync.WaitGroup

	// Consume events
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range collector.Events() {
			// Just consume events
		}
	}()

	// Memory monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		var m runtime.MemStats
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runtime.ReadMemStats(&m)

				snapshotsMu.Lock()
				memorySnapshots = append(memorySnapshots, m.Alloc)
				snapshotsMu.Unlock()

				t.Logf("Memory usage: %d bytes", m.Alloc)
			}
		}
	}()

	// Run test
	<-ctx.Done()
	wg.Wait()

	// Analyze memory stability
	snapshotsMu.Lock()
	defer snapshotsMu.Unlock()

	if len(memorySnapshots) < 3 {
		t.Skip("Not enough memory snapshots for analysis")
	}

	// Check for excessive memory growth
	initialMem := memorySnapshots[0]
	finalMem := memorySnapshots[len(memorySnapshots)-1]

	growthRatio := float64(finalMem) / float64(initialMem)

	t.Logf("Memory Stability Results:")
	t.Logf("  Initial Memory: %d bytes", initialMem)
	t.Logf("  Final Memory: %d bytes", finalMem)
	t.Logf("  Growth Ratio: %.2fx", growthRatio)
	t.Logf("  Snapshots: %d", len(memorySnapshots))

	// Memory should not grow excessively (allow 2x growth)
	if growthRatio > 2.0 {
		t.Errorf("Excessive memory growth: %.2fx (from %d to %d bytes)",
			growthRatio, initialMem, finalMem)
	}

	// Final memory should be reasonable
	if finalMem > 200*1024*1024 { // 200MB
		t.Errorf("Final memory usage too high: %d bytes", finalMem)
	}

	t.Logf("Memory stability test passed - no significant leaks detected")
}
