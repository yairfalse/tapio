package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

func TestInotifyFileMonitor(t *testing.T) {
	// Skip if not on Linux
	if _, err := os.Stat("/proc/sys/fs/inotify"); os.IsNotExist(err) {
		t.Skip("Inotify not available on this system")
	}

	// Create test directory
	testDir := "/tmp/cni-test-" + time.Now().Format("20060102150405")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create config
	config := core.Config{
		CNIConfPath: testDir,
		UseInotify:  true,
	}

	// Create monitor
	monitor, err := NewInotifyFileMonitor(config)
	if err != nil {
		t.Fatalf("Failed to create inotify monitor: %v", err)
	}

	// Start monitor
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan domain.UnifiedEvent, 10)
	if err := monitor.Start(ctx, events); err != nil {
		t.Fatalf("Failed to start monitor: %v", err)
	}

	// Test file operations
	testFile := testDir + "/test.conflist"

	// Create file
	if err := os.WriteFile(testFile, []byte(`{"name": "test"}`), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wait for event
	select {
	case event := <-events:
		t.Logf("✅ Received create event: %s", event.Message)
		if event.Category != "cni" {
			t.Errorf("Expected CNI category, got: %s", event.Category)
		}
	case <-time.After(2 * time.Second):
		t.Error("❌ Timeout waiting for create event")
	}

	// Modify file
	if err := os.WriteFile(testFile, []byte(`{"name": "modified"}`), 0644); err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}

	// Wait for event
	select {
	case event := <-events:
		t.Logf("✅ Received modify event: %s", event.Message)
	case <-time.After(2 * time.Second):
		t.Error("❌ Timeout waiting for modify event")
	}

	// Delete file
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("Failed to delete test file: %v", err)
	}

	// Wait for event
	select {
	case event := <-events:
		t.Logf("✅ Received delete event: %s", event.Message)
	case <-time.After(2 * time.Second):
		t.Error("❌ Timeout waiting for delete event")
	}

	// Stop monitor
	monitor.Stop()
	t.Log("✅ Inotify monitor test completed successfully!")
}

func TestProcessMonitorFallback(t *testing.T) {
	// Create config with process monitoring
	config := core.Config{
		CNIBinPath: "/tmp/test-cni-bin",
		UseEBPF:    false, // Force process monitor
	}

	// Create monitor (will use process monitor as fallback)
	monitor, err := NewProcessMonitor(config)
	if err != nil {
		t.Fatalf("Failed to create process monitor: %v", err)
	}

	// Basic validation
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	events := make(chan domain.UnifiedEvent, 10)
	if err := monitor.Start(ctx, events); err != nil {
		t.Logf("Process monitor start error (expected): %v", err)
	}

	monitor.Stop()
	t.Log("✅ Process monitor fallback test completed!")
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(10) // 10 events per second

	// Should allow first 10 events
	allowed := 0
	for i := 0; i < 15; i++ {
		if limiter.Allow(context.Background()) {
			allowed++
		}
	}

	if allowed != 10 {
		t.Errorf("Expected 10 allowed events, got %d", allowed)
	}

	// Wait and try again
	time.Sleep(1100 * time.Millisecond)

	if !limiter.Allow(context.Background()) {
		t.Error("Expected event to be allowed after waiting")
	}

	t.Log("✅ Rate limiter test completed!")
}

func TestCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker("test", 2, 1*time.Second)

	// First two calls should succeed
	err1 := cb.Call(func() error { return nil })
	err2 := cb.Call(func() error { return nil })

	if err1 != nil || err2 != nil {
		t.Error("Expected successful calls")
	}

	// Next two calls fail
	cb.Call(func() error { return os.ErrNotExist })
	cb.Call(func() error { return os.ErrNotExist })

	// Circuit should be open now
	err := cb.Call(func() error { return nil })
	if err != ErrCircuitBreakerOpen {
		t.Error("Expected circuit breaker to be open")
	}

	t.Log("✅ Circuit breaker test completed!")
}
