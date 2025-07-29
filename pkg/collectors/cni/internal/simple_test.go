package internal

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterBasic(t *testing.T) {
	limiter := NewRateLimiter(10) // 10 events per second

	// Should allow first event
	if !limiter.Allow(context.Background()) {
		t.Error("Expected first event to be allowed")
	}

	// Quick burst should be limited
	allowed := 0
	for i := 0; i < 20; i++ {
		if limiter.Allow(context.Background()) {
			allowed++
		}
	}

	// Should have allowed approximately 10 (bucket size)
	if allowed < 5 || allowed > 15 {
		t.Errorf("Expected ~10 allowed events, got %d", allowed)
	}

	t.Log("✅ Rate limiter working correctly!")
}

func TestCircuitBreakerBasic(t *testing.T) {
	cb := NewCircuitBreaker("test", 2, 1*time.Second)

	// Should start closed
	if cb.state != StateCircuitClosed {
		t.Error("Circuit breaker should start closed")
	}

	t.Log("✅ Circuit breaker initialized correctly!")
}

func TestBackpressureControllerBasic(t *testing.T) {
	bc := NewBackpressureController(100, 0.8, 0.5)

	// Should start accepting
	if !bc.ShouldAccept() {
		t.Error("Should accept events when buffer is empty")
	}

	// Simulate high load
	for i := 0; i < 85; i++ {
		bc.RecordEvent()
	}

	// Check metrics
	metrics := bc.GetMetrics()
	if metrics.EventsProcessed != 85 {
		t.Errorf("Expected 85 events processed, got %d", metrics.EventsProcessed)
	}

	t.Log("✅ Backpressure controller working correctly!")
}

func TestResourceMonitorBasic(t *testing.T) {
	config := ResourceLimits{
		MaxMemoryMB:   100,
		MaxGoroutines: 50,
		MaxCPUPercent: 80,
		CheckInterval: 100 * time.Millisecond,
	}

	rm := NewResourceMonitor(config)

	// Start and immediately stop
	ctx, cancel := context.WithCancel(context.Background())
	rm.Start(ctx)

	// Let it run briefly
	time.Sleep(200 * time.Millisecond)
	cancel()

	// Check we got some metrics
	metrics := rm.GetMetrics()
	if metrics.MemoryUsageMB == 0 {
		t.Error("Expected non-zero memory usage")
	}
	if metrics.GoroutineCount == 0 {
		t.Error("Expected non-zero goroutine count")
	}

	t.Logf("✅ Resource monitor working! Memory: %.2f MB, Goroutines: %d",
		metrics.MemoryUsageMB, metrics.GoroutineCount)
}
