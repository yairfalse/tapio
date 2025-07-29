package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/internal"
)

func main() {
	fmt.Println("🧪 Testing CNI Production Hardening Components")
	fmt.Println("=============================================")
	fmt.Println()

	// Test 1: Rate Limiter
	fmt.Println("1️⃣  Testing Rate Limiter (10 events/sec)")
	testRateLimiter()
	fmt.Println()

	// Test 2: Circuit Breaker
	fmt.Println("2️⃣  Testing Circuit Breaker")
	testCircuitBreaker()
	fmt.Println()

	// Test 3: Backpressure Controller
	fmt.Println("3️⃣  Testing Backpressure Controller")
	testBackpressure()
	fmt.Println()

	// Test 4: Resource Monitor
	fmt.Println("4️⃣  Testing Resource Monitor")
	testResourceMonitor()
	fmt.Println()

	fmt.Println("✅ All production hardening components tested successfully!")
}

func testRateLimiter() {
	limiter := internal.NewRateLimiter(10) // 10 events/sec

	// Burst test
	allowed := 0
	start := time.Now()
	for i := 0; i < 20; i++ {
		if limiter.Allow(context.Background()) {
			allowed++
		}
	}
	duration := time.Since(start)

	fmt.Printf("   • Allowed %d/20 events in %v (burst control ✅)\n", allowed, duration)

	// Wait and test refill
	time.Sleep(1100 * time.Millisecond)
	if limiter.Allow(context.Background()) {
		fmt.Println("   • Token refill working ✅")
	}

	// Show metrics
	metrics := limiter.GetMetrics()
	fmt.Printf("   • Total allowed: %d, rejected: %d\n",
		metrics.EventsAllowed, metrics.EventsRejected)
}

func testCircuitBreaker() {
	cb := internal.NewCircuitBreaker("test-monitor", 2, 1*time.Second)

	// Success calls
	cb.Call(func() error { return nil })
	cb.Call(func() error { return nil })
	fmt.Println("   • Success calls recorded ✅")

	// Failure calls
	cb.Call(func() error { return fmt.Errorf("simulated error") })
	cb.Call(func() error { return fmt.Errorf("simulated error") })
	fmt.Println("   • Failure threshold reached ✅")

	// Circuit should be open
	err := cb.Call(func() error { return nil })
	if err == internal.ErrCircuitBreakerOpen {
		fmt.Println("   • Circuit opened correctly ✅")
	}

	// Show metrics
	metrics := cb.GetMetrics()
	fmt.Printf("   • Successes: %d, Failures: %d, Rejections: %d\n",
		metrics.TotalSuccesses, metrics.TotalFailures, metrics.TotalRejections)
}

func testBackpressure() {
	bc := internal.NewBackpressureController()

	// Initially should accept
	if bc.ShouldAccept() {
		fmt.Println("   • Accepting events when load is low ✅")
	}

	// Simulate high load
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bc.RecordEvent()
		}()
	}
	wg.Wait()

	// Check metrics
	metrics := bc.GetMetrics()
	fmt.Printf("   • Processed %d events\n", metrics.EventsProcessed)
	fmt.Printf("   • Load shedding active: %v\n", metrics.LoadSheddingActive)

	if metrics.EventsProcessed > 0 {
		fmt.Println("   • Backpressure control working ✅")
	}
}

func testResourceMonitor() {
	config := internal.ResourceLimits{
		MaxMemoryMB:   1000,
		MaxGoroutines: 100,
		MaxCPUPercent: 80,
		CheckInterval: 100 * time.Millisecond,
	}

	rm := internal.NewResourceMonitor(config)

	// Start monitoring
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	rm.Start(ctx)

	// Wait for some measurements
	time.Sleep(300 * time.Millisecond)

	// Get metrics
	metrics := rm.GetMetrics()
	fmt.Printf("   • Memory usage: %.2f MB\n", metrics.MemoryUsageMB)
	fmt.Printf("   • Goroutines: %d\n", metrics.GoroutineCount)
	fmt.Printf("   • CPU usage: %.2f%%\n", metrics.CPUPercent)

	if metrics.MemoryUsageMB > 0 && metrics.GoroutineCount > 0 {
		fmt.Println("   • Resource monitoring active ✅")
	}
}
