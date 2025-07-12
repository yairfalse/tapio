package correlation_v2

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/events_correlation"
	"github.com/yairfalse/tapio/pkg/events_correlation/rules"
)

// BenchmarkEventIngestion benchmarks pure event ingestion performance
func BenchmarkEventIngestion(b *testing.B) {
	config := DefaultEngineConfig()
	config.NumShards = runtime.NumCPU()
	config.BufferSize = 65536
	
	engine := NewHighPerformanceEngine(config)
	
	// Create test events
	events := generateTestEvents(1000)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	b.RunParallel(func(pb *testing.PB) {
		eventIndex := 0
		for pb.Next() {
			event := events[eventIndex%len(events)]
			engine.ProcessEvent(event)
			eventIndex++
		}
	})
	
	engine.Stop()
}

// BenchmarkFullPipeline benchmarks the complete correlation pipeline
func BenchmarkFullPipeline(b *testing.B) {
	config := DefaultEngineConfig()
	config.NumShards = runtime.NumCPU()
	
	engine := NewHighPerformanceEngine(config)
	
	// Register some test rules
	memoryRule := rules.MemoryPressureCascade()
	cpuRule := rules.CPUThrottleDetection()
	
	engine.RegisterRule(memoryRule)
	engine.RegisterRule(cpuRule)
	
	// Start the engine
	engine.Start()
	defer engine.Stop()
	
	// Create test events
	events := generateTestEvents(1000)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	b.RunParallel(func(pb *testing.PB) {
		eventIndex := 0
		for pb.Next() {
			event := events[eventIndex%len(events)]
			engine.ProcessEvent(event)
			eventIndex++
		}
	})
}

// BenchmarkBatchProcessing benchmarks batch event processing
func BenchmarkBatchProcessing(b *testing.B) {
	config := DefaultEngineConfig()
	engine := NewHighPerformanceEngine(config)
	
	engine.Start()
	defer engine.Stop()
	
	// Create batches of events
	batchSize := 100
	events := generateTestEvents(batchSize)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		engine.ProcessBatch(events)
	}
}

// BenchmarkMemoryAllocation benchmarks memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	config := DefaultEngineConfig()
	config.EnableGCOptimization = true
	
	engine := NewHighPerformanceEngine(config)
	
	events := generateTestEvents(100)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		for _, event := range events {
			engine.ProcessEvent(event)
		}
	}
	
	engine.Stop()
}

// BenchmarkConcurrentLoad benchmarks performance under high concurrency
func BenchmarkConcurrentLoad(b *testing.B) {
	config := DefaultEngineConfig()
	config.NumShards = runtime.NumCPU() * 2 // More shards for higher concurrency
	
	engine := NewHighPerformanceEngine(config)
	engine.Start()
	defer engine.Stop()
	
	events := generateTestEvents(1000)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	// Use many goroutines to simulate high load
	concurrency := runtime.NumCPU() * 4
	var wg sync.WaitGroup
	
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			eventsPerGoroutine := b.N / concurrency
			eventIndex := goroutineID * 13 // Offset to avoid cache alignment
			
			for j := 0; j < eventsPerGoroutine; j++ {
				event := events[eventIndex%len(events)]
				engine.ProcessEvent(event)
				eventIndex++
			}
		}(i)
	}
	
	wg.Wait()
}

// BenchmarkRuleExecution benchmarks rule execution performance
func BenchmarkRuleExecution(b *testing.B) {
	// Test different numbers of rules
	ruleCounts := []int{1, 10, 50, 100}
	
	for _, ruleCount := range ruleCounts {
		b.Run(fmt.Sprintf("Rules_%d", ruleCount), func(b *testing.B) {
			config := DefaultEngineConfig()
			engine := NewHighPerformanceEngine(config)
			
			// Register test rules
			for i := 0; i < ruleCount; i++ {
				rule := createTestRule(fmt.Sprintf("test-rule-%d", i))
				engine.RegisterRule(rule)
			}
			
			engine.Start()
			defer engine.Stop()
			
			events := generateTestEvents(100)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				for _, event := range events {
					engine.ProcessEvent(event)
				}
			}
		})
	}
}

// BenchmarkThroughput measures sustained throughput
func BenchmarkThroughput(b *testing.B) {
	config := DefaultEngineConfig()
	engine := NewHighPerformanceEngine(config)
	
	engine.Start()
	defer engine.Stop()
	
	events := generateTestEvents(1000)
	
	// Measure throughput over time
	duration := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	eventCount := int64(0)
	var wg sync.WaitGroup
	
	// Start multiple producers
	producers := runtime.NumCPU()
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func(producerID int) {
			defer wg.Done()
			
			eventIndex := producerID * 17 // Offset for cache diversity
			for {
				select {
				case <-ctx.Done():
					return
				default:
					event := events[eventIndex%len(events)]
					if engine.ProcessEvent(event) {
						eventCount++
					}
					eventIndex++
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	throughput := float64(eventCount) / duration.Seconds()
	b.ReportMetric(throughput, "events/sec")
}

// generateTestEvents creates a set of test events for benchmarking
func generateTestEvents(count int) []*events_correlation.Event {
	events := make([]*events_correlation.Event, count)
	
	eventTypes := []string{"memory_pressure", "cpu_throttle", "oom_kill", "network_error", "disk_full"}
	sources := []events_correlation.EventSource{
		events_correlation.SourceEBPF,
		events_correlation.SourceKubernetes,
		events_correlation.SourceSystemd,
	}
	
	for i := 0; i < count; i++ {
		event := &events_correlation.Event{
			ID:        fmt.Sprintf("bench-event-%d", i),
			Timestamp: time.Now().Add(-time.Duration(i) * time.Second),
			Type:      eventTypes[i%len(eventTypes)],
			Source:    sources[i%len(sources)],
			Entity: events_correlation.Entity{
				Type:      "pod",
				Name:      fmt.Sprintf("test-pod-%d", i%50), // 50 different pods
				Namespace: fmt.Sprintf("namespace-%d", i%10), // 10 namespaces
				UID:       fmt.Sprintf("uid-%d", i),
			},
			Attributes: map[string]interface{}{
				"cpu_usage":    float64(50 + (i%50)),
				"memory_usage": float64(1024*1024*512 + (i%1024)*1024*1024),
				"severity":     "medium",
			},
			Fingerprint: fmt.Sprintf("fp-%d", i%100), // 100 different fingerprints
		}
		
		events[i] = event
	}
	
	return events
}

// createTestRule creates a simple test rule for benchmarking
func createTestRule(id string) *events_correlation.Rule {
	return &events_correlation.Rule{
		ID:          id,
		Name:        fmt.Sprintf("Test Rule %s", id),
		Description: "Benchmark test rule",
		Category:    events_correlation.CategoryPerformance,
		Enabled:     true,
		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceEBPF,
			events_correlation.SourceKubernetes,
		},
		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			// Simple rule that triggers on multiple events
			events := ctx.GetEvents(events_correlation.Filter{})
			if len(events) >= 2 {
				return &events_correlation.Result{
					RuleID:      id,
					RuleName:    fmt.Sprintf("Test Rule %s", id),
					Timestamp:   time.Now(),
					Confidence:  0.75,
					Severity:    events_correlation.SeverityMedium,
					Category:    events_correlation.CategoryPerformance,
					Title:       "Test correlation detected",
					Description: "Multiple events detected in test rule",
					Evidence: events_correlation.Evidence{
						Events: events[:2], // Use first 2 events as evidence
					},
				}
			}
			return nil
		},
	}
}

// TestEnginePerformance tests engine performance under various conditions
func TestEnginePerformance(t *testing.T) {
	config := DefaultEngineConfig()
	engine := NewHighPerformanceEngine(config)
	
	// Register test rules
	engine.RegisterRule(rules.MemoryPressureCascade())
	engine.RegisterRule(rules.CPUThrottleDetection())
	
	engine.Start()
	defer engine.Stop()
	
	// Generate load
	events := generateTestEvents(10000)
	
	start := time.Now()
	processed := 0
	
	for _, event := range events {
		if engine.ProcessEvent(event) {
			processed++
		}
	}
	
	elapsed := time.Since(start)
	throughput := float64(processed) / elapsed.Seconds()
	
	t.Logf("Processed %d events in %v (%.2f events/sec)", processed, elapsed, throughput)
	
	// Check engine health
	if !engine.IsHealthy() {
		t.Error("Engine is not healthy after processing events")
	}
	
	// Get engine statistics
	stats := engine.Stats()
	t.Logf("Engine stats: %+v", stats)
	
	// Verify performance targets
	if throughput < 10000 { // Target: 10K+ events/sec
		t.Errorf("Throughput too low: %.2f events/sec (target: 10,000+)", throughput)
	}
	
	if stats.DropRate > 0.01 { // Target: <1% drop rate
		t.Errorf("Drop rate too high: %.2f%% (target: <1%%)", stats.DropRate*100)
	}
}

// TestMemoryUsage validates memory usage patterns
func TestMemoryUsage(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	
	config := DefaultEngineConfig()
	config.EnableGCOptimization = true
	engine := NewHighPerformanceEngine(config)
	
	engine.Start()
	defer engine.Stop()
	
	// Process many events
	events := generateTestEvents(50000)
	for _, event := range events {
		engine.ProcessEvent(event)
	}
	
	runtime.GC()
	runtime.ReadMemStats(&m2)
	
	memoryUsed := m2.Alloc - m1.Alloc
	t.Logf("Memory used: %d bytes (%.2f MB)", memoryUsed, float64(memoryUsed)/(1024*1024))
	
	// Check memory usage against target
	targetMemoryMB := float64(config.MaxMemoryMB)
	actualMemoryMB := float64(memoryUsed) / (1024 * 1024)
	
	if actualMemoryMB > targetMemoryMB {
		t.Errorf("Memory usage too high: %.2f MB (target: %.2f MB)", actualMemoryMB, targetMemoryMB)
	}
}

// TestLatency measures processing latency
func TestLatency(t *testing.T) {
	config := DefaultEngineConfig()
	engine := NewHighPerformanceEngine(config)
	
	engine.Start()
	defer engine.Stop()
	
	// Measure latency for individual events
	event := generateTestEvents(1)[0]
	
	latencies := make([]time.Duration, 1000)
	
	for i := 0; i < 1000; i++ {
		start := time.Now()
		engine.ProcessEvent(event)
		latencies[i] = time.Since(start)
	}
	
	// Calculate percentiles
	// Sort latencies for percentile calculation
	for i := 0; i < len(latencies)-1; i++ {
		for j := 0; j < len(latencies)-i-1; j++ {
			if latencies[j] > latencies[j+1] {
				latencies[j], latencies[j+1] = latencies[j+1], latencies[j]
			}
		}
	}
	
	p50 := latencies[len(latencies)/2]
	p99 := latencies[len(latencies)*99/100]
	
	t.Logf("Latency P50: %v, P99: %v", p50, p99)
	
	// Check latency targets
	if p99 > time.Millisecond {
		t.Errorf("P99 latency too high: %v (target: <1ms)", p99)
	}
}