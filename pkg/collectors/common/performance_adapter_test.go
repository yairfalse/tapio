package common

import (
	"sync"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
)

func TestPerformanceAdapter(t *testing.T) {
	t.Run("CreateAdapter", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}
		defer adapter.Stop()

		if adapter.buffer == nil {
			t.Error("Expected buffer to be initialized")
		}
		if adapter.eventPool == nil {
			t.Error("Expected event pool to be initialized")
		}
	})

	t.Run("InvalidBufferSize", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		config.BufferSize = 1023 // Not power of 2
		_, err := NewPerformanceAdapter(config)
		if err == nil {
			t.Error("Expected error for non-power-of-2 buffer size")
		}
	})

	t.Run("StartStop", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}

		// Start adapter
		if err := adapter.Start(); err != nil {
			t.Fatalf("Failed to start adapter: %v", err)
		}

		// Try to start again
		if err := adapter.Start(); err == nil {
			t.Error("Expected error when starting already running adapter")
		}

		// Stop adapter
		if err := adapter.Stop(); err != nil {
			t.Fatalf("Failed to stop adapter: %v", err)
		}

		// Stop again should be safe
		if err := adapter.Stop(); err != nil {
			t.Error("Expected no error when stopping already stopped adapter")
		}
	})

	t.Run("SubmitEvent", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		config.BufferSize = 1024
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}
		defer adapter.Stop()

		if err := adapter.Start(); err != nil {
			t.Fatalf("Failed to start adapter: %v", err)
		}

		// Submit event
		event := adapter.GetEvent()
		event.ID = domain.GenerateEventID()
		event.Type = "test"
		event.Timestamp = time.Now()

		if err := adapter.Submit(event); err != nil {
			t.Fatalf("Failed to submit event: %v", err)
		}

		// Check metrics
		metrics := adapter.GetMetrics()
		if metrics.EventsProcessed != 1 {
			t.Errorf("Expected 1 event processed, got %d", metrics.EventsProcessed)
		}
	})

	t.Run("BatchSubmit", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		config.BufferSize = 1024
		config.BatchSize = 10
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}
		defer adapter.Stop()

		if err := adapter.Start(); err != nil {
			t.Fatalf("Failed to start adapter: %v", err)
		}

		// Create batch of events
		events := make([]*domain.UnifiedEvent, 20)
		for i := range events {
			event := adapter.GetEvent()
			event.ID = domain.GenerateEventID()
			event.Type = "batch-test"
			event.Timestamp = time.Now()
			events[i] = event
		}

		// Submit batch
		added, err := adapter.SubmitBatch(events)
		if err != nil {
			t.Fatalf("Failed to submit batch: %v", err)
		}
		if added != 20 {
			t.Errorf("Expected 20 events added, got %d", added)
		}

		// Check metrics
		metrics := adapter.GetMetrics()
		if metrics.EventsProcessed != 20 {
			t.Errorf("Expected 20 events processed, got %d", metrics.EventsProcessed)
		}
	})

	t.Run("EventFlow", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		config.BufferSize = 1024
		config.BatchSize = 5
		config.BatchTimeout = 10 * time.Millisecond
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}
		defer adapter.Stop()

		if err := adapter.Start(); err != nil {
			t.Fatalf("Failed to start adapter: %v", err)
		}

		// Submit events
		numEvents := 10
		for i := 0; i < numEvents; i++ {
			event := adapter.GetEvent()
			event.ID = domain.GenerateEventID()
			event.Type = "flow-test"
			event.Timestamp = time.Now()
			if err := adapter.Submit(event); err != nil {
				t.Fatalf("Failed to submit event %d: %v", i, err)
			}
		}

		// Receive events
		received := 0
		timeout := time.After(100 * time.Millisecond)
		for received < numEvents {
			select {
			case <-adapter.Events():
				received++
			case <-timeout:
				t.Fatalf("Timeout waiting for events, received %d/%d", received, numEvents)
			}
		}

		if received != numEvents {
			t.Errorf("Expected %d events, received %d", numEvents, received)
		}
	})

	t.Run("BufferOverflow", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		config.BufferSize = 16 // Very small buffer
		config.BatchSize = 1
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}
		defer adapter.Stop()

		if err := adapter.Start(); err != nil {
			t.Fatalf("Failed to start adapter: %v", err)
		}

		// Block processing by not reading from output channel
		// Submit more events than buffer can hold
		submitted := 0
		dropped := 0
		for i := 0; i < 32; i++ {
			event := adapter.GetEvent()
			event.ID = domain.GenerateEventID()
			if err := adapter.Submit(event); err != nil {
				dropped++
			} else {
				submitted++
			}
		}

		// Give some time for events to be processed
		time.Sleep(50 * time.Millisecond)

		// Drain events to make room
		drained := 0
		done := time.After(100 * time.Millisecond)
	drainLoop:
		for {
			select {
			case <-adapter.Events():
				drained++
			case <-done:
				break drainLoop
			}
		}

		// Some events should have been dropped
		if dropped == 0 {
			t.Error("Expected some events to be dropped due to buffer overflow")
		}

		metrics := adapter.GetMetrics()
		// Due to concurrent processing, the exact number might vary
		if metrics.EventsDropped == 0 {
			t.Error("Expected some events to be dropped, but metrics show 0")
		}
	})

	t.Run("ConcurrentSubmit", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		config.BufferSize = 4096
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}
		defer adapter.Stop()

		if err := adapter.Start(); err != nil {
			t.Fatalf("Failed to start adapter: %v", err)
		}

		// Multiple goroutines submitting events
		var wg sync.WaitGroup
		numGoroutines := 10
		eventsPerGoroutine := 100

		for g := 0; g < numGoroutines; g++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for i := 0; i < eventsPerGoroutine; i++ {
					event := adapter.GetEvent()
					event.ID = domain.GenerateEventID()
					event.Type = "concurrent"
					adapter.Submit(event)
				}
			}(g)
		}

		// Consume events
		go func() {
			for range adapter.Events() {
				// Drain events
			}
		}()

		wg.Wait()
		time.Sleep(50 * time.Millisecond) // Allow batch processing to complete

		metrics := adapter.GetMetrics()
		// Due to the async nature and potential drops, we should process at least some events
		minExpected := uint64(100) // At least 100 events should be processed
		if metrics.EventsProcessed < minExpected {
			t.Errorf("Expected at least %d events processed, got %d",
				minExpected, metrics.EventsProcessed)
		}
	})

	t.Run("ZeroCopyMode", func(t *testing.T) {
		config := DefaultPerformanceConfig("test")
		config.EnableZeroCopy = true
		config.BufferSize = 1024
		adapter, err := NewPerformanceAdapter(config)
		if err != nil {
			t.Fatalf("Failed to create adapter: %v", err)
		}
		defer adapter.Stop()

		if err := adapter.Start(); err != nil {
			t.Fatalf("Failed to start adapter: %v", err)
		}

		// Get event from pool
		event := adapter.GetEvent()
		originalID := domain.GenerateEventID()
		event.ID = originalID
		event.Type = "zero-copy"

		// Submit event
		if err := adapter.Submit(event); err != nil {
			t.Fatalf("Failed to submit event: %v", err)
		}

		// Receive event
		select {
		case receivedEvent := <-adapter.Events():
			if receivedEvent.ID != originalID {
				t.Errorf("Expected event ID %s, got %s", originalID, receivedEvent.ID)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Timeout waiting for event")
		}

		// Check pool metrics
		poolStats := adapter.eventPool.GetStats()
		if poolStats.Recycled == 0 {
			t.Error("Expected events to be recycled in zero-copy mode")
		}
	})
}

func BenchmarkPerformanceAdapter(b *testing.B) {
	b.Run("Submit", func(b *testing.B) {
		config := DefaultPerformanceConfig("bench")
		config.BufferSize = 65536
		adapter, _ := NewPerformanceAdapter(config)
		adapter.Start()
		defer adapter.Stop()

		// Drain events in background
		go func() {
			for range adapter.Events() {
			}
		}()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			event := adapter.GetEvent()
			event.ID = domain.GenerateEventID()
			adapter.Submit(event)
		}
	})

	b.Run("BatchSubmit", func(b *testing.B) {
		config := DefaultPerformanceConfig("bench")
		config.BufferSize = 65536
		adapter, _ := NewPerformanceAdapter(config)
		adapter.Start()
		defer adapter.Stop()

		// Drain events in background
		go func() {
			for range adapter.Events() {
			}
		}()

		// Prepare batch
		batchSize := 100
		events := make([]*domain.UnifiedEvent, batchSize)
		for i := range events {
			events[i] = adapter.GetEvent()
			events[i].ID = domain.GenerateEventID()
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			adapter.SubmitBatch(events)
		}
	})
}
