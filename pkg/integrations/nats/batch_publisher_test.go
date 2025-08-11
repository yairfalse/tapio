package nats

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/yairfalse/tapio/pkg/collectors"
	"github.com/yairfalse/tapio/pkg/domain"
)

// mockEventPublisher implements EventPublisher interface for testing
type mockEventPublisher struct {
	rawEventCount     int64
	unifiedEventCount int64
	publishDelay      time.Duration
	publishError      error
	mu                sync.RWMutex
	publishedRawEvents     []collectors.RawEvent
	publishedUnifiedEvents []*domain.UnifiedEvent
}

func (m *mockEventPublisher) PublishRawEvent(ctx context.Context, event collectors.RawEvent) error {
	if m.publishDelay > 0 {
		time.Sleep(m.publishDelay)
	}
	
	if m.publishError != nil {
		return m.publishError
	}

	atomic.AddInt64(&m.rawEventCount, 1)
	
	m.mu.Lock()
	m.publishedRawEvents = append(m.publishedRawEvents, event)
	m.mu.Unlock()
	
	return nil
}

func (m *mockEventPublisher) PublishUnifiedEvent(ctx context.Context, event *domain.UnifiedEvent) error {
	if m.publishDelay > 0 {
		time.Sleep(m.publishDelay)
	}
	
	if m.publishError != nil {
		return m.publishError
	}

	atomic.AddInt64(&m.unifiedEventCount, 1)
	
	m.mu.Lock()
	m.publishedUnifiedEvents = append(m.publishedUnifiedEvents, event)
	m.mu.Unlock()
	
	return nil
}

func (m *mockEventPublisher) Close() error {
	return nil
}

func (m *mockEventPublisher) HealthCheck() error {
	return nil
}

func (m *mockEventPublisher) GetRawEventCount() int64 {
	return atomic.LoadInt64(&m.rawEventCount)
}

func (m *mockEventPublisher) GetUnifiedEventCount() int64 {
	return atomic.LoadInt64(&m.unifiedEventCount)
}

func (m *mockEventPublisher) GetPublishedRawEvents() []collectors.RawEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]collectors.RawEvent, len(m.publishedRawEvents))
	copy(result, m.publishedRawEvents)
	return result
}

func (m *mockEventPublisher) GetPublishedUnifiedEvents() []*domain.UnifiedEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*domain.UnifiedEvent, len(m.publishedUnifiedEvents))
	copy(result, m.publishedUnifiedEvents)
	return result
}

func createTestRawEvent(id string) collectors.RawEvent {
	return collectors.RawEvent{
		ID:        id,
		Type:      "test",
		Source:    "test-collector",
		Timestamp: time.Now(),
		Data:      []byte(fmt.Sprintf(`{"id":"%s"}`, id)),
		Metadata:  map[string]string{"test": "true"},
	}
}

func createTestUnifiedEvent(id string) *domain.UnifiedEvent {
	return &domain.UnifiedEvent{
		ID:        id,
		Type:      domain.EventTypeResource,
		Source:    "test-source",
		Timestamp: time.Now(),
		Severity:  domain.EventSeverityInfo,
		Message:   fmt.Sprintf("Test event %s", id),
	}
}

func TestNewBatchEventPublisher(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockPublisher := &mockEventPublisher{}

	t.Run("successful creation", func(t *testing.T) {
		config := BatchConfig{
			BatchSize:     50,
			BatchTimeout:  200 * time.Millisecond,
			WorkerCount:   5,
			ChannelBuffer: 500,
		}

		bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
		require.NoError(t, err)
		require.NotNil(t, bp)

		assert.Equal(t, 50, bp.config.BatchSize)
		assert.Equal(t, 200*time.Millisecond, bp.config.BatchTimeout)
		assert.Equal(t, 5, bp.config.WorkerCount)
		assert.Equal(t, 500, bp.config.ChannelBuffer)
	})

	t.Run("nil publisher fails", func(t *testing.T) {
		config := BatchConfig{}
		bp, err := NewBatchEventPublisher(nil, config, logger)
		require.Error(t, err)
		assert.Nil(t, bp)
		assert.Contains(t, err.Error(), "publisher cannot be nil")
	})

	t.Run("nil logger fails", func(t *testing.T) {
		config := BatchConfig{}
		bp, err := NewBatchEventPublisher(mockPublisher, config, nil)
		require.Error(t, err)
		assert.Nil(t, bp)
		assert.Contains(t, err.Error(), "logger cannot be nil")
	})

	t.Run("default config values", func(t *testing.T) {
		config := BatchConfig{} // Empty config should get defaults

		bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
		require.NoError(t, err)

		assert.Equal(t, DefaultBatchSize, bp.config.BatchSize)
		assert.Equal(t, DefaultBatchTimeout, bp.config.BatchTimeout)
		assert.Equal(t, DefaultWorkerCount, bp.config.WorkerCount)
		assert.Equal(t, DefaultChannelBuffer, bp.config.ChannelBuffer)
	})

	t.Run("invalid config values", func(t *testing.T) {
		config := BatchConfig{
			BatchSize: 20000, // Too large
		}

		bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
		require.Error(t, err)
		assert.Nil(t, bp)
		assert.Contains(t, err.Error(), "batch size too large")
	})
}

func TestBatchEventPublisher_StartStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockPublisher := &mockEventPublisher{}
	config := BatchConfig{
		BatchSize:     10,
		BatchTimeout:  100 * time.Millisecond,
		WorkerCount:   2,
		ChannelBuffer: 100,
	}

	bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("successful start", func(t *testing.T) {
		err := bp.Start(ctx)
		require.NoError(t, err)

		// Wait a moment for workers to start
		time.Sleep(50 * time.Millisecond)

		// Verify started state
		stats := bp.Stats()
		assert.True(t, stats["started"].(bool))
		assert.False(t, stats["closed"].(bool))
	})

	t.Run("double start fails", func(t *testing.T) {
		err := bp.Start(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already started")
	})

	t.Run("successful close", func(t *testing.T) {
		err := bp.Close()
		require.NoError(t, err)

		// Verify closed state
		stats := bp.Stats()
		assert.True(t, stats["closed"].(bool))
	})

	t.Run("double close is safe", func(t *testing.T) {
		err := bp.Close()
		require.NoError(t, err) // Should not error
	})
}

func TestBatchEventPublisher_PublishRawEvents(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockPublisher := &mockEventPublisher{}
	config := BatchConfig{
		BatchSize:     5, // Small batch size for testing
		BatchTimeout:  500 * time.Millisecond,
		WorkerCount:   2,
		ChannelBuffer: 100,
	}

	bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = bp.Start(ctx)
	require.NoError(t, err)
	defer bp.Close()

	t.Run("batch size trigger", func(t *testing.T) {
		// Reset mock counter
		atomic.StoreInt64(&mockPublisher.rawEventCount, 0)

		// Publish exactly batch size events
		events := make([]collectors.RawEvent, config.BatchSize)
		for i := 0; i < config.BatchSize; i++ {
			events[i] = createTestRawEvent(fmt.Sprintf("batch-event-%d", i))
			err := bp.PublishRawEventAsync(events[i])
			require.NoError(t, err)
		}

		// Wait for batch to be processed
		require.Eventually(t, func() bool {
			return mockPublisher.GetRawEventCount() == int64(config.BatchSize)
		}, 2*time.Second, 50*time.Millisecond, "Events should be published when batch size reached")

		// Verify all events were published
		publishedEvents := mockPublisher.GetPublishedRawEvents()
		assert.Len(t, publishedEvents, config.BatchSize)
	})

	t.Run("timeout trigger", func(t *testing.T) {
		// Reset mock counter
		atomic.StoreInt64(&mockPublisher.rawEventCount, 0)
		mockPublisher.mu.Lock()
		mockPublisher.publishedRawEvents = nil
		mockPublisher.mu.Unlock()

		// Publish fewer than batch size events
		partialBatchSize := config.BatchSize - 2
		for i := 0; i < partialBatchSize; i++ {
			event := createTestRawEvent(fmt.Sprintf("timeout-event-%d", i))
			err := bp.PublishRawEventAsync(event)
			require.NoError(t, err)
		}

		// Wait for timeout to trigger batch processing
		require.Eventually(t, func() bool {
			return mockPublisher.GetRawEventCount() == int64(partialBatchSize)
		}, config.BatchTimeout+time.Second, 50*time.Millisecond, "Events should be published when timeout reached")

		// Verify partial batch was published
		publishedEvents := mockPublisher.GetPublishedRawEvents()
		assert.Len(t, publishedEvents, partialBatchSize)
	})
}

func TestBatchEventPublisher_PublishUnifiedEvents(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockPublisher := &mockEventPublisher{}
	config := BatchConfig{
		BatchSize:     3, // Small batch size for testing
		BatchTimeout:  500 * time.Millisecond,
		WorkerCount:   2,
		ChannelBuffer: 100,
	}

	bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = bp.Start(ctx)
	require.NoError(t, err)
	defer bp.Close()

	t.Run("mixed event types in batch", func(t *testing.T) {
		// Reset mock counters
		atomic.StoreInt64(&mockPublisher.rawEventCount, 0)
		atomic.StoreInt64(&mockPublisher.unifiedEventCount, 0)
		mockPublisher.mu.Lock()
		mockPublisher.publishedRawEvents = nil
		mockPublisher.publishedUnifiedEvents = nil
		mockPublisher.mu.Unlock()

		// Publish mixed event types to fill batch
		rawEvent := createTestRawEvent("mixed-raw-1")
		err := bp.PublishRawEventAsync(rawEvent)
		require.NoError(t, err)

		unifiedEvent1 := createTestUnifiedEvent("mixed-unified-1")
		err = bp.PublishUnifiedEventAsync(unifiedEvent1)
		require.NoError(t, err)

		unifiedEvent2 := createTestUnifiedEvent("mixed-unified-2")
		err = bp.PublishUnifiedEventAsync(unifiedEvent2)
		require.NoError(t, err)

		// Wait for batch to be processed (batch size = 3, so should trigger immediately)
		require.Eventually(t, func() bool {
			return mockPublisher.GetRawEventCount() == 1 && mockPublisher.GetUnifiedEventCount() == 2
		}, 2*time.Second, 50*time.Millisecond, "Mixed batch should be processed")

		// Verify events were published
		publishedRawEvents := mockPublisher.GetPublishedRawEvents()
		publishedUnifiedEvents := mockPublisher.GetPublishedUnifiedEvents()
		
		assert.Len(t, publishedRawEvents, 1)
		assert.Len(t, publishedUnifiedEvents, 2)
		assert.Equal(t, "mixed-raw-1", publishedRawEvents[0].ID)
		assert.Equal(t, "mixed-unified-1", publishedUnifiedEvents[0].ID)
		assert.Equal(t, "mixed-unified-2", publishedUnifiedEvents[1].ID)
	})

	t.Run("nil unified event fails", func(t *testing.T) {
		err := bp.PublishUnifiedEventAsync(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "event cannot be nil")
	})
}

func TestBatchEventPublisher_ConcurrentThroughput(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockPublisher := &mockEventPublisher{
		publishDelay: time.Millisecond, // Add small delay to simulate real publishing
	}
	
	config := BatchConfig{
		BatchSize:     50,
		BatchTimeout:  100 * time.Millisecond,
		WorkerCount:   8, // Multiple workers for concurrency
		ChannelBuffer: 1000,
	}

	bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = bp.Start(ctx)
	require.NoError(t, err)
	defer bp.Close()

	t.Run("high throughput test", func(t *testing.T) {
		// Reset counters
		atomic.StoreInt64(&mockPublisher.rawEventCount, 0)
		atomic.StoreInt64(&mockPublisher.unifiedEventCount, 0)

		const numEvents = 1000
		const numGoroutines = 10
		eventsPerGoroutine := numEvents / numGoroutines

		var wg sync.WaitGroup
		start := time.Now()

		// Launch multiple goroutines to publish events concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < eventsPerGoroutine; j++ {
					eventID := fmt.Sprintf("throughput-%d-%d", goroutineID, j)
					
					if j%2 == 0 {
						// Publish raw event
						event := createTestRawEvent(eventID)
						err := bp.PublishRawEventAsync(event)
						if err != nil {
							t.Logf("Failed to publish raw event %s: %v", eventID, err)
						}
					} else {
						// Publish unified event
						event := createTestUnifiedEvent(eventID)
						err := bp.PublishUnifiedEventAsync(event)
						if err != nil {
							t.Logf("Failed to publish unified event %s: %v", eventID, err)
						}
					}
				}
			}(i)
		}

		wg.Wait()
		publishDuration := time.Since(start)

		// Wait for all events to be processed
		expectedRawEvents := int64(numEvents / 2)
		expectedUnifiedEvents := int64(numEvents / 2)

		require.Eventually(t, func() bool {
			rawCount := mockPublisher.GetRawEventCount()
			unifiedCount := mockPublisher.GetUnifiedEventCount()
			return rawCount == expectedRawEvents && unifiedCount == expectedUnifiedEvents
		}, 10*time.Second, 100*time.Millisecond, "All events should be processed")

		processingDuration := time.Since(start)

		t.Logf("Throughput test results:")
		t.Logf("  Events published: %d", numEvents)
		t.Logf("  Publish duration: %v", publishDuration)
		t.Logf("  Total processing duration: %v", processingDuration)
		t.Logf("  Events/sec (publish): %.0f", float64(numEvents)/publishDuration.Seconds())
		t.Logf("  Events/sec (total): %.0f", float64(numEvents)/processingDuration.Seconds())

		// Verify performance improvement - should be much faster than sequential
		// With 8 workers and batching, should be significantly faster
		maxExpectedDuration := time.Duration(numEvents) * mockPublisher.publishDelay / 4 // At least 4x improvement
		assert.Less(t, processingDuration, maxExpectedDuration,
			"Concurrent batch processing should be much faster than sequential")
	})
}

func TestBatchEventPublisher_ErrorHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("publisher errors are handled gracefully", func(t *testing.T) {
		mockPublisher := &mockEventPublisher{
			publishError: fmt.Errorf("mock publish error"),
		}
		
		config := BatchConfig{
			BatchSize:     2,
			BatchTimeout:  100 * time.Millisecond,
			WorkerCount:   1,
			ChannelBuffer: 10,
		}

		bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
		require.NoError(t, err)

		ctx := context.Background()
		err = bp.Start(ctx)
		require.NoError(t, err)
		defer bp.Close()

		// Publish events that will trigger errors
		event1 := createTestRawEvent("error-event-1")
		event2 := createTestRawEvent("error-event-2")

		err = bp.PublishRawEventAsync(event1)
		require.NoError(t, err) // Async publish should not fail

		err = bp.PublishRawEventAsync(event2)
		require.NoError(t, err) // Async publish should not fail

		// Wait for processing - errors should be logged but not crash the system
		time.Sleep(500 * time.Millisecond)

		// Batch publisher should still be functional
		stats := bp.Stats()
		assert.False(t, stats["closed"].(bool))
	})

	t.Run("full queue drops events", func(t *testing.T) {
		mockPublisher := &mockEventPublisher{
			publishDelay: 5 * time.Second, // Very slow to fill the queue
		}
		
		config := BatchConfig{
			BatchSize:     100,
			BatchTimeout:  1 * time.Second,
			WorkerCount:   1,
			ChannelBuffer: 5, // Very small buffer
		}

		bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
		require.NoError(t, err)

		ctx := context.Background()
		err = bp.Start(ctx)
		require.NoError(t, err)
		defer bp.Close()

		// Try to publish more events than the buffer can handle
		successCount := 0
		dropCount := 0
		
		for i := 0; i < 20; i++ {
			event := createTestRawEvent(fmt.Sprintf("overflow-event-%d", i))
			err := bp.PublishRawEventAsync(event)
			if err != nil {
				dropCount++
				assert.Contains(t, err.Error(), "event queue full")
			} else {
				successCount++
			}
		}

		t.Logf("Events: %d successful, %d dropped", successCount, dropCount)
		assert.Greater(t, dropCount, 0, "Some events should be dropped due to full queue")
		assert.Equal(t, successCount+dropCount, 20, "All events should be accounted for")
	})
}

func TestBatchEventPublisher_Stats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockPublisher := &mockEventPublisher{}
	config := BatchConfig{
		BatchSize:     10,
		BatchTimeout:  200 * time.Millisecond,
		WorkerCount:   3,
		ChannelBuffer: 50,
	}

	bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
	require.NoError(t, err)

	stats := bp.Stats()
	assert.False(t, stats["started"].(bool))
	assert.False(t, stats["closed"].(bool))
	assert.Equal(t, 0, stats["raw_queue_size"].(int))
	assert.Equal(t, 0, stats["unified_queue_size"].(int))
	assert.Equal(t, 3, stats["worker_count"].(int))
	assert.Equal(t, 10, stats["batch_size"].(int))
	assert.Equal(t, int64(200), stats["batch_timeout_ms"].(int64))
	assert.Equal(t, 50, stats["channel_buffer"].(int))

	ctx := context.Background()
	err = bp.Start(ctx)
	require.NoError(t, err)

	stats = bp.Stats()
	assert.True(t, stats["started"].(bool))
	assert.False(t, stats["closed"].(bool))

	err = bp.Close()
	require.NoError(t, err)

	stats = bp.Stats()
	assert.True(t, stats["closed"].(bool))
}

// Benchmark to measure performance improvement
func BenchmarkBatchEventPublisher(b *testing.B) {
	logger := zaptest.NewLogger(b)

	b.Run("batch_processing", func(b *testing.B) {
		mockPublisher := &mockEventPublisher{
			publishDelay: 100 * time.Microsecond, // Small delay to simulate real work
		}
		
		config := BatchConfig{
			BatchSize:     100,
			BatchTimeout:  50 * time.Millisecond,
			WorkerCount:   8,
			ChannelBuffer: 1000,
		}

		bp, err := NewBatchEventPublisher(mockPublisher, config, logger)
		require.NoError(b, err)

		ctx := context.Background()
		err = bp.Start(ctx)
		require.NoError(b, err)
		defer bp.Close()

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			event := createTestRawEvent(fmt.Sprintf("bench-event-%d", i))
			err := bp.PublishRawEventAsync(event)
			if err != nil {
				b.Fatalf("Failed to publish event: %v", err)
			}
		}

		// Wait for all events to be processed
		require.Eventually(b, func() bool {
			return mockPublisher.GetRawEventCount() == int64(b.N)
		}, 30*time.Second, 100*time.Millisecond, "All benchmark events should be processed")
	})
}