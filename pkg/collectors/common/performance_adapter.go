package common

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/performance"
)

// PerformanceConfig configures the performance adapter for collectors
type PerformanceConfig struct {
	// Buffer size for the ring buffer (must be power of 2)
	BufferSize uint64
	// Number of events to batch before processing
	BatchSize int
	// Maximum time to wait before processing a partial batch
	BatchTimeout time.Duration
	// Enable zero-copy operations
	EnableZeroCopy bool
	// Collector name for metrics
	CollectorName string
}

// DefaultPerformanceConfig returns default configuration optimized for each collector
func DefaultPerformanceConfig(collectorName string) PerformanceConfig {
	switch collectorName {
	case "ebpf":
		return PerformanceConfig{
			BufferSize:     131072, // 128k for high-volume eBPF
			BatchSize:      1000,
			BatchTimeout:   10 * time.Millisecond,
			EnableZeroCopy: true,
			CollectorName:  collectorName,
		}
	case "k8s":
		return PerformanceConfig{
			BufferSize:     16384, // 16k for moderate K8s events
			BatchSize:      100,
			BatchTimeout:   50 * time.Millisecond,
			EnableZeroCopy: true,
			CollectorName:  collectorName,
		}
	case "cni":
		return PerformanceConfig{
			BufferSize:     32768, // 32k for CNI events
			BatchSize:      200,
			BatchTimeout:   25 * time.Millisecond,
			EnableZeroCopy: true,
			CollectorName:  collectorName,
		}
	case "systemd":
		return PerformanceConfig{
			BufferSize:     32768, // 32k for systemd logs
			BatchSize:      200,
			BatchTimeout:   25 * time.Millisecond,
			EnableZeroCopy: true,
			CollectorName:  collectorName,
		}
	default:
		return PerformanceConfig{
			BufferSize:     65536, // 64k default
			BatchSize:      500,
			BatchTimeout:   20 * time.Millisecond,
			EnableZeroCopy: true,
			CollectorName:  collectorName,
		}
	}
}

// PerformanceAdapter provides high-performance event handling for collectors
type PerformanceAdapter struct {
	config PerformanceConfig

	// Performance components
	buffer    *performance.EventBatchBuffer
	eventPool *performance.UnifiedEventPool
	bytePool  *performance.ByteSlicePool

	// Output channel for compatibility with existing code
	outputChan chan domain.UnifiedEvent

	// Processing control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	eventsProcessed  atomic.Uint64
	eventsDropped    atomic.Uint64
	batchesProcessed atomic.Uint64

	// State
	running atomic.Bool
	mu      sync.RWMutex
}

// NewPerformanceAdapter creates a new performance adapter for collectors
func NewPerformanceAdapter(config PerformanceConfig) (*PerformanceAdapter, error) {
	// Validate config
	if config.BufferSize == 0 || (config.BufferSize&(config.BufferSize-1)) != 0 {
		return nil, fmt.Errorf("buffer size must be a power of 2, got %d", config.BufferSize)
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	if config.BatchTimeout <= 0 {
		config.BatchTimeout = 20 * time.Millisecond
	}

	// Create performance components
	buffer, err := performance.NewEventBatchBuffer(config.BufferSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create event buffer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	adapter := &PerformanceAdapter{
		config:     config,
		buffer:     buffer,
		eventPool:  performance.NewUnifiedEventPool(),
		bytePool:   performance.NewByteSlicePool(),
		outputChan: make(chan domain.UnifiedEvent, config.BatchSize*2),
		ctx:        ctx,
		cancel:     cancel,
	}

	return adapter, nil
}

// Start begins the performance adapter processing
func (pa *PerformanceAdapter) Start() error {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	if pa.running.Load() {
		return fmt.Errorf("performance adapter already running")
	}

	pa.running.Store(true)
	pa.wg.Add(1)
	go pa.processBatches()

	return nil
}

// Stop gracefully shuts down the performance adapter
func (pa *PerformanceAdapter) Stop() error {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	if !pa.running.Load() {
		return nil
	}

	pa.running.Store(false)
	pa.cancel()
	pa.wg.Wait()
	close(pa.outputChan)

	return nil
}

// Submit adds an event to the high-performance buffer
func (pa *PerformanceAdapter) Submit(event *domain.UnifiedEvent) error {
	if !pa.running.Load() {
		return fmt.Errorf("performance adapter not running")
	}

	// Try to put the event in the buffer
	if !pa.buffer.TryPut(event) {
		pa.eventsDropped.Add(1)
		return fmt.Errorf("buffer full, event dropped")
	}

	pa.eventsProcessed.Add(1)
	return nil
}

// SubmitBatch adds multiple events to the buffer efficiently
func (pa *PerformanceAdapter) SubmitBatch(events []*domain.UnifiedEvent) (int, error) {
	if !pa.running.Load() {
		return 0, fmt.Errorf("performance adapter not running")
	}

	added, err := pa.buffer.PutBatch(events)
	if err != nil {
		dropped := len(events) - added
		pa.eventsDropped.Add(uint64(dropped))
	}
	pa.eventsProcessed.Add(uint64(added))

	return added, err
}

// GetEvent retrieves an event from the pool (for zero-copy operations)
func (pa *PerformanceAdapter) GetEvent() *domain.UnifiedEvent {
	return pa.eventPool.Get()
}

// PutEvent returns an event to the pool
func (pa *PerformanceAdapter) PutEvent(event *domain.UnifiedEvent) {
	pa.eventPool.Put(event)
}

// GetBytes retrieves a byte slice from the pool
func (pa *PerformanceAdapter) GetBytes(size int) []byte {
	return pa.bytePool.Get(size)
}

// PutBytes returns a byte slice to the pool
func (pa *PerformanceAdapter) PutBytes(data []byte) {
	pa.bytePool.Put(data)
}

// Events returns the output channel for processed events
func (pa *PerformanceAdapter) Events() <-chan domain.UnifiedEvent {
	return pa.outputChan
}

// GetMetrics returns current performance metrics
func (pa *PerformanceAdapter) GetMetrics() PerformanceMetrics {
	stats := pa.buffer.GetStats()
	poolStats := pa.eventPool.GetStats()

	return PerformanceMetrics{
		EventsProcessed:   pa.eventsProcessed.Load(),
		EventsDropped:     pa.eventsDropped.Load(),
		BatchesProcessed:  pa.batchesProcessed.Load(),
		BufferSize:        uint64(stats.Size),
		BufferCapacity:    uint64(stats.Capacity),
		BufferUtilization: float64(stats.Size) / float64(stats.Capacity),
		PoolAllocated:     poolStats.Allocated,
		PoolRecycled:      poolStats.Recycled,
		PoolInUse:         poolStats.InUse,
	}
}

// processBatches handles batch processing of events
func (pa *PerformanceAdapter) processBatches() {
	defer pa.wg.Done()

	batch := make([]*domain.UnifiedEvent, pa.config.BatchSize)
	ticker := time.NewTicker(pa.config.BatchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-pa.ctx.Done():
			// Drain remaining events
			pa.drainBuffer(batch)
			return
		case <-ticker.C:
			// Process partial batch on timeout
			pa.processPendingBatch(batch)
		default:
			// Try to get a full batch
			events, err := pa.buffer.GetBatch(len(batch))
			if err != nil {
				// Buffer might be empty, wait a bit
				time.Sleep(time.Millisecond)
				continue
			}
			if len(events) > 0 {
				pa.processBatch(events)
				pa.batchesProcessed.Add(1)
			}
		}
	}
}

// processBatch sends events to the output channel
func (pa *PerformanceAdapter) processBatch(events []*domain.UnifiedEvent) {
	for _, event := range events {
		if event == nil {
			continue
		}

		select {
		case pa.outputChan <- *event:
			// Event sent successfully
		case <-pa.ctx.Done():
			return
		default:
			// Output channel full, drop event
			pa.eventsDropped.Add(1)
		}

		// Return event to pool if zero-copy is enabled
		if pa.config.EnableZeroCopy {
			pa.eventPool.Put(event)
		}
	}
}

// processPendingBatch processes any pending events on timeout
func (pa *PerformanceAdapter) processPendingBatch(batch []*domain.UnifiedEvent) {
	events, _ := pa.buffer.GetBatch(len(batch))
	if len(events) > 0 {
		pa.processBatch(events)
		pa.batchesProcessed.Add(1)
	}
}

// drainBuffer processes all remaining events during shutdown
func (pa *PerformanceAdapter) drainBuffer(batch []*domain.UnifiedEvent) {
	for {
		events, err := pa.buffer.GetBatch(len(batch))
		if err != nil || len(events) == 0 {
			break
		}
		pa.processBatch(events)
	}
}

// PerformanceMetrics contains performance statistics
type PerformanceMetrics struct {
	EventsProcessed   uint64
	EventsDropped     uint64
	BatchesProcessed  uint64
	BufferSize        uint64
	BufferCapacity    uint64
	BufferUtilization float64
	PoolAllocated     int64
	PoolRecycled      int64
	PoolInUse         int64
}
