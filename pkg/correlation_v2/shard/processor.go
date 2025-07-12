package shard

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/correlation_v2/lockfree"
	"github.com/yairfalse/tapio/pkg/correlation_v2/timeline"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// ProcessingShard handles event processing for a specific shard
type ProcessingShard struct {
	// Shard identification
	id       int
	cpuAffinity int
	
	// Event processing
	eventBuffer  *lockfree.RingBuffer
	timeline     *timeline.CompressedTimeline
	ruleEngine   *ShardRuleEngine
	
	// Processing control
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	
	// Configuration
	config       ShardConfig
	
	// Performance metrics
	eventsProcessed uint64
	processingTime  uint64 // Nanoseconds
	resultsGenerated uint64
	lastProcessedAt time.Time
	
	// Batch processing
	eventBatch   []*events_correlation.Event
	batchSize    int
	batchTimeout time.Duration
	
	// Memory management
	eventPool    *sync.Pool
	
	// Load balancing
	loadMetrics  *LoadMetrics
}

// ShardConfig configures a processing shard
type ShardConfig struct {
	ID                int           `json:"id"`
	CPUAffinity       int           `json:"cpu_affinity"`
	BatchSize         int           `json:"batch_size"`
	BatchTimeout      time.Duration `json:"batch_timeout"`
	TimelineCapacity  int           `json:"timeline_capacity"`
	MaxRules          int           `json:"max_rules"`
	EnableProfiling   bool          `json:"enable_profiling"`
}

// LoadMetrics tracks shard performance metrics
type LoadMetrics struct {
	cpuUsage       uint64  // Percentage * 100
	memoryUsage    uint64  // Bytes
	queueDepth     uint64  // Number of pending events
	throughput     uint64  // Events per second
	latencyP50     uint64  // Nanoseconds
	latencyP99     uint64  // Nanoseconds
	lastUpdate     time.Time
}

// DefaultShardConfig returns optimized default configuration
func DefaultShardConfig(id int) ShardConfig {
	return ShardConfig{
		ID:               id,
		CPUAffinity:      id % runtime.NumCPU(),
		BatchSize:        256,
		BatchTimeout:     10 * time.Millisecond,
		TimelineCapacity: 100000,
		MaxRules:         100,
		EnableProfiling:  false,
	}
}

// NewProcessingShard creates a new processing shard
func NewProcessingShard(eventBuffer *lockfree.RingBuffer, config ShardConfig) *ProcessingShard {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create compressed timeline
	timelineConfig := timeline.DefaultTimelineConfig()
	timelineConfig.Capacity = config.TimelineCapacity
	timelineConfig.CompressionLevel = timeline.CompressionHigh
	compressedTimeline := timeline.NewCompressedTimeline(timelineConfig)
	
	// Create rule engine
	ruleEngine := NewShardRuleEngine(config.MaxRules)
	
	shard := &ProcessingShard{
		id:           config.ID,
		cpuAffinity:  config.CPUAffinity,
		eventBuffer:  eventBuffer,
		timeline:     compressedTimeline,
		ruleEngine:   ruleEngine,
		ctx:          ctx,
		cancel:       cancel,
		config:       config,
		eventBatch:   make([]*events_correlation.Event, config.BatchSize),
		batchSize:    config.BatchSize,
		batchTimeout: config.BatchTimeout,
		loadMetrics:  &LoadMetrics{},
	}
	
	// Initialize object pools
	shard.initializePools()
	
	return shard
}

// initializePools creates object pools for zero-allocation processing
func (ps *ProcessingShard) initializePools() {
	ps.eventPool = &sync.Pool{
		New: func() interface{} {
			return &events_correlation.Event{}
		},
	}
}

// Start begins processing events for this shard
func (ps *ProcessingShard) Start() error {
	// Set CPU affinity if supported
	if ps.config.CPUAffinity >= 0 {
		ps.setCPUAffinity(ps.config.CPUAffinity)
	}
	
	// Start processing goroutine
	ps.wg.Add(1)
	go ps.processEvents()
	
	// Start metrics collection
	ps.wg.Add(1)
	go ps.collectMetrics()
	
	return nil
}

// processEvents is the main event processing loop
func (ps *ProcessingShard) processEvents() {
	defer ps.wg.Done()
	
	ticker := time.NewTicker(ps.batchTimeout)
	defer ticker.Stop()
	
	batchIndex := 0
	
	for {
		select {
		case <-ps.ctx.Done():
			// Process any remaining events in batch
			if batchIndex > 0 {
				ps.processBatch(ps.eventBatch[:batchIndex])
			}
			return
			
		case <-ticker.C:
			// Process batch on timeout
			if batchIndex > 0 {
				ps.processBatch(ps.eventBatch[:batchIndex])
				batchIndex = 0
			}
			
		default:
			// Try to get events from buffer
			eventPtr, ok := ps.eventBuffer.TryPop()
			if !ok {
				// No events available, yield CPU
				runtime.Gosched()
				continue
			}
			
			// Convert back to event
			event := (*events_correlation.Event)(eventPtr)
			ps.eventBatch[batchIndex] = event
			batchIndex++
			
			// Process full batch
			if batchIndex >= ps.batchSize {
				ps.processBatch(ps.eventBatch[:batchIndex])
				batchIndex = 0
			}
		}
	}
}

// processBatch processes a batch of events efficiently
func (ps *ProcessingShard) processBatch(events []*events_correlation.Event) {
	start := time.Now()
	defer func() {
		// Update processing metrics
		elapsed := uint64(time.Since(start).Nanoseconds())
		atomic.AddUint64(&ps.processingTime, elapsed)
		atomic.AddUint64(&ps.eventsProcessed, uint64(len(events)))
		ps.lastProcessedAt = time.Now()
	}()
	
	// Add events to timeline
	for _, event := range events {
		ps.timeline.AddEvent(*event)
	}
	
	// Create correlation context
	correlationWindow := events_correlation.TimeWindow{
		Start: time.Now().Add(-5 * time.Minute),
		End:   time.Now(),
	}
	
	// Get relevant events from timeline
	timelineEvents := ps.timeline.GetEventsInWindow(correlationWindow)
	
	// Create correlation context with events
	ctx := events_correlation.NewContext(correlationWindow, timelineEvents)
	
	// Execute rules on the batch
	results := ps.ruleEngine.ProcessBatch(ctx, events)
	
	// Update results metrics
	atomic.AddUint64(&ps.resultsGenerated, uint64(len(results)))
	
	// TODO: Send results to output channel or handler
	_ = results
}

// collectMetrics periodically collects performance metrics
func (ps *ProcessingShard) collectMetrics() {
	defer ps.wg.Done()
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ps.ctx.Done():
			return
		case <-ticker.C:
			ps.updateLoadMetrics()
		}
	}
}

// updateLoadMetrics updates the load metrics for this shard
func (ps *ProcessingShard) updateLoadMetrics() {
	// Update queue depth
	queueDepth := ps.eventBuffer.Size()
	atomic.StoreUint64(&ps.loadMetrics.queueDepth, queueDepth)
	
	// Calculate throughput (events per second)
	now := time.Now()
	if !ps.loadMetrics.lastUpdate.IsZero() {
		elapsed := now.Sub(ps.loadMetrics.lastUpdate).Seconds()
		if elapsed > 0 {
			eventsProcessed := atomic.LoadUint64(&ps.eventsProcessed)
			throughput := uint64(float64(eventsProcessed) / elapsed)
			atomic.StoreUint64(&ps.loadMetrics.throughput, throughput)
		}
	}
	ps.loadMetrics.lastUpdate = now
	
	// Update memory usage (approximate)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	atomic.StoreUint64(&ps.loadMetrics.memoryUsage, memStats.Alloc/uint64(runtime.NumCPU()))
}

// setCPUAffinity sets CPU affinity for this goroutine (platform-specific)
func (ps *ProcessingShard) setCPUAffinity(cpu int) {
	// This would use platform-specific syscalls in a real implementation
	// For now, we'll just use GOMAXPROCS as a hint
	runtime.LockOSThread()
}

// Stop gracefully stops the processing shard
func (ps *ProcessingShard) Stop() error {
	ps.cancel()
	ps.wg.Wait()
	return nil
}

// Stats returns comprehensive shard statistics
func (ps *ProcessingShard) Stats() ShardStats {
	eventsProcessed := atomic.LoadUint64(&ps.eventsProcessed)
	processingTime := atomic.LoadUint64(&ps.processingTime)
	resultsGenerated := atomic.LoadUint64(&ps.resultsGenerated)
	
	stats := ShardStats{
		ID:               ps.id,
		EventsProcessed:  eventsProcessed,
		ResultsGenerated: resultsGenerated,
		QueueDepth:       atomic.LoadUint64(&ps.loadMetrics.queueDepth),
		Throughput:       atomic.LoadUint64(&ps.loadMetrics.throughput),
		MemoryUsage:      atomic.LoadUint64(&ps.loadMetrics.memoryUsage),
		LastProcessedAt:  ps.lastProcessedAt,
	}
	
	// Calculate average processing time
	if eventsProcessed > 0 {
		stats.AvgProcessingTimeNs = processingTime / eventsProcessed
	}
	
	// Get buffer statistics
	stats.BufferStats = ps.eventBuffer.Stats()
	
	// Get timeline statistics
	stats.TimelineStats = ps.timeline.Stats()
	
	return stats
}

// ShardStats contains comprehensive shard performance metrics
type ShardStats struct {
	ID                   int                        `json:"id"`
	EventsProcessed      uint64                     `json:"events_processed"`
	ResultsGenerated     uint64                     `json:"results_generated"`
	AvgProcessingTimeNs  uint64                     `json:"avg_processing_time_ns"`
	QueueDepth           uint64                     `json:"queue_depth"`
	Throughput           uint64                     `json:"throughput"`
	MemoryUsage          uint64                     `json:"memory_usage"`
	LastProcessedAt      time.Time                  `json:"last_processed_at"`
	BufferStats          lockfree.RingBufferStats   `json:"buffer_stats"`
	TimelineStats        timeline.TimelineStats     `json:"timeline_stats"`
}

// GetLoadScore returns a load score for load balancing (0.0 = no load, 1.0 = maximum load)
func (ps *ProcessingShard) GetLoadScore() float64 {
	// Combine multiple metrics for load score
	queueLoad := float64(ps.loadMetrics.queueDepth) / float64(ps.eventBuffer.Capacity())
	
	// CPU load approximation based on processing time
	cpuLoad := 0.0
	if ps.loadMetrics.throughput > 0 {
		avgProcessingTime := float64(atomic.LoadUint64(&ps.processingTime)) / float64(atomic.LoadUint64(&ps.eventsProcessed))
		cpuLoad = avgProcessingTime / float64(time.Millisecond) // Normalize to milliseconds
	}
	
	// Weighted combination
	return (queueLoad * 0.7) + (cpuLoad * 0.3)
}

// IsHealthy returns true if the shard is operating normally
func (ps *ProcessingShard) IsHealthy() bool {
	// Check if processing is stuck
	timeSinceLastProcess := time.Since(ps.lastProcessedAt)
	if timeSinceLastProcess > 30*time.Second && ps.eventBuffer.Size() > 0 {
		return false
	}
	
	// Check if queue is severely backed up
	if ps.eventBuffer.Stats().Utilization > 0.95 {
		return false
	}
	
	return true
}

// Reset clears all metrics and state
func (ps *ProcessingShard) Reset() {
	atomic.StoreUint64(&ps.eventsProcessed, 0)
	atomic.StoreUint64(&ps.processingTime, 0)
	atomic.StoreUint64(&ps.resultsGenerated, 0)
	ps.lastProcessedAt = time.Time{}
	
	ps.timeline.Reset()
	ps.eventBuffer.Reset()
}

// RegisterRule registers a rule with the shard's rule engine
func (ps *ProcessingShard) RegisterRule(rule *events_correlation.Rule) error {
	return ps.ruleEngine.RegisterRule(rule)
}