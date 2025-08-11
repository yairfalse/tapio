package nats

import (
	"context"
	"fmt"
	"sync"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/yairfalse/tapio/pkg/collectors"
	"github.com/yairfalse/tapio/pkg/domain"
)

const (
	// DefaultBatchSize is the default number of events to batch together
	DefaultBatchSize = 100
	// DefaultBatchTimeout is the maximum time to wait before publishing a partial batch
	DefaultBatchTimeout = 100 * time.Millisecond
	// DefaultWorkerCount is the number of concurrent batch processing workers
	DefaultWorkerCount = 10
	// DefaultChannelBuffer is the size of the event channel buffer
	DefaultChannelBuffer = 1000
)

// BatchConfig configures batch processing behavior
type BatchConfig struct {
	BatchSize     int           `json:"batch_size"`
	BatchTimeout  time.Duration `json:"batch_timeout"`
	WorkerCount   int           `json:"worker_count"`
	ChannelBuffer int           `json:"channel_buffer"`
}

// eventBatch represents a batch of events to be published
type eventBatch struct {
	rawEvents     []collectors.RawEvent
	unifiedEvents []*domain.UnifiedEvent
	timestamp     time.Time
}

// BatchEventPublisher provides high-throughput event publishing with batching and concurrency
type BatchEventPublisher struct {
	publisher *EventPublisher
	config    BatchConfig
	logger    *zap.Logger

	// Channels for event processing
	rawEventCh     chan collectors.RawEvent
	unifiedEventCh chan *domain.UnifiedEvent
	stopCh         chan struct{}
	doneCh         chan struct{}

	// State management
	mu      sync.RWMutex
	started bool
	closed  bool

	// OpenTelemetry instrumentation
	tracer              trace.Tracer
	batchesProcessed    metric.Int64Counter
	eventsPerBatch      metric.Float64Histogram
	batchProcessingTime metric.Float64Histogram
	queueSize           metric.Int64Gauge
	droppedEvents       metric.Int64Counter
	workerErrors        metric.Int64Counter
}

// NewBatchEventPublisher creates a new batch event publisher
func NewBatchEventPublisher(publisher *EventPublisher, config BatchConfig, logger *zap.Logger) (*BatchEventPublisher, error) {
	if publisher == nil {
		return nil, fmt.Errorf("publisher cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Validate and set defaults for batch configuration
	if err := validateBatchConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid batch config: %w", err)
	}

	// Initialize OpenTelemetry instrumentation
	tracer := otel.Tracer("integrations.nats.batch_publisher")
	meter := otel.Meter("integrations.nats.batch_publisher")

	batchesProcessed, err := meter.Int64Counter(
		"nats_batches_processed_total",
		metric.WithDescription("Total number of batches processed"),
	)
	if err != nil {
		logger.Warn("Failed to create batches processed counter", zap.Error(err))
	}

	eventsPerBatch, err := meter.Float64Histogram(
		"nats_events_per_batch",
		metric.WithDescription("Number of events per batch"),
	)
	if err != nil {
		logger.Warn("Failed to create events per batch histogram", zap.Error(err))
	}

	batchProcessingTime, err := meter.Float64Histogram(
		"nats_batch_processing_duration_ms",
		metric.WithDescription("Batch processing duration in milliseconds"),
	)
	if err != nil {
		logger.Warn("Failed to create batch processing time histogram", zap.Error(err))
	}

	queueSize, err := meter.Int64Gauge(
		"nats_publisher_queue_size",
		metric.WithDescription("Current size of the event queue"),
	)
	if err != nil {
		logger.Warn("Failed to create queue size gauge", zap.Error(err))
	}

	droppedEvents, err := meter.Int64Counter(
		"nats_dropped_events_total",
		metric.WithDescription("Total number of dropped events due to full queue"),
	)
	if err != nil {
		logger.Warn("Failed to create dropped events counter", zap.Error(err))
	}

	workerErrors, err := meter.Int64Counter(
		"nats_worker_errors_total",
		metric.WithDescription("Total number of worker errors"),
	)
	if err != nil {
		logger.Warn("Failed to create worker errors counter", zap.Error(err))
	}

	return &BatchEventPublisher{
		publisher:           publisher,
		config:              config,
		logger:              logger,
		rawEventCh:          make(chan collectors.RawEvent, config.ChannelBuffer),
		unifiedEventCh:      make(chan *domain.UnifiedEvent, config.ChannelBuffer),
		stopCh:              make(chan struct{}),
		doneCh:              make(chan struct{}),
		tracer:              tracer,
		batchesProcessed:    batchesProcessed,
		eventsPerBatch:      eventsPerBatch,
		batchProcessingTime: batchProcessingTime,
		queueSize:           queueSize,
		droppedEvents:       droppedEvents,
		workerErrors:        workerErrors,
	}, nil
}

// validateBatchConfig validates and sets default values for batch configuration
func validateBatchConfig(config *BatchConfig) error {
	if config.BatchSize <= 0 {
		config.BatchSize = DefaultBatchSize
	}
	if config.BatchTimeout <= 0 {
		config.BatchTimeout = DefaultBatchTimeout
	}
	if config.WorkerCount <= 0 {
		config.WorkerCount = DefaultWorkerCount
	}
	if config.ChannelBuffer <= 0 {
		config.ChannelBuffer = DefaultChannelBuffer
	}

	// Validate reasonable limits
	if config.BatchSize > 10000 {
		return fmt.Errorf("batch size too large: %d (max 10000)", config.BatchSize)
	}
	if config.WorkerCount > 100 {
		return fmt.Errorf("worker count too large: %d (max 100)", config.WorkerCount)
	}
	if config.ChannelBuffer > 100000 {
		return fmt.Errorf("channel buffer too large: %d (max 100000)", config.ChannelBuffer)
	}

	return nil
}

// Start begins batch processing workers
func (bp *BatchEventPublisher) Start(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.started {
		return fmt.Errorf("batch publisher already started")
	}
	if bp.closed {
		return fmt.Errorf("batch publisher is closed")
	}

	bp.started = true

	// Start batch processing workers
	for i := 0; i < bp.config.WorkerCount; i++ {
		go bp.batchWorker(ctx, i)
	}

	// Start queue size monitoring
	go bp.queueMonitor(ctx)

	bp.logger.Info("Batch event publisher started",
		zap.Int("worker_count", bp.config.WorkerCount),
		zap.Int("batch_size", bp.config.BatchSize),
		zap.Duration("batch_timeout", bp.config.BatchTimeout))

	return nil
}

// PublishRawEventAsync publishes a raw event asynchronously through batching
func (bp *BatchEventPublisher) PublishRawEventAsync(event collectors.RawEvent) error {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	if bp.closed {
		return fmt.Errorf("batch publisher is closed")
	}
	if !bp.started {
		return fmt.Errorf("batch publisher not started")
	}

	select {
	case bp.rawEventCh <- event:
		return nil
	default:
		// Channel is full, record dropped event
		if bp.droppedEvents != nil {
			bp.droppedEvents.Add(context.Background(), 1, metric.WithAttributes(
				attribute.String("event_type", "raw"),
				attribute.String("drop_reason", "channel_full"),
			))
		}
		return fmt.Errorf("event queue full, event dropped")
	}
}

// PublishUnifiedEventAsync publishes a unified event asynchronously through batching
func (bp *BatchEventPublisher) PublishUnifiedEventAsync(event *domain.UnifiedEvent) error {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	if bp.closed {
		return fmt.Errorf("batch publisher is closed")
	}
	if !bp.started {
		return fmt.Errorf("batch publisher not started")
	}

	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	select {
	case bp.unifiedEventCh <- event:
		return nil
	default:
		// Channel is full, record dropped event
		if bp.droppedEvents != nil {
			bp.droppedEvents.Add(context.Background(), 1, metric.WithAttributes(
				attribute.String("event_type", "unified"),
				attribute.String("drop_reason", "channel_full"),
			))
		}
		return fmt.Errorf("event queue full, event dropped")
	}
}

// batchWorker processes events in batches using timer-based or size-based batching
func (bp *BatchEventPublisher) batchWorker(ctx context.Context, workerID int) {
	defer func() {
		if workerID == 0 {
			// Only first worker signals completion
			close(bp.doneCh)
		}
	}()

	logger := bp.logger.With(zap.Int("worker_id", workerID))
	logger.Debug("Batch worker started")

	batch := &eventBatch{
		rawEvents:     make([]collectors.RawEvent, 0, bp.config.BatchSize),
		unifiedEvents: make([]*domain.UnifiedEvent, 0, bp.config.BatchSize),
		timestamp:     time.Now(),
	}

	batchTimer := time.NewTimer(bp.config.BatchTimeout)
	defer batchTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			// Process remaining batch before exiting
			bp.processBatch(ctx, batch, workerID, "context_cancelled")
			logger.Debug("Batch worker stopped due to context cancellation")
			return

		case <-bp.stopCh:
			// Process remaining batch before exiting
			bp.processBatch(ctx, batch, workerID, "stop_requested")
			logger.Debug("Batch worker stopped")
			return

		case rawEvent := <-bp.rawEventCh:
			batch.rawEvents = append(batch.rawEvents, rawEvent)
			
			// Check if batch is full
			if len(batch.rawEvents)+len(batch.unifiedEvents) >= bp.config.BatchSize {
				bp.processBatch(ctx, batch, workerID, "batch_full")
				batch = bp.resetBatch(batch)
				batchTimer.Reset(bp.config.BatchTimeout)
			}

		case unifiedEvent := <-bp.unifiedEventCh:
			batch.unifiedEvents = append(batch.unifiedEvents, unifiedEvent)
			
			// Check if batch is full
			if len(batch.rawEvents)+len(batch.unifiedEvents) >= bp.config.BatchSize {
				bp.processBatch(ctx, batch, workerID, "batch_full")
				batch = bp.resetBatch(batch)
				batchTimer.Reset(bp.config.BatchTimeout)
			}

		case <-batchTimer.C:
			// Timer expired, process current batch if not empty
			if len(batch.rawEvents) > 0 || len(batch.unifiedEvents) > 0 {
				bp.processBatch(ctx, batch, workerID, "timeout")
				batch = bp.resetBatch(batch)
			}
			batchTimer.Reset(bp.config.BatchTimeout)
		}
	}
}

// processBatch processes a complete batch of events
func (bp *BatchEventPublisher) processBatch(ctx context.Context, batch *eventBatch, workerID int, reason string) {
	if len(batch.rawEvents) == 0 && len(batch.unifiedEvents) == 0 {
		return
	}

	ctx, span := bp.tracer.Start(ctx, "batch_publisher.process_batch")
	defer span.End()

	start := time.Now()
	totalEvents := len(batch.rawEvents) + len(batch.unifiedEvents)

	span.SetAttributes(
		attribute.Int("worker_id", workerID),
		attribute.Int("raw_events_count", len(batch.rawEvents)),
		attribute.Int("unified_events_count", len(batch.unifiedEvents)),
		attribute.Int("total_events", totalEvents),
		attribute.String("batch_reason", reason),
	)

	// Process raw events concurrently
	var wg sync.WaitGroup
	errorCh := make(chan error, totalEvents)

	// Process raw events
	for _, rawEvent := range batch.rawEvents {
		wg.Add(1)
		go func(event collectors.RawEvent) {
			defer wg.Done()
			if err := bp.publisher.PublishRawEvent(ctx, event); err != nil {
				errorCh <- fmt.Errorf("failed to publish raw event: %w", err)
			}
		}(rawEvent)
	}

	// Process unified events
	for _, unifiedEvent := range batch.unifiedEvents {
		wg.Add(1)
		go func(event *domain.UnifiedEvent) {
			defer wg.Done()
			if err := bp.publisher.PublishUnifiedEvent(ctx, event); err != nil {
				errorCh <- fmt.Errorf("failed to publish unified event: %w", err)
			}
		}(unifiedEvent)
	}

	wg.Wait()
	close(errorCh)

	// Count errors
	errorCount := 0
	for err := range errorCh {
		errorCount++
		if bp.workerErrors != nil {
			bp.workerErrors.Add(ctx, 1, metric.WithAttributes(
				attribute.Int("worker_id", workerID),
				attribute.String("error_type", "publish_failed"),
			))
		}
		bp.logger.Warn("Error publishing event in batch", zap.Error(err), zap.Int("worker_id", workerID))
	}

	// Record metrics
	duration := time.Since(start).Seconds() * 1000 // Convert to milliseconds
	
	if bp.batchesProcessed != nil {
		bp.batchesProcessed.Add(ctx, 1, metric.WithAttributes(
			attribute.Int("worker_id", workerID),
			attribute.String("batch_reason", reason),
			attribute.Int("error_count", errorCount),
		))
	}

	if bp.eventsPerBatch != nil {
		bp.eventsPerBatch.Record(ctx, float64(totalEvents), metric.WithAttributes(
			attribute.Int("worker_id", workerID),
			attribute.String("batch_reason", reason),
		))
	}

	if bp.batchProcessingTime != nil {
		bp.batchProcessingTime.Record(ctx, duration, metric.WithAttributes(
			attribute.Int("worker_id", workerID),
			attribute.Int("event_count", totalEvents),
		))
	}

	span.SetAttributes(
		attribute.Int("error_count", errorCount),
		attribute.Float64("duration_ms", duration),
	)

	bp.logger.Debug("Batch processed",
		zap.Int("worker_id", workerID),
		zap.Int("total_events", totalEvents),
		zap.Int("errors", errorCount),
		zap.Float64("duration_ms", duration),
		zap.String("reason", reason))
}

// resetBatch prepares a batch for reuse
func (bp *BatchEventPublisher) resetBatch(batch *eventBatch) *eventBatch {
	batch.rawEvents = batch.rawEvents[:0]
	batch.unifiedEvents = batch.unifiedEvents[:0]
	batch.timestamp = time.Now()
	return batch
}

// queueMonitor periodically reports queue sizes for observability
func (bp *BatchEventPublisher) queueMonitor(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-bp.stopCh:
			return
		case <-ticker.C:
			rawQueueSize := len(bp.rawEventCh)
			unifiedQueueSize := len(bp.unifiedEventCh)
			totalQueueSize := rawQueueSize + unifiedQueueSize

			if bp.queueSize != nil {
				bp.queueSize.Record(ctx, int64(totalQueueSize), metric.WithAttributes(
					attribute.String("queue_type", "total"),
				))
				bp.queueSize.Record(ctx, int64(rawQueueSize), metric.WithAttributes(
					attribute.String("queue_type", "raw_events"),
				))
				bp.queueSize.Record(ctx, int64(unifiedQueueSize), metric.WithAttributes(
					attribute.String("queue_type", "unified_events"),
				))
			}

			if totalQueueSize > bp.config.ChannelBuffer/2 {
				bp.logger.Warn("Event queue getting full",
					zap.Int("raw_queue_size", rawQueueSize),
					zap.Int("unified_queue_size", unifiedQueueSize),
					zap.Int("total_queue_size", totalQueueSize),
					zap.Int("buffer_capacity", bp.config.ChannelBuffer))
			}
		}
	}
}

// Close gracefully shuts down the batch publisher
func (bp *BatchEventPublisher) Close() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.closed {
		return nil
	}

	bp.closed = true
	close(bp.stopCh)

	// Wait for workers to finish processing remaining events
	select {
	case <-bp.doneCh:
		bp.logger.Info("Batch publisher stopped gracefully")
	case <-time.After(30 * time.Second):
		bp.logger.Warn("Timeout waiting for batch publisher to stop")
	}

	return nil
}

// Stats returns current batch publisher statistics
func (bp *BatchEventPublisher) Stats() map[string]interface{} {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	return map[string]interface{}{
		"started":            bp.started,
		"closed":             bp.closed,
		"raw_queue_size":     len(bp.rawEventCh),
		"unified_queue_size": len(bp.unifiedEventCh),
		"worker_count":       bp.config.WorkerCount,
		"batch_size":         bp.config.BatchSize,
		"batch_timeout_ms":   bp.config.BatchTimeout.Milliseconds(),
		"channel_buffer":     bp.config.ChannelBuffer,
	}
}