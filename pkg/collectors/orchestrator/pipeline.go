package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors"
	"github.com/yairfalse/tapio/pkg/domain"
	"go.uber.org/zap"
)

// New creates a new collector orchestrator
func New(logger *zap.Logger, config Config) (*CollectorOrchestrator, error) {
	// Validate and set defaults for worker count
	if config.Workers <= 0 {
		logger.Warn("Invalid worker count, using default", zap.Int("provided", config.Workers), zap.Int("default", 4))
		config.Workers = DefaultConfig().Workers
	} else if config.Workers > 64 {
		logger.Warn("Worker count too high, capping at maximum", zap.Int("provided", config.Workers), zap.Int("maximum", 64))
		config.Workers = 64
	}

	// Validate and set defaults for buffer size
	if config.BufferSize <= 0 {
		logger.Warn("Invalid buffer size, using default", zap.Int("provided", config.BufferSize), zap.Int("default", 10000))
		config.BufferSize = DefaultConfig().BufferSize
	} else if config.BufferSize < 100 {
		logger.Warn("Buffer size too small, using minimum", zap.Int("provided", config.BufferSize), zap.Int("minimum", 100))
		config.BufferSize = 100
	} else if config.BufferSize > 100000 {
		logger.Warn("Buffer size too large, capping at maximum", zap.Int("provided", config.BufferSize), zap.Int("maximum", 100000))
		config.BufferSize = 100000
	}

	logger.Info("Creating collector orchestrator",
		zap.Int("workers", config.Workers),
		zap.Int("buffer_size", config.BufferSize),
		zap.String("nats_url", config.NATSConfig.URL))

	// Create enhanced NATS publisher (production-ready with backpressure)
	publisher, err := NewEnhancedNATSPublisher(logger, config.NATSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create NATS publisher: %w", err)
	}

	return &CollectorOrchestrator{
		collectors: make(map[string]collectors.Collector),
		publisher:  publisher,
		logger:     logger,
		eventsChan: make(chan *domain.CollectorEvent, config.BufferSize),
		workers:    config.Workers,
	}, nil
}

// RegisterCollector adds a collector to the orchestrator
func (p *CollectorOrchestrator) RegisterCollector(name string, collector collectors.Collector) error {
	if p.ctx != nil {
		return fmt.Errorf("cannot register collector after orchestrator started")
	}
	if _, exists := p.collectors[name]; exists {
		return fmt.Errorf("collector %s already registered", name)
	}
	p.collectors[name] = collector
	return nil
}

// Start begins processing events
func (p *CollectorOrchestrator) Start(ctx context.Context) error {
	if p.ctx != nil {
		return fmt.Errorf("orchestrator already started")
	}

	p.ctx, p.cancel = context.WithCancel(ctx)

	// Start all collectors
	for name, collector := range p.collectors {
		if err := collector.Start(p.ctx); err != nil {
			p.Stop()
			return fmt.Errorf("failed to start collector %s: %w", name, err)
		}
	}

	// Use WaitGroup to track all goroutines
	p.wg = &sync.WaitGroup{}

	// Start collector consumers
	for name, collector := range p.collectors {
		p.wg.Add(1)
		go p.consumeCollector(name, collector)
	}

	// Start workers
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	return nil
}

// Stop gracefully shuts down the orchestrator
func (p *CollectorOrchestrator) Stop() error {
	p.logger.Info("Stopping collector orchestrator")

	// Prevent multiple shutdown attempts
	if p.cancel == nil {
		p.logger.Warn("Orchestrator already stopped or not started")
		return nil
	}

	// Step 1: Signal shutdown to all components first
	p.cancel()

	// Step 2: Stop all collectors to prevent new events
	// This must be done BEFORE waiting for goroutines to prevent new events
	for name, collector := range p.collectors {
		if err := collector.Stop(); err != nil {
			// Log but continue stopping others
			p.logger.Warn("Error stopping collector",
				zap.String("collector", name),
				zap.Error(err))
		}
	}

	// Step 3: Wait for all goroutines to finish with timeout
	// This ensures all collector consumers and workers have stopped before closing channels
	done := make(chan struct{})
	go func() {
		if p.wg != nil {
			p.wg.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info("All workers stopped gracefully")
	case <-time.After(10 * time.Second):
		p.logger.Error("Timeout waiting for workers to stop")
		// Continue with shutdown even after timeout
	}

	// Step 4: Close event channel safely after all goroutines have stopped
	// Use a safe close pattern to prevent panic if already closed
	if p.eventsChan != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					p.logger.Debug("Channel already closed during shutdown")
				}
			}()
			// Only close if not already closed
			select {
			case event, ok := <-p.eventsChan:
				if !ok {
					// Channel already closed
					return
				}
				// Put the value back if we read one
				select {
				case p.eventsChan <- event:
				default:
					// Channel full, just close it
				}
				close(p.eventsChan)
			default:
				// No data available, safe to close
				close(p.eventsChan)
			}
		}()
	}

	// Step 5: Close publisher with graceful shutdown
	if p.publisher != nil {
		publisherDone := make(chan bool, 1)
		go func() {
			p.publisher.Close()
			publisherDone <- true
		}()

		select {
		case <-publisherDone:
			p.logger.Info("Publisher closed gracefully")
		case <-time.After(5 * time.Second):
			p.logger.Warn("Timeout closing publisher")
		}
	}

	// Reset cancel to prevent multiple shutdowns
	p.cancel = nil

	p.logger.Info("Collector orchestrator stopped")
	return nil
}

// consumeCollector reads events from a collector and forwards to processing
func (p *CollectorOrchestrator) consumeCollector(name string, collector collectors.Collector) {
	defer p.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("Panic in collector consumer",
				zap.String("collector", name),
				zap.Any("panic", r),
			)
		}
	}()

	p.logger.Debug("Starting collector consumer", zap.String("collector", name))

	for {
		select {
		case <-p.ctx.Done():
			p.logger.Info("Collector consumer stopping due to context cancellation",
				zap.String("collector", name))
			return
		case event, ok := <-collector.Events():
			if !ok {
				p.logger.Info("Collector channel closed", zap.String("collector", name))
				return
			}

			// Add collector name to metadata attributes
			if event.Metadata.Attributes == nil {
				event.Metadata.Attributes = make(map[string]string)
			}
			event.Metadata.Attributes["collector_name"] = name

			// Try to send event with safe channel writing
			// Use a non-blocking select to avoid race conditions during shutdown
			select {
			case <-p.ctx.Done():
				// Orchestrator is shutting down, drop event
				p.logger.Debug("Dropping event due to shutdown",
					zap.String("collector", name),
					zap.String("event_type", string(event.Type)))
				return
			case p.eventsChan <- event:
				// Successfully sent event
			default:
				// Channel full or closed, use timeout with graceful handling
				select {
				case <-p.ctx.Done():
					return
				case p.eventsChan <- event:
					// Successfully sent after retry
				case <-time.After(100 * time.Millisecond):
					// Drop event if channel is blocked
					p.logger.Debug("Dropping event due to channel backpressure",
						zap.String("collector", name),
						zap.String("event_type", string(event.Type)))
				}
			}
		}
	}
}

// worker processes events
func (p *CollectorOrchestrator) worker() {
	defer p.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("Panic in orchestrator worker",
				zap.Any("panic", r),
			)
		}
	}()

	for {
		select {
		case event, ok := <-p.eventsChan:
			if !ok {
				return
			}
			func() {
				// Wrap individual event processing in recovery
				defer func() {
					if r := recover(); r != nil {
						p.logger.Error("Panic processing event",
							zap.Any("panic", r),
							zap.String("event_type", string(event.Type)),
						)
					}
				}()

				// Publish raw event directly to NATS with retry logic
				if p.publisher != nil {
					retries := 3
					for i := 0; i < retries; i++ {
						err := p.publisher.Publish(event)
						if err == nil {
							break
						}

						if i == retries-1 {
							// Final retry failed - use CollectorEvent fields for logging
							eventID := fmt.Sprintf("%s-%d", string(event.Type), event.Timestamp.UnixNano())
							if event.Metadata.TraceID != "" {
								eventID = event.Metadata.TraceID
							}
							p.logger.Error("Failed to publish event after retries",
								zap.Error(err),
								zap.String("event_id", eventID),
								zap.String("event_type", string(event.Type)),
								zap.String("trace_id", event.Metadata.TraceID),
								zap.Int("retries", retries),
							)
						} else {
							// Wait before retry
							time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
						}
					}
				}
			}()
		case <-p.ctx.Done():
			return
		}
	}
}

// GetHealthStatus returns the health status of all collectors
func (p *CollectorOrchestrator) GetHealthStatus() map[string]CollectorHealthStatus {
	status := make(map[string]CollectorHealthStatus)

	for name, collector := range p.collectors {
		health := CollectorHealthStatus{
			Healthy: collector.IsHealthy(),
		}

		// Check if collector implements structured health interface
		if healthReporter, ok := collector.(interface {
			Health() HealthDetails
		}); ok {
			details := healthReporter.Health()
			health.Healthy = details.Healthy
			health.Error = details.Error
			health.LastEvent = details.LastEvent
		}

		status[name] = health
	}

	return status
}

// CollectorFactory creates a collector from YAML configuration
type CollectorFactory func(name string, config *CollectorConfigData, logger *zap.Logger) (collectors.Collector, error)

// Global collector factory registry
var collectorFactories = sync.Map{}

// RegisterCollectorFactory registers a collector factory for automatic YAML instantiation
func RegisterCollectorFactory(collectorType string, factory CollectorFactory) {
	collectorFactories.Store(collectorType, factory)
}

// RegisterCollectorsFromYAML automatically registers all enabled collectors from YAML config
func (p *CollectorOrchestrator) RegisterCollectorsFromYAML(config *YAMLConfig, logger *zap.Logger) error {
	if p.ctx != nil {
		return fmt.Errorf("cannot register collectors after orchestrator started")
	}

	registered := []string{}

	// Iterate through all collectors in YAML config
	for collectorType, collectorConfig := range config.Collectors {
		if !collectorConfig.Enabled {
			logger.Debug("Collector disabled in config", zap.String("type", collectorType))
			continue
		}

		// Look up factory for this collector type
		factoryInterface, exists := collectorFactories.Load(collectorType)
		if !exists {
			logger.Error("No factory registered for collector type",
				zap.String("type", collectorType),
				zap.Strings("available", getRegisteredCollectorTypes()))
			continue
		}

		factory, ok := factoryInterface.(CollectorFactory)
		if !ok {
			logger.Error("Invalid factory type for collector", zap.String("type", collectorType))
			continue
		}

		// Create collector instance using factory
		collector, err := factory(collectorType, &collectorConfig.Config, logger)
		if err != nil {
			logger.Error("Failed to create collector from factory",
				zap.String("type", collectorType),
				zap.Error(err))
			continue
		}

		// Register with orchestrator
		if err := p.RegisterCollector(collectorType, collector); err != nil {
			logger.Error("Failed to register collector with orchestrator",
				zap.String("type", collectorType),
				zap.Error(err))
			continue
		}

		registered = append(registered, collectorType)
	}

	if len(registered) == 0 {
		return fmt.Errorf("no collectors were successfully registered")
	}

	logger.Info("Successfully registered collectors from YAML",
		zap.Strings("collectors", registered))

	return nil
}

// getRegisteredCollectorTypes returns list of available collector types
func getRegisteredCollectorTypes() []string {
	var types []string
	collectorFactories.Range(func(key, value interface{}) bool {
		if typeStr, ok := key.(string); ok {
			types = append(types, typeStr)
		}
		return true
	})
	return types
}
