package internal

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/ebpf/core"
	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/integrations/otel"
	"go.opentelemetry.io/otel/trace"
)

// collector implements the core.Collector interface
type collector struct {
	// Configuration
	config core.Config

	// State management
	started atomic.Bool
	stopped atomic.Bool

	// Event processing
	eventChan chan domain.Event
	processor core.EventProcessor

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Statistics
	stats struct {
		eventsCollected atomic.Uint64
		eventsDropped   atomic.Uint64
		bytesProcessed  atomic.Uint64
		errorCount      atomic.Uint64
	}

	// Health tracking
	lastEventTime atomic.Value // time.Time
	startTime     time.Time

	// Platform-specific implementation
	impl platformImpl

	// OTEL instrumentation
	otelInstrumentation *otel.CollectorInstrumentation
}

// platformImpl is the platform-specific interface
type platformImpl interface {
	init(config core.Config) error
	start(ctx context.Context) error
	stop() error
	events() <-chan core.RawEvent
	programsLoaded() int
	mapsCreated() int
}

// NewCollector creates a new eBPF collector
func NewCollector(config core.Config) (core.Collector, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	c := &collector{
		config:    config,
		eventChan: make(chan domain.Event, config.EventBufferSize),
		startTime: time.Now(),
		processor: newEventProcessor(),
	}

	// Initialize platform-specific implementation
	impl, err := newPlatformImpl()
	if err != nil {
		return nil, fmt.Errorf("failed to create platform implementation: %w", err)
	}

	if err := impl.init(config); err != nil {
		return nil, fmt.Errorf("failed to initialize platform implementation: %w", err)
	}

	c.impl = impl
	c.lastEventTime.Store(time.Now())

	// Initialize OTEL instrumentation
	if config.EnableOTEL {
		otelConfig := otel.DefaultConfig()
		otelConfig.ServiceName = "tapio-ebpf-collector"
		otelConfig.ServiceVersion = "1.0.0"
		otelConfig.Environment = getEnvironment()
		otelConfig.Enabled = true

		otelIntegration, err := otel.NewSimpleOTEL(otelConfig)
		if err != nil {
			// OTEL is optional, just log the error
			fmt.Printf("Failed to initialize OTEL: %v\n", err)
		} else {
			c.otelInstrumentation = otel.NewCollectorInstrumentation(otelIntegration)
		}
	}

	return c, nil
}

// getEnvironment returns the current environment based on env vars
func getEnvironment() string {
	if env := os.Getenv("TAPIO_ENV"); env != "" {
		return env
	}
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	return "development"
}

// Start begins event collection
func (c *collector) Start(ctx context.Context) error {
	if !c.config.Enabled {
		return fmt.Errorf("collector is disabled")
	}

	if c.started.Load() {
		return core.ErrAlreadyStarted
	}

	// Create OTEL span for collector startup
	if c.otelInstrumentation != nil {
		var span trace.Span
		ctx, span = c.otelInstrumentation.InstrumentCollectorStart(ctx, "ebpf")
		defer span.End()
	}

	// Create cancellable context
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Start platform implementation
	if err := c.impl.start(c.ctx); err != nil {
		return fmt.Errorf("failed to start platform implementation: %w", err)
	}

	// Mark as started
	c.started.Store(true)

	// Start event processing
	c.wg.Add(1)
	go c.processEvents()

	return nil
}

// Stop gracefully stops the collector
func (c *collector) Stop() error {
	if !c.started.Load() {
		return core.ErrNotStarted
	}

	if c.stopped.Load() {
		return nil
	}

	// Mark as stopping
	c.stopped.Store(true)

	// Cancel context
	if c.cancel != nil {
		c.cancel()
	}

	// Stop platform implementation
	if err := c.impl.stop(); err != nil {
		return fmt.Errorf("failed to stop platform implementation: %w", err)
	}

	// Wait for goroutines
	c.wg.Wait()

	// Close event channel
	close(c.eventChan)

	return nil
}

// Events returns the event channel
func (c *collector) Events() <-chan domain.Event {
	return c.eventChan
}

// Health returns the current health status
func (c *collector) Health() core.Health {
	status := core.HealthStatusHealthy
	message := "eBPF collector is healthy"

	if !c.started.Load() {
		status = core.HealthStatusUnknown
		message = "Collector not started"
	} else if c.stopped.Load() {
		status = core.HealthStatusUnhealthy
		message = "Collector stopped"
	} else if c.stats.errorCount.Load() > 100 {
		status = core.HealthStatusDegraded
		message = fmt.Sprintf("High error count: %d", c.stats.errorCount.Load())
	}

	lastEvent := c.lastEventTime.Load().(time.Time)
	if time.Since(lastEvent) > 5*time.Minute && c.started.Load() {
		status = core.HealthStatusDegraded
		message = "No events received in 5 minutes"
	}

	return core.Health{
		Status:          status,
		Message:         message,
		LastEventTime:   lastEvent,
		EventsProcessed: c.stats.eventsCollected.Load(),
		EventsDropped:   c.stats.eventsDropped.Load(),
		ErrorCount:      c.stats.errorCount.Load(),
		Metrics: map[string]float64{
			"programs_loaded":    float64(c.impl.programsLoaded()),
			"maps_created":       float64(c.impl.mapsCreated()),
			"buffer_utilization": c.getBufferUtilization(),
			"events_per_second":  c.getEventsPerSecond(),
			"bytes_per_second":   c.getBytesPerSecond(),
		},
	}
}

// Statistics returns runtime statistics
func (c *collector) Statistics() core.Statistics {
	uptime := time.Since(c.startTime)

	return core.Statistics{
		StartTime:       c.startTime,
		EventsCollected: c.stats.eventsCollected.Load(),
		EventsDropped:   c.stats.eventsDropped.Load(),
		BytesProcessed:  c.stats.bytesProcessed.Load(),
		ProgramsLoaded:  c.impl.programsLoaded(),
		MapsCreated:     c.impl.mapsCreated(),
		Custom: map[string]interface{}{
			"uptime_seconds":    uptime.Seconds(),
			"events_per_second": c.getEventsPerSecond(),
			"bytes_per_second":  c.getBytesPerSecond(),
		},
	}
}

// Configure updates the collector configuration
func (c *collector) Configure(config core.Config) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	c.config = config
	return nil
}

// processEvents processes raw events from the platform implementation
func (c *collector) processEvents() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return

		case rawEvent, ok := <-c.impl.events():
			if !ok {
				return
			}

			// Create OTEL span for event processing
			eventCtx := c.ctx
			if c.otelInstrumentation != nil {
				// Create a temporary domain.Event for span creation
				tempEvent := &domain.Event{
					ID:     domain.EventID(fmt.Sprintf("ebpf-%d-%d", rawEvent.PID, rawEvent.Timestamp)),
					Source: domain.SourceEBPF,
				}
				var span trace.Span
				eventCtx, span = c.otelInstrumentation.InstrumentEventProcessing(eventCtx, &domain.UnifiedEvent{
					ID:     string(tempEvent.ID),
					Source: string(tempEvent.Source),
				})
				defer span.End()
			}

			// Process the raw event
			event, err := c.processor.ProcessEvent(eventCtx, rawEvent)
			if err != nil {
				if c.otelInstrumentation != nil {
					c.otelInstrumentation.RecordError(eventCtx, err, "failed to process eBPF event")
				}
				c.stats.errorCount.Add(1)
				continue
			}

			// Update stats
			c.stats.eventsCollected.Add(1)
			c.stats.bytesProcessed.Add(uint64(len(rawEvent.Data)))
			c.lastEventTime.Store(time.Now())

			// Try to send event
			select {
			case c.eventChan <- event:
				// Event sent successfully
			default:
				// Buffer full, drop event
				c.stats.eventsDropped.Add(1)
			}
		}
	}
}

// Helper methods

func (c *collector) getBufferUtilization() float64 {
	if c.config.EventBufferSize == 0 {
		return 0
	}
	return float64(len(c.eventChan)) / float64(c.config.EventBufferSize) * 100
}

func (c *collector) getEventsPerSecond() float64 {
	uptime := time.Since(c.startTime).Seconds()
	if uptime == 0 {
		return 0
	}
	return float64(c.stats.eventsCollected.Load()) / uptime
}

func (c *collector) getBytesPerSecond() float64 {
	uptime := time.Since(c.startTime).Seconds()
	if uptime == 0 {
		return 0
	}
	return float64(c.stats.bytesProcessed.Load()) / uptime
}
