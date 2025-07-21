package internal

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/integrations/otel"
	"go.opentelemetry.io/otel/trace"
)

// CNICollector implements the core.Collector interface
// It orchestrates multiple monitoring approaches (logs, processes, events, files)
// and produces UnifiedEvent directly from CNI sources for optimal performance.
type CNICollector struct {
	config    core.Config
	monitors  []core.CNIMonitor
	processor core.EventProcessor

	// Event streaming
	eventChan    chan domain.UnifiedEvent
	rawEventChan chan core.CNIRawEvent

	// Lifecycle management
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
	mu      sync.RWMutex

	// Health and statistics
	health     core.Health
	statistics core.Statistics
	startTime  time.Time
	lastUpdate time.Time

	// Error tracking
	errors   []error
	errorsMu sync.Mutex

	// OTEL instrumentation
	otelInstrumentation *otel.CollectorInstrumentation
}

// NewCNICollector creates a new CNI collector with the given configuration
func NewCNICollector(config core.Config) (*CNICollector, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	collector := &CNICollector{
		config:       config,
		eventChan:    make(chan domain.UnifiedEvent, config.EventBufferSize),
		rawEventChan: make(chan core.CNIRawEvent, config.EventBufferSize*2),
		processor:    newCNIEventProcessor(),
		health: core.Health{
			Status:             core.HealthStatusUnknown,
			Message:            "Initializing",
			CNIPluginsDetected: []string{},
			Metrics:            make(map[string]float64),
		},
		statistics: core.Statistics{
			StartTime:           time.Now(),
			PluginExecutionTime: make(map[string]time.Duration),
			Custom:              make(map[string]interface{}),
		},
		startTime: time.Now(),
	}

	// Initialize monitors based on configuration
	if err := collector.initializeMonitors(); err != nil {
		return nil, fmt.Errorf("failed to initialize monitors: %w", err)
	}

	// Initialize OTEL instrumentation
	if config.EnableOTEL {
		otelConfig := otel.DefaultConfig()
		otelConfig.ServiceName = "tapio-cni-collector"
		otelConfig.ServiceVersion = "1.0.0"
		otelConfig.Environment = getEnvironment()
		otelConfig.Enabled = true

		otelIntegration, err := otel.NewSimpleOTEL(otelConfig)
		if err != nil {
			// OTEL is optional, just log the error
			collector.recordError(fmt.Errorf("failed to initialize OTEL: %w", err))
		} else {
			collector.otelInstrumentation = otel.NewCollectorInstrumentation(otelIntegration)
		}
	}

	collector.updateHealth()
	return collector, nil
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

// Start begins CNI monitoring and event collection
func (c *CNICollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector already running")
	}

	// Create OTEL span for collector startup
	if c.otelInstrumentation != nil {
		var span trace.Span
		ctx, span = c.otelInstrumentation.InstrumentCollectorStart(ctx, "cni")
		defer span.End()
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.running = true
	c.startTime = time.Now()
	c.statistics.StartTime = c.startTime

	// Start raw event processing
	c.wg.Add(1)
	go c.processRawEvents()

	// Start all monitors
	for i, monitor := range c.monitors {
		if err := monitor.Start(c.ctx); err != nil {
			c.recordError(fmt.Errorf("failed to start monitor %d (%s): %w", i, monitor.MonitorType(), err))
			continue
		}

		// Start goroutine to collect events from this monitor
		c.wg.Add(1)
		go c.collectFromMonitor(monitor)
	}

	// Start health monitoring
	c.wg.Add(1)
	go c.monitorHealth()

	c.updateHealth()
	return nil
}

// Stop gracefully shuts down the collector
func (c *CNICollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.running = false

	// Cancel context to signal all goroutines to stop
	if c.cancel != nil {
		c.cancel()
	}

	// Stop all monitors
	for _, monitor := range c.monitors {
		if err := monitor.Stop(); err != nil {
			c.recordError(fmt.Errorf("error stopping monitor: %w", err))
		}
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		// Clean shutdown
	case <-time.After(10 * time.Second):
		// Force shutdown after timeout
		c.recordError(fmt.Errorf("timeout waiting for goroutines to finish"))
	}

	// Close channels
	close(c.rawEventChan)
	close(c.eventChan)

	c.health.Status = core.HealthStatusUnknown
	c.health.Message = "Stopped"

	return nil
}

// Events returns the channel of processed UnifiedEvent
func (c *CNICollector) Events() <-chan domain.UnifiedEvent {
	return c.eventChan
}

// Health returns current health status
func (c *CNICollector) Health() core.Health {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.health
}

// Statistics returns runtime statistics
func (c *CNICollector) Statistics() core.Statistics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.statistics
}

// Configure updates the collector configuration
func (c *CNICollector) Configure(config core.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("cannot reconfigure while running")
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	c.config = config

	// Reinitialize monitors with new config
	if err := c.initializeMonitors(); err != nil {
		return fmt.Errorf("failed to reinitialize monitors: %w", err)
	}

	c.updateHealth()
	return nil
}

// Internal methods

// initializeMonitors creates monitors based on configuration
func (c *CNICollector) initializeMonitors() error {
	c.monitors = []core.CNIMonitor{}

	// Initialize log monitor if enabled
	if c.config.EnableLogMonitoring {
		monitor, err := NewLogMonitor(c.config)
		if err != nil {
			c.recordError(fmt.Errorf("failed to create log monitor: %w", err))
		} else {
			c.monitors = append(c.monitors, monitor)
		}
	}

	// Initialize process monitor if enabled
	if c.config.EnableProcessMonitoring {
		monitor, err := NewProcessMonitor(c.config)
		if err != nil {
			c.recordError(fmt.Errorf("failed to create process monitor: %w", err))
		} else {
			c.monitors = append(c.monitors, monitor)
		}
	}

	// Initialize event monitor if enabled
	if c.config.EnableEventMonitoring {
		monitor, err := NewEventMonitor(c.config)
		if err != nil {
			c.recordError(fmt.Errorf("failed to create event monitor: %w", err))
		} else {
			c.monitors = append(c.monitors, monitor)
		}
	}

	// Initialize file monitor if enabled
	if c.config.EnableFileMonitoring {
		monitor, err := NewFileMonitor(c.config)
		if err != nil {
			c.recordError(fmt.Errorf("failed to create file monitor: %w", err))
		} else {
			c.monitors = append(c.monitors, monitor)
		}
	}

	if len(c.monitors) == 0 {
		return fmt.Errorf("no monitors could be initialized")
	}

	return nil
}

// processRawEvents processes raw CNI events into UnifiedEvents
func (c *CNICollector) processRawEvents() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case rawEvent, ok := <-c.rawEventChan:
			if !ok {
				return
			}

			// Create OTEL span for event processing
			eventCtx := c.ctx
			if c.otelInstrumentation != nil {
				// Create a temporary UnifiedEvent for span creation
				tempEvent := &domain.UnifiedEvent{
					ID:     rawEvent.ID,
					Source: string(domain.SourceCNI),
				}
				var span trace.Span
				eventCtx, span = c.otelInstrumentation.InstrumentEventProcessing(eventCtx, tempEvent)
				defer span.End()
			}

			// Process the raw event into a UnifiedEvent
			unifiedEvent, err := c.processor.ProcessEvent(eventCtx, rawEvent)
			if err != nil {
				if c.otelInstrumentation != nil {
					c.otelInstrumentation.RecordError(eventCtx, err, "failed to process CNI event")
				}
				c.recordError(fmt.Errorf("failed to process event %s: %w", rawEvent.ID, err))
				c.statistics.EventsDropped++
				continue
			}

			// The processor already adds trace context from annotations,
			// but OTEL instrumentation will enhance it with active span

			// Update statistics
			c.updateStatistics(rawEvent, unifiedEvent)

			// Send the processed event
			select {
			case c.eventChan <- *unifiedEvent:
				c.statistics.EventsCollected++
			case <-c.ctx.Done():
				return
			default:
				// Channel full, drop event
				c.statistics.EventsDropped++
				c.recordError(fmt.Errorf("event channel full, dropped event %s", unifiedEvent.ID))
			}
		}
	}
}

// collectFromMonitor collects events from a specific monitor
func (c *CNICollector) collectFromMonitor(monitor core.CNIMonitor) {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case rawEvent, ok := <-monitor.Events():
			if !ok {
				return
			}

			// Forward raw event for processing
			select {
			case c.rawEventChan <- rawEvent:
				// Event forwarded successfully
			case <-c.ctx.Done():
				return
			default:
				// Raw event channel full, drop event
				c.statistics.EventsDropped++
				c.recordError(fmt.Errorf("raw event channel full, dropped event from %s", monitor.MonitorType()))
			}
		}
	}
}

// monitorHealth periodically updates health status
func (c *CNICollector) monitorHealth() {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.updateHealth()
		}
	}
}

// updateHealth updates the health status based on current state
func (c *CNICollector) updateHealth() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastUpdate = time.Now()
	c.health.LastEventTime = c.lastUpdate
	c.health.ActiveMonitors = len(c.monitors)

	// Count recent errors
	c.errorsMu.Lock()
	recentErrors := 0
	cutoff := time.Now().Add(-5 * time.Minute)
	for _, err := range c.errors {
		if errTime, ok := err.(*timestampError); ok && errTime.timestamp.After(cutoff) {
			recentErrors++
		}
	}
	c.errorsMu.Unlock()

	c.health.ErrorCount = uint64(recentErrors)

	// Determine health status
	if !c.running {
		c.health.Status = core.HealthStatusUnknown
		c.health.Message = "Not running"
	} else if recentErrors > 10 {
		c.health.Status = core.HealthStatusUnhealthy
		c.health.Message = fmt.Sprintf("High error rate: %d errors in last 5 minutes", recentErrors)
	} else if len(c.monitors) == 0 {
		c.health.Status = core.HealthStatusUnhealthy
		c.health.Message = "No active monitors"
	} else if recentErrors > 5 {
		c.health.Status = core.HealthStatusDegraded
		c.health.Message = fmt.Sprintf("Moderate error rate: %d errors in last 5 minutes", recentErrors)
	} else {
		c.health.Status = core.HealthStatusHealthy
		c.health.Message = "Operating normally"
	}

	// Update metrics
	c.health.Metrics["events_per_second"] = float64(c.statistics.EventsCollected) / time.Since(c.startTime).Seconds()
	c.health.Metrics["drop_rate"] = float64(c.statistics.EventsDropped) / float64(c.statistics.EventsCollected+c.statistics.EventsDropped)
	c.health.Metrics["active_monitors"] = float64(len(c.monitors))
}

// updateStatistics updates runtime statistics based on processed events
func (c *CNICollector) updateStatistics(rawEvent core.CNIRawEvent, unifiedEvent *domain.UnifiedEvent) {
	// Update operation counts
	c.statistics.CNIOperationsTotal++
	if !rawEvent.Success {
		c.statistics.CNIOperationsFailed++
	}

	// Update IP allocation counts
	if rawEvent.Operation == core.CNIOperationAdd && rawEvent.AssignedIP != "" {
		c.statistics.IPAllocationsTotal++
	}
	if rawEvent.Operation == core.CNIOperationDel && rawEvent.AssignedIP != "" {
		c.statistics.IPDeallocationsTotal++
	}

	// Update plugin execution times
	if rawEvent.PluginName != "" {
		current, exists := c.statistics.PluginExecutionTime[rawEvent.PluginName]
		if !exists {
			c.statistics.PluginExecutionTime[rawEvent.PluginName] = rawEvent.Duration
		} else {
			// Keep running average
			c.statistics.PluginExecutionTime[rawEvent.PluginName] = (current + rawEvent.Duration) / 2
		}
	}

	// Update Kubernetes events if applicable
	if unifiedEvent.Kubernetes != nil {
		c.statistics.K8sEventsProcessed++
	}
}

// recordError records an error with timestamp
func (c *CNICollector) recordError(err error) {
	c.errorsMu.Lock()
	defer c.errorsMu.Unlock()

	timestampedErr := &timestampError{
		error:     err,
		timestamp: time.Now(),
	}

	c.errors = append(c.errors, timestampedErr)

	// Keep only last 100 errors
	if len(c.errors) > 100 {
		c.errors = c.errors[len(c.errors)-100:]
	}

	c.statistics.MonitoringErrors++
}

// timestampError wraps an error with a timestamp
type timestampError struct {
	error
	timestamp time.Time
}

// getNodeHostname gets the actual node hostname
func getNodeHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown-node"
}
