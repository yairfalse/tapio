package internal

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/common"
	"github.com/yairfalse/tapio/pkg/collectors/systemd/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

// HardenedCollector is a production-hardened systemd collector
type HardenedCollector struct {
	// Core collector
	*collector

	// Production hardening components
	rateLimiter    *RateLimiter
	circuitBreaker *CircuitBreaker
	backpressure   *BackpressureController
	validator      *EventValidator
	connectionPool *ConnectionPool

	// Enhanced metrics
	metrics struct {
		rateLimited      atomic.Uint64
		circuitOpened    atomic.Uint64
		backpressureDrop atomic.Uint64
		validationFailed atomic.Uint64
	}

	// Configuration
	hardeningConfig HardeningConfig
}

// HardeningConfig contains production hardening settings
type HardeningConfig struct {
	// Rate limiting
	MaxEventsPerSecond int

	// Circuit breaker
	FailureThreshold int
	RecoveryTimeout  time.Duration

	// Backpressure
	MaxQueueSize int

	// Connection pool
	MaxConnections int

	// Validation
	StrictValidation bool
}

// DefaultHardeningConfig returns default hardening configuration
func DefaultHardeningConfig() HardeningConfig {
	return HardeningConfig{
		MaxEventsPerSecond: 10000,
		FailureThreshold:   5,
		RecoveryTimeout:    30 * time.Second,
		MaxQueueSize:       100000,
		MaxConnections:     5,
		StrictValidation:   true,
	}
}

// NewHardenedCollector creates a new production-hardened collector
func NewHardenedCollector(config core.Config, hardeningConfig HardeningConfig) (core.Collector, error) {
	// Create base collector
	baseCollector, err := NewCollector(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create base collector: %w", err)
	}

	c := baseCollector.(*collector)

	// Create hardening components
	hc := &HardenedCollector{
		collector:       c,
		hardeningConfig: hardeningConfig,
		rateLimiter:     NewRateLimiter(hardeningConfig.MaxEventsPerSecond),
		circuitBreaker:  NewCircuitBreaker(),
		backpressure:    NewBackpressureController(hardeningConfig.MaxQueueSize),
		validator:       NewEventValidator(),
	}

	// Override the event processing
	c.processor = hc

	return hc, nil
}

// Start begins event collection with hardening
func (hc *HardenedCollector) Start(ctx context.Context) error {
	// Create connection pool if using D-Bus
	if hc.config.UseDBus {
		pool, err := NewConnectionPool(
			hc.hardeningConfig.MaxConnections,
			func() (core.DBusConnection, error) {
				// This would create a new D-Bus connection
				// Implementation depends on platform
				return hc.impl.(interface {
					createDBusConnection() (core.DBusConnection, error)
				}).createDBusConnection()
			},
		)
		if err != nil {
			return fmt.Errorf("failed to create connection pool: %w", err)
		}
		hc.connectionPool = pool
	}

	// Start base collector
	if err := hc.collector.Start(ctx); err != nil {
		if hc.connectionPool != nil {
			hc.connectionPool.Close()
		}
		return err
	}

	// Start monitoring goroutine
	go hc.monitorHealth()

	return nil
}

// Stop stops the collector with cleanup
func (hc *HardenedCollector) Stop() error {
	// Stop base collector
	err := hc.collector.Stop()

	// Close connection pool
	if hc.connectionPool != nil {
		if poolErr := hc.connectionPool.Close(); poolErr != nil && err == nil {
			err = poolErr
		}
	}

	return err
}

// ProcessEvent implements EventProcessor interface with hardening
func (hc *HardenedCollector) ProcessEvent(rawEvent core.RawEvent) (*domain.UnifiedEvent, error) {
	// 1. Rate limiting
	if !hc.rateLimiter.Allow() {
		hc.metrics.rateLimited.Add(1)
		return nil, core.ErrRateLimitExceeded
	}

	// 2. Validation
	if err := hc.validator.ValidateEvent(&rawEvent); err != nil {
		hc.metrics.validationFailed.Add(1)
		if hc.hardeningConfig.StrictValidation {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		// Log but continue with sanitized event
	}

	// 3. Determine priority
	priority := hc.validator.DeterminePriority(&rawEvent)

	// 4. Backpressure check
	queueSize := len(hc.eventChan)
	hc.backpressure.UpdateQueueSize(queueSize)

	if !hc.backpressure.ShouldAccept(priority) {
		hc.metrics.backpressureDrop.Add(1)
		return nil, core.ErrBufferFull
	}

	// 5. Circuit breaker for processing
	var event *domain.UnifiedEvent
	err := hc.circuitBreaker.Call(func() error {
		// Use base processor for actual conversion
		processed, err := newEventProcessor().ProcessEvent(rawEvent)
		if err != nil {
			return err
		}
		event = processed
		return nil
	})

	if err != nil {
		if err == ErrCircuitBreakerOpen {
			hc.metrics.circuitOpened.Add(1)
		}
		return nil, err
	}

	return event, nil
}

// monitorHealth monitors collector health and adjusts parameters
func (hc *HardenedCollector) monitorHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-ticker.C:
			hc.performHealthCheck()
		}
	}
}

// performHealthCheck performs health checks and adjustments
func (hc *HardenedCollector) performHealthCheck() {
	// Check circuit breaker state
	if hc.circuitBreaker.GetState() == StateOpen {
		// Log warning about open circuit
		hc.stats.dbusErrors.Add(1)
	}

	// Check connection pool health
	if hc.connectionPool != nil {
		hc.connectionPool.HealthCheck()
	}

	// Check backpressure levels
	loadLevel := hc.backpressure.GetLoadLevel()
	if loadLevel == "critical" {
		// Could implement dynamic throttling here
		hc.stats.eventsDropped.Add(hc.metrics.backpressureDrop.Load())
	}

	// Update last event time if healthy
	if hc.stats.eventsCollected.Load() > 0 {
		hc.lastEventTime.Store(time.Now())
	}
}

// Health returns enhanced health information
func (hc *HardenedCollector) Health() core.Health {
	health := hc.collector.Health()

	// Add hardening metrics
	health.Metrics["rate_limited"] = float64(hc.metrics.rateLimited.Load())
	health.Metrics["circuit_opened"] = float64(hc.metrics.circuitOpened.Load())
	health.Metrics["backpressure_dropped"] = float64(hc.metrics.backpressureDrop.Load())
	health.Metrics["validation_failed"] = float64(hc.metrics.validationFailed.Load())

	// Add component health
	health.Metrics["circuit_breaker_state"] = string(hc.circuitBreaker.GetState())
	health.Metrics["backpressure_load"] = hc.backpressure.GetLoadLevel()

	// Rate limiter metrics
	allowed, limited := hc.rateLimiter.Metrics()
	health.Metrics["rate_limit_allowed"] = float64(allowed)
	health.Metrics["rate_limit_denied"] = float64(limited)

	// Connection pool metrics
	if hc.connectionPool != nil {
		poolMetrics := hc.connectionPool.Metrics()
		for k, v := range poolMetrics {
			health.Metrics["pool_"+k] = float64(v.(int))
		}
	}

	// Determine overall health
	if hc.circuitBreaker.GetState() == StateOpen {
		health.Status = core.StatusUnhealthy
		health.Message = "Circuit breaker is open"
	} else if hc.backpressure.GetLoadLevel() == "critical" {
		health.Status = core.StatusDegraded
		health.Message = "System under heavy load"
	}

	return health
}

// Statistics returns enhanced statistics
func (hc *HardenedCollector) Statistics() core.Statistics {
	stats := hc.collector.Statistics()

	// Add hardening statistics
	stats.Custom["hardening"] = map[string]interface{}{
		"rate_limiter":    hc.rateLimiter.Metrics(),
		"circuit_breaker": hc.circuitBreaker.Metrics(),
		"backpressure":    hc.backpressure.Metrics(),
		"validator":       hc.validator.Metrics(),
	}

	if hc.connectionPool != nil {
		stats.Custom["connection_pool"] = hc.connectionPool.Metrics()
	}

	return stats
}

// executeWithConnection executes a function with a pooled connection
func (hc *HardenedCollector) executeWithConnection(ctx context.Context, fn func(core.DBusConnection) error) error {
	if hc.connectionPool == nil {
		return fmt.Errorf("connection pool not initialized")
	}

	return hc.connectionPool.Execute(ctx, fn)
}
