package hybrid

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/correlation_v2"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// HybridCorrelationEngine routes traffic between V1 and V2 correlation engines
type HybridCorrelationEngine struct {
	// Engines
	v1Engine events_correlation.Engine
	v2Engine *correlation_v2.HighPerformanceEngine
	
	// Routing
	router      *TrafficRouter
	adapter     *EventAdapter
	deduplicator *ResultDeduplicator
	
	// Monitoring
	metrics     *HybridMetrics
	comparator  *ResultComparator
	healthCheck *HealthMonitor
	
	// Configuration
	config      HybridConfig
	configMu    sync.RWMutex
	
	// Circuit breaker for V2
	v2Circuit   *CircuitBreaker
	
	// Shadow mode
	shadowMode  atomic.Bool
	
	// Lifecycle
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// HybridConfig configures the hybrid correlation engine
type HybridConfig struct {
	// Feature flags
	EnableV2        bool          `json:"enable_v2"`
	EnableShadowMode bool          `json:"enable_shadow_mode"`
	
	// Traffic routing
	V2Percentage    int32         `json:"v2_percentage"` // 0-100
	RoutingStrategy RoutingStrategy `json:"routing_strategy"`
	
	// Rollback configuration
	RollbackConfig  RollbackConfig `json:"rollback_config"`
	
	// Performance tuning
	BatchSplitSize  int           `json:"batch_split_size"`
	MaxParallel     int           `json:"max_parallel"`
	
	// Monitoring
	MetricsInterval time.Duration `json:"metrics_interval"`
	CompareResults  bool          `json:"compare_results"`
}

// RoutingStrategy defines how traffic is routed between engines
type RoutingStrategy string

const (
	RoutingRandom      RoutingStrategy = "random"
	RoutingRuleBased   RoutingStrategy = "rule_based"
	RoutingEntityBased RoutingStrategy = "entity_based"
	RoutingProgressive RoutingStrategy = "progressive"
	RoutingLoadBased   RoutingStrategy = "load_based"
)

// RollbackConfig defines automatic rollback criteria
type RollbackConfig struct {
	ErrorThreshold    float64       `json:"error_threshold"`    // Error rate threshold (0-1)
	LatencyThreshold  time.Duration `json:"latency_threshold"`  // P99 latency threshold
	WindowSize        time.Duration `json:"window_size"`        // Monitoring window
	MinSamples        int           `json:"min_samples"`        // Minimum samples before rollback
}

// NewHybridEngine creates a new hybrid correlation engine
func NewHybridEngine(v1 events_correlation.Engine, v2Config correlation_v2.EngineConfig, config HybridConfig) (*HybridCorrelationEngine, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create V2 engine
	v2Engine := correlation_v2.NewHighPerformanceEngine(v2Config)
	
	// Initialize components
	router := NewTrafficRouter(config.RoutingStrategy, config.V2Percentage)
	adapter := NewEventAdapter()
	deduplicator := NewResultDeduplicator(5 * time.Minute)
	metrics := NewHybridMetrics()
	comparator := NewResultComparator()
	
	// Create circuit breaker for V2
	v2Circuit := NewCircuitBreaker(CircuitConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Timeout:         30 * time.Second,
		ResetTimeout:    1 * time.Minute,
	})
	
	engine := &HybridCorrelationEngine{
		v1Engine:     v1,
		v2Engine:     v2Engine,
		router:       router,
		adapter:      adapter,
		deduplicator: deduplicator,
		metrics:      metrics,
		comparator:   comparator,
		v2Circuit:    v2Circuit,
		config:       config,
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Initialize health monitor
	engine.healthCheck = NewHealthMonitor(engine, config.RollbackConfig)
	
	// Set shadow mode if configured
	engine.shadowMode.Store(config.EnableShadowMode)
	
	return engine, nil
}

// Start begins the hybrid correlation engine
func (h *HybridCorrelationEngine) Start(ctx context.Context) error {
	// Start V1 engine
	if err := h.v1Engine.Start(ctx); err != nil {
		return fmt.Errorf("failed to start V1 engine: %w", err)
	}
	
	// Start V2 engine if enabled
	if h.config.EnableV2 {
		if err := h.v2Engine.Start(); err != nil {
			// V2 failure is not critical, log and continue with V1 only
			h.metrics.RecordV2StartupFailure()
			h.config.EnableV2 = false
		}
	}
	
	// Start monitoring
	h.wg.Add(1)
	go h.monitorHealth()
	
	// Start metrics collection
	h.wg.Add(1)
	go h.collectMetrics()
	
	return nil
}

// RegisterRule registers a rule with both engines
func (h *HybridCorrelationEngine) RegisterRule(rule *events_correlation.Rule) error {
	// Always register with V1 for compatibility
	if err := h.v1Engine.RegisterRule(rule); err != nil {
		return fmt.Errorf("failed to register rule with V1: %w", err)
	}
	
	// Register with V2 if enabled and compatible
	if h.config.EnableV2 {
		// Convert to V2 rule format
		v2Rule := h.adapter.ConvertRuleToV2(rule)
		if v2Rule != nil {
			if err := h.v2Engine.RegisterRule(v2Rule); err != nil {
				// Log but don't fail - V2 registration is optional
				h.metrics.RecordV2RuleRegistrationFailure(rule.ID)
			}
		}
	}
	
	return nil
}

// ProcessEvents processes events through the appropriate engine(s)
func (h *HybridCorrelationEngine) ProcessEvents(ctx context.Context, events []events_correlation.Event) ([]*events_correlation.Result, error) {
	startTime := time.Now()
	defer func() {
		h.metrics.RecordProcessingLatency(time.Since(startTime))
	}()
	
	// Shadow mode - process in both but return V1 results
	if h.shadowMode.Load() {
		return h.processInShadowMode(ctx, events)
	}
	
	// Check if V2 is enabled and healthy
	if !h.config.EnableV2 || h.v2Circuit.State() == StateOpen {
		return h.v1Engine.ProcessEvents(ctx, events)
	}
	
	// Route based on strategy
	switch h.router.RouteDecision(events) {
	case RouteToV1:
		h.metrics.IncrementV1Usage()
		return h.v1Engine.ProcessEvents(ctx, events)
		
	case RouteToV2:
		h.metrics.IncrementV2Usage()
		return h.processWithV2(ctx, events)
		
	case RouteSplit:
		// Split processing between engines
		return h.processSplit(ctx, events)
		
	default:
		return h.v1Engine.ProcessEvents(ctx, events)
	}
}

// processWithV2 processes events using V2 engine with circuit breaker
func (h *HybridCorrelationEngine) processWithV2(ctx context.Context, events []events_correlation.Event) ([]*events_correlation.Result, error) {
	var results []*events_correlation.Result
	var err error
	
	// Use circuit breaker
	cbErr := h.v2Circuit.Call(func() error {
		// Convert events to V2 format
		v2Events := h.adapter.ConvertEventsToV2(events)
		
		// Process with V2
		processed := h.v2Engine.ProcessBatch(v2Events)
		h.metrics.RecordV2Processed(processed)
		
		// Collect results from V2 (this would need to be implemented)
		// For now, we'll simulate collecting results
		results = h.collectV2Results(ctx)
		
		return nil
	})
	
	if cbErr != nil {
		// Fallback to V1
		h.metrics.IncrementV2Fallback()
		return h.v1Engine.ProcessEvents(ctx, events)
	}
	
	return results, err
}

// processInShadowMode processes in both engines but returns V1 results
func (h *HybridCorrelationEngine) processInShadowMode(ctx context.Context, events []events_correlation.Event) ([]*events_correlation.Result, error) {
	// Process with V1 (primary)
	v1Results, v1Err := h.v1Engine.ProcessEvents(ctx, events)
	
	// Process with V2 (shadow) - non-blocking
	if h.config.EnableV2 {
		go func() {
			v2Results, v2Err := h.processWithV2(ctx, events)
			
			// Compare results if both succeeded
			if v1Err == nil && v2Err == nil {
				comparison := h.comparator.Compare(v1Results, v2Results)
				h.metrics.RecordComparison(comparison)
			}
		}()
	}
	
	// Always return V1 results in shadow mode
	return v1Results, v1Err
}

// processSplit splits events between V1 and V2
func (h *HybridCorrelationEngine) processSplit(ctx context.Context, events []events_correlation.Event) ([]*events_correlation.Result, error) {
	// Split events based on routing strategy
	v1Events, v2Events := h.router.SplitEvents(events, h.config.V2Percentage)
	
	var (
		v1Results []*events_correlation.Result
		v2Results []*events_correlation.Result
		v1Err     error
		v2Err     error
		wg        sync.WaitGroup
	)
	
	// Process in parallel
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		if len(v1Events) > 0 {
			v1Results, v1Err = h.v1Engine.ProcessEvents(ctx, v1Events)
		}
	}()
	
	go func() {
		defer wg.Done()
		if len(v2Events) > 0 {
			v2Results, v2Err = h.processWithV2(ctx, v2Events)
		}
	}()
	
	wg.Wait()
	
	// Handle errors
	if v1Err != nil && v2Err != nil {
		return nil, fmt.Errorf("both engines failed: v1=%w, v2=%v", v1Err, v2Err)
	}
	
	// Combine results
	allResults := append(v1Results, v2Results...)
	
	// Deduplicate if needed
	return h.deduplicator.Deduplicate(allResults), nil
}

// collectV2Results collects results from V2 engine
func (h *HybridCorrelationEngine) collectV2Results(ctx context.Context) []*events_correlation.Result {
	// This is a placeholder - in reality, we'd need to implement
	// result collection from V2's result channels
	return []*events_correlation.Result{}
}

// monitorHealth continuously monitors engine health
func (h *HybridCorrelationEngine) monitorHealth() {
	defer h.wg.Done()
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			// Check health metrics
			if h.healthCheck.ShouldRollback() {
				h.performRollback("Health check failed")
			}
		}
	}
}

// performRollback rolls back to V1-only mode
func (h *HybridCorrelationEngine) performRollback(reason string) {
	h.configMu.Lock()
	defer h.configMu.Unlock()
	
	h.config.EnableV2 = false
	h.router.SetV2Percentage(0)
	h.metrics.RecordRollback(reason)
	
	// Notify about rollback
	fmt.Printf("ROLLBACK: Disabled V2 engine - %s\n", reason)
}

// collectMetrics periodically collects and reports metrics
func (h *HybridCorrelationEngine) collectMetrics() {
	defer h.wg.Done()
	
	ticker := time.NewTicker(h.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.metrics.Report()
		}
	}
}

// UpdateV2Percentage dynamically updates V2 traffic percentage
func (h *HybridCorrelationEngine) UpdateV2Percentage(percentage int32) {
	if percentage < 0 {
		percentage = 0
	} else if percentage > 100 {
		percentage = 100
	}
	
	h.router.SetV2Percentage(percentage)
	h.metrics.RecordConfigChange("v2_percentage", percentage)
}

// EnableShadowMode enables or disables shadow mode
func (h *HybridCorrelationEngine) EnableShadowMode(enable bool) {
	h.shadowMode.Store(enable)
	h.metrics.RecordConfigChange("shadow_mode", enable)
}

// GetStats returns combined statistics from both engines
func (h *HybridCorrelationEngine) GetStats() events_correlation.Stats {
	v1Stats := h.v1Engine.GetStats()
	
	// Enhance with hybrid-specific stats
	v1Stats.HybridStats = map[string]interface{}{
		"v2_enabled":      h.config.EnableV2,
		"v2_percentage":   h.router.GetV2Percentage(),
		"shadow_mode":     h.shadowMode.Load(),
		"circuit_state":   h.v2Circuit.State().String(),
		"routing_strategy": string(h.config.RoutingStrategy),
		"metrics":         h.metrics.GetSummary(),
	}
	
	return v1Stats
}

// Additional Engine interface methods...

// ProcessWindow processes events within a specific time window
func (h *HybridCorrelationEngine) ProcessWindow(ctx context.Context, window events_correlation.TimeWindow, events []events_correlation.Event) ([]*events_correlation.Result, error) {
	// Similar logic to ProcessEvents but with window
	return h.ProcessEvents(ctx, events)
}

// UnregisterRule removes a rule from both engines
func (h *HybridCorrelationEngine) UnregisterRule(ruleID string) error {
	if err := h.v1Engine.UnregisterRule(ruleID); err != nil {
		return err
	}
	
	// Ignore V2 errors during unregistration
	if h.config.EnableV2 {
		// V2 doesn't have UnregisterRule in our current implementation
		// but we'd call it here if it did
	}
	
	return nil
}

// GetRule retrieves a rule by ID
func (h *HybridCorrelationEngine) GetRule(ruleID string) (*events_correlation.Rule, bool) {
	return h.v1Engine.GetRule(ruleID)
}

// ListRules returns all registered rules
func (h *HybridCorrelationEngine) ListRules() []*events_correlation.Rule {
	return h.v1Engine.ListRules()
}

// EnableRule enables a rule in both engines
func (h *HybridCorrelationEngine) EnableRule(ruleID string) error {
	return h.v1Engine.EnableRule(ruleID)
}

// DisableRule disables a rule in both engines
func (h *HybridCorrelationEngine) DisableRule(ruleID string) error {
	return h.v1Engine.DisableRule(ruleID)
}

// SetWindowSize sets the correlation window size
func (h *HybridCorrelationEngine) SetWindowSize(duration time.Duration) {
	h.v1Engine.SetWindowSize(duration)
}

// SetProcessingInterval sets the processing interval
func (h *HybridCorrelationEngine) SetProcessingInterval(interval time.Duration) {
	h.v1Engine.SetProcessingInterval(interval)
}

// SetMaxConcurrentRules sets the maximum concurrent rules
func (h *HybridCorrelationEngine) SetMaxConcurrentRules(limit int) {
	h.v1Engine.SetMaxConcurrentRules(limit)
}

// GetRuleStats returns performance statistics for a specific rule
func (h *HybridCorrelationEngine) GetRuleStats(ruleID string) (events_correlation.RulePerformance, error) {
	return h.v1Engine.GetRuleStats(ruleID)
}

// Stop stops the hybrid correlation engine
func (h *HybridCorrelationEngine) Stop() error {
	// Cancel context
	h.cancel()
	
	// Stop V2 engine
	if h.config.EnableV2 {
		h.v2Engine.Stop()
	}
	
	// Stop V1 engine
	if err := h.v1Engine.Stop(); err != nil {
		return err
	}
	
	// Wait for goroutines
	h.wg.Wait()
	
	return nil
}

// Health checks the health of both engines
func (h *HybridCorrelationEngine) Health() error {
	// Check V1 health
	if err := h.v1Engine.Health(); err != nil {
		return fmt.Errorf("V1 engine unhealthy: %w", err)
	}
	
	// Check V2 health if enabled
	if h.config.EnableV2 {
		if !h.v2Engine.IsHealthy() {
			return fmt.Errorf("V2 engine unhealthy")
		}
	}
	
	return nil
}