package hybrid

import (
	"context"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/correlation_v2"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// MockV1Engine implements events_correlation.Engine for testing
type MockV1Engine struct {
	rules     map[string]*events_correlation.Rule
	results   []*events_correlation.Result
	processCount int
}

func NewMockV1Engine() *MockV1Engine {
	return &MockV1Engine{
		rules: make(map[string]*events_correlation.Rule),
	}
}

func (m *MockV1Engine) Start(ctx context.Context) error {
	return nil
}

func (m *MockV1Engine) Stop() error {
	return nil
}

func (m *MockV1Engine) RegisterRule(rule *events_correlation.Rule) error {
	m.rules[rule.ID] = rule
	return nil
}

func (m *MockV1Engine) UnregisterRule(ruleID string) error {
	delete(m.rules, ruleID)
	return nil
}

func (m *MockV1Engine) GetRule(ruleID string) (*events_correlation.Rule, bool) {
	rule, exists := m.rules[ruleID]
	return rule, exists
}

func (m *MockV1Engine) ListRules() []*events_correlation.Rule {
	rules := make([]*events_correlation.Rule, 0, len(m.rules))
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	return rules
}

func (m *MockV1Engine) EnableRule(ruleID string) error {
	if rule, exists := m.rules[ruleID]; exists {
		rule.Enabled = true
	}
	return nil
}

func (m *MockV1Engine) DisableRule(ruleID string) error {
	if rule, exists := m.rules[ruleID]; exists {
		rule.Enabled = false
	}
	return nil
}

func (m *MockV1Engine) ProcessEvents(ctx context.Context, events []events_correlation.Event) ([]*events_correlation.Result, error) {
	m.processCount++
	
	// Create mock results based on events
	results := make([]*events_correlation.Result, 0, len(events))
	for _, event := range events {
		if event.Type == "memory_pressure" {
			results = append(results, &events_correlation.Result{
				RuleID:     "memory-pressure-rule",
				RuleName:   "Memory Pressure Detection",
				Timestamp:  time.Now(),
				Confidence: 0.8,
				Severity:   events_correlation.SeverityMedium,
				Category:   events_correlation.CategoryResource,
				Title:      "Memory pressure detected",
				Description: "High memory pressure on container",
				Evidence: events_correlation.Evidence{
					Events:   []events_correlation.Event{event},
					Entities: []events_correlation.Entity{event.Entity},
				},
			})
		}
	}
	
	m.results = results
	return results, nil
}

func (m *MockV1Engine) ProcessWindow(ctx context.Context, window events_correlation.TimeWindow, events []events_correlation.Event) ([]*events_correlation.Result, error) {
	return m.ProcessEvents(ctx, events)
}

func (m *MockV1Engine) SetWindowSize(duration time.Duration) {}

func (m *MockV1Engine) SetProcessingInterval(interval time.Duration) {}

func (m *MockV1Engine) SetMaxConcurrentRules(limit int) {}

func (m *MockV1Engine) GetStats() events_correlation.Stats {
	return events_correlation.Stats{
		EventsProcessed: uint64(m.processCount),
		RulesRegistered: len(m.rules),
	}
}

func (m *MockV1Engine) GetRuleStats(ruleID string) (events_correlation.RulePerformance, error) {
	return events_correlation.RulePerformance{}, nil
}

func (m *MockV1Engine) Health() error {
	return nil
}

// Helper functions for tests
func createTestEvents() []events_correlation.Event {
	return []events_correlation.Event{
		{
			ID:        "event-1",
			Timestamp: time.Now(),
			Source:    events_correlation.SourceEBPF,
			Type:      "memory_pressure",
			Entity: events_correlation.Entity{
				Type: "container",
				UID:  "container-1",
				Name: "app-container",
			},
			Attributes: map[string]interface{}{
				"memory_usage": 0.85,
				"threshold":    0.8,
			},
			Fingerprint: "memory-pressure-container-1",
			Labels: map[string]string{
				"severity": "medium",
				"rule_id":  "memory-pressure-rule",
			},
		},
		{
			ID:        "event-2",
			Timestamp: time.Now(),
			Source:    events_correlation.SourceKubernetes,
			Type:      "cpu_throttle",
			Entity: events_correlation.Entity{
				Type: "pod",
				UID:  "pod-1",
				Name: "app-pod",
			},
			Attributes: map[string]interface{}{
				"throttle_ratio": 0.6,
				"cpu_limit":      "500m",
			},
			Fingerprint: "cpu-throttle-pod-1",
			Labels: map[string]string{
				"severity": "high",
				"rule_id":  "cpu-throttle-rule",
			},
		},
	}
}

func createTestRule() *events_correlation.Rule {
	return &events_correlation.Rule{
		ID:          "test-rule",
		Name:        "Test Memory Rule",
		Description: "Test rule for memory pressure",
		Category:    events_correlation.CategoryResource,
		Tags:        []string{"v2-compatible", "memory", "resource"},
		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceEBPF,
			events_correlation.SourceKubernetes,
		},
		Enabled: true,
		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			events := ctx.GetEvents(events_correlation.Filter{})
			if len(events) > 0 {
				return &events_correlation.Result{
					RuleID:     "test-rule",
					RuleName:   "Test Memory Rule",
					Timestamp:  time.Now(),
					Confidence: 0.9,
					Severity:   events_correlation.SeverityMedium,
					Category:   events_correlation.CategoryResource,
					Title:      "Test correlation detected",
				}
			}
			return nil
		},
	}
}

func TestHybridEngine_BasicFunctionality(t *testing.T) {
	// Create mock V1 engine
	v1Engine := NewMockV1Engine()
	
	// Create V2 config
	v2Config := correlation_v2.EngineConfig{
		NumShards:             2,
		BufferSize:            1024, // Must be power of 2
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		BackpressureThreshold: 0.8,
	}
	
	// Create hybrid config
	hybridConfig := HybridConfig{
		EnableV2:        false, // Start with V2 disabled
		EnableShadowMode: false,
		V2Percentage:    0,
		RoutingStrategy: RoutingRandom,
		RollbackConfig: RollbackConfig{
			ErrorThreshold:   0.05,
			LatencyThreshold: 100 * time.Millisecond,
			WindowSize:       1 * time.Minute,
			MinSamples:       10,
		},
		BatchSplitSize:  50,
		MaxParallel:     4,
		MetricsInterval: 10 * time.Second,
		CompareResults:  true,
	}
	
	// Create hybrid engine
	hybrid, err := NewHybridEngine(v1Engine, v2Config, hybridConfig)
	if err != nil {
		t.Fatalf("Failed to create hybrid engine: %v", err)
	}
	defer hybrid.Stop()
	
	// Start the engine
	ctx := context.Background()
	if err := hybrid.Start(ctx); err != nil {
		t.Fatalf("Failed to start hybrid engine: %v", err)
	}
	
	// Test rule registration
	rule := createTestRule()
	if err := hybrid.RegisterRule(rule); err != nil {
		t.Errorf("Failed to register rule: %v", err)
	}
	
	// Verify rule was registered
	if retrievedRule, exists := hybrid.GetRule(rule.ID); !exists {
		t.Error("Rule not found after registration")
	} else if retrievedRule.ID != rule.ID {
		t.Errorf("Retrieved rule ID mismatch: got %s, want %s", retrievedRule.ID, rule.ID)
	}
	
	// Test event processing
	events := createTestEvents()
	results, err := hybrid.ProcessEvents(ctx, events)
	if err != nil {
		t.Errorf("Failed to process events: %v", err)
	}
	
	// Verify results
	if len(results) == 0 {
		t.Error("Expected results from event processing")
	}
	
	// Check that V1 was used (since V2 is disabled)
	if v1Engine.processCount != 1 {
		t.Errorf("Expected V1 engine to be called once, got %d", v1Engine.processCount)
	}
}

func TestHybridEngine_V2Routing(t *testing.T) {
	v1Engine := NewMockV1Engine()
	
	v2Config := correlation_v2.EngineConfig{
		NumShards:             2,
		BufferSize:            1024, // Must be power of 2
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		BackpressureThreshold: 0.8,
	}
	
	hybridConfig := HybridConfig{
		EnableV2:        true,  // Enable V2
		EnableShadowMode: false,
		V2Percentage:    50,    // 50% to V2
		RoutingStrategy: RoutingRandom,
		RollbackConfig: RollbackConfig{
			ErrorThreshold:   0.05,
			LatencyThreshold: 100 * time.Millisecond,
			WindowSize:       1 * time.Minute,
			MinSamples:       10,
		},
		MetricsInterval: 1 * time.Second,
	}
	
	hybrid, err := NewHybridEngine(v1Engine, v2Config, hybridConfig)
	if err != nil {
		t.Fatalf("Failed to create hybrid engine: %v", err)
	}
	defer hybrid.Stop()
	
	ctx := context.Background()
	if err := hybrid.Start(ctx); err != nil {
		t.Fatalf("Failed to start hybrid engine: %v", err)
	}
	
	// Process multiple batches to test routing
	events := createTestEvents()
	processCount := 10
	
	for i := 0; i < processCount; i++ {
		_, err := hybrid.ProcessEvents(ctx, events)
		if err != nil {
			t.Errorf("Failed to process events batch %d: %v", i, err)
		}
	}
	
	// Get metrics
	stats := hybrid.GetStats()
	hybridStats := stats.HybridStats.(map[string]interface{})
	
	// Verify V2 is enabled
	if !hybridStats["v2_enabled"].(bool) {
		t.Error("Expected V2 to be enabled")
	}
	
	// Verify percentage is set correctly
	if hybridStats["v2_percentage"].(int32) != 50 {
		t.Errorf("Expected V2 percentage to be 50, got %v", hybridStats["v2_percentage"])
	}
}

func TestHybridEngine_ShadowMode(t *testing.T) {
	v1Engine := NewMockV1Engine()
	
	v2Config := correlation_v2.EngineConfig{
		NumShards:             2,
		BufferSize:            1024, // Must be power of 2
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		BackpressureThreshold: 0.8,
	}
	
	hybridConfig := HybridConfig{
		EnableV2:        true,
		EnableShadowMode: true,  // Enable shadow mode
		V2Percentage:    100,    // Route to V2, but shadow mode should use V1
		RoutingStrategy: RoutingRandom,
		RollbackConfig: RollbackConfig{
			ErrorThreshold:   0.05,
			LatencyThreshold: 100 * time.Millisecond,
			WindowSize:       1 * time.Minute,
			MinSamples:       10,
		},
		MetricsInterval: 1 * time.Second,
		CompareResults:  true,
	}
	
	hybrid, err := NewHybridEngine(v1Engine, v2Config, hybridConfig)
	if err != nil {
		t.Fatalf("Failed to create hybrid engine: %v", err)
	}
	defer hybrid.Stop()
	
	ctx := context.Background()
	if err := hybrid.Start(ctx); err != nil {
		t.Fatalf("Failed to start hybrid engine: %v", err)
	}
	
	// Process events
	events := createTestEvents()
	results, err := hybrid.ProcessEvents(ctx, events)
	if err != nil {
		t.Errorf("Failed to process events: %v", err)
	}
	
	// In shadow mode, should always get V1 results
	if len(results) == 0 {
		t.Error("Expected results from shadow mode processing")
	}
	
	// V1 should have been called (shadow mode returns V1 results)
	if v1Engine.processCount != 1 {
		t.Errorf("Expected V1 engine to be called in shadow mode, got %d calls", v1Engine.processCount)
	}
	
	// Verify shadow mode is enabled in stats
	stats := hybrid.GetStats()
	hybridStats := stats.HybridStats.(map[string]interface{})
	
	if !hybridStats["shadow_mode"].(bool) {
		t.Error("Expected shadow mode to be enabled in stats")
	}
}

func TestHybridEngine_CircuitBreaker(t *testing.T) {
	v1Engine := NewMockV1Engine()
	
	v2Config := correlation_v2.EngineConfig{
		NumShards:             2,
		BufferSize:            1024, // Must be power of 2
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		BackpressureThreshold: 0.8,
	}
	
	hybridConfig := HybridConfig{
		EnableV2:        true,
		EnableShadowMode: false,
		V2Percentage:    100,  // Route everything to V2
		RoutingStrategy: RoutingRandom,
		RollbackConfig: RollbackConfig{
			ErrorThreshold:   0.05,
			LatencyThreshold: 100 * time.Millisecond,
			WindowSize:       1 * time.Minute,
			MinSamples:       10,
		},
		MetricsInterval: 1 * time.Second,
	}
	
	hybrid, err := NewHybridEngine(v1Engine, v2Config, hybridConfig)
	if err != nil {
		t.Fatalf("Failed to create hybrid engine: %v", err)
	}
	defer hybrid.Stop()
	
	ctx := context.Background()
	if err := hybrid.Start(ctx); err != nil {
		t.Fatalf("Failed to start hybrid engine: %v", err)
	}
	
	// Get initial circuit breaker state
	stats := hybrid.GetStats()
	hybridStats := stats.HybridStats.(map[string]interface{})
	initialCircuitState := hybridStats["circuit_state"].(string)
	
	if initialCircuitState != "closed" {
		t.Errorf("Expected initial circuit state to be 'closed', got %s", initialCircuitState)
	}
	
	// Process events (should trigger V2, but V2 might fail and open circuit)
	events := createTestEvents()
	_, err = hybrid.ProcessEvents(ctx, events)
	if err != nil {
		t.Errorf("Failed to process events: %v", err)
	}
	
	// Check if fallback to V1 occurred
	if v1Engine.processCount > 0 {
		t.Log("V2 failed and fell back to V1 (expected behavior)")
	}
}

func TestHybridEngine_MetricsCollection(t *testing.T) {
	v1Engine := NewMockV1Engine()
	
	v2Config := correlation_v2.EngineConfig{
		NumShards:             2,
		BufferSize:            1024, // Must be power of 2
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		BackpressureThreshold: 0.8,
	}
	
	hybridConfig := HybridConfig{
		EnableV2:        false,  // Start with V2 disabled for predictable metrics
		EnableShadowMode: false,
		V2Percentage:    0,
		RoutingStrategy: RoutingRandom,
		MetricsInterval: 100 * time.Millisecond,  // Fast metrics for testing
	}
	
	hybrid, err := NewHybridEngine(v1Engine, v2Config, hybridConfig)
	if err != nil {
		t.Fatalf("Failed to create hybrid engine: %v", err)
	}
	defer hybrid.Stop()
	
	ctx := context.Background()
	if err := hybrid.Start(ctx); err != nil {
		t.Fatalf("Failed to start hybrid engine: %v", err)
	}
	
	// Process some events
	events := createTestEvents()
	for i := 0; i < 5; i++ {
		_, err := hybrid.ProcessEvents(ctx, events)
		if err != nil {
			t.Errorf("Failed to process events: %v", err)
		}
	}
	
	// Wait for metrics collection
	time.Sleep(200 * time.Millisecond)
	
	// Get metrics
	stats := hybrid.GetStats()
	hybridStats := stats.HybridStats.(map[string]interface{})
	metrics := hybridStats["metrics"].(map[string]interface{})
	
	// Verify metrics structure
	if usage, ok := metrics["usage"].(map[string]interface{}); ok {
		if v1Count := usage["v1_count"]; v1Count == nil {
			t.Error("Expected v1_count in usage metrics")
		}
	} else {
		t.Error("Expected usage metrics")
	}
	
	if errors, ok := metrics["errors"].(map[string]interface{}); ok {
		if v1Errors := errors["v1_errors"]; v1Errors == nil {
			t.Error("Expected v1_errors in error metrics")
		}
	} else {
		t.Error("Expected error metrics")
	}
}

func TestHybridEngine_DynamicConfiguration(t *testing.T) {
	v1Engine := NewMockV1Engine()
	
	v2Config := correlation_v2.EngineConfig{
		NumShards:             2,
		BufferSize:            1024, // Must be power of 2
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		BackpressureThreshold: 0.8,
	}
	
	hybridConfig := HybridConfig{
		EnableV2:        true,
		V2Percentage:    25,
		RoutingStrategy: RoutingRandom,
		MetricsInterval: 1 * time.Second,
	}
	
	hybrid, err := NewHybridEngine(v1Engine, v2Config, hybridConfig)
	if err != nil {
		t.Fatalf("Failed to create hybrid engine: %v", err)
	}
	defer hybrid.Stop()
	
	ctx := context.Background()
	if err := hybrid.Start(ctx); err != nil {
		t.Fatalf("Failed to start hybrid engine: %v", err)
	}
	
	// Test dynamic percentage update
	hybrid.UpdateV2Percentage(75)
	
	stats := hybrid.GetStats()
	hybridStats := stats.HybridStats.(map[string]interface{})
	
	if percentage := hybridStats["v2_percentage"].(int32); percentage != 75 {
		t.Errorf("Expected V2 percentage to be 75 after update, got %d", percentage)
	}
	
	// Test shadow mode toggle
	hybrid.EnableShadowMode(true)
	
	stats = hybrid.GetStats()
	hybridStats = stats.HybridStats.(map[string]interface{})
	
	if !hybridStats["shadow_mode"].(bool) {
		t.Error("Expected shadow mode to be enabled after toggle")
	}
	
	// Test boundary conditions
	hybrid.UpdateV2Percentage(-10)  // Should be clamped to 0
	stats = hybrid.GetStats()
	hybridStats = stats.HybridStats.(map[string]interface{})
	
	if percentage := hybridStats["v2_percentage"].(int32); percentage != 0 {
		t.Errorf("Expected V2 percentage to be clamped to 0, got %d", percentage)
	}
	
	hybrid.UpdateV2Percentage(150)  // Should be clamped to 100
	stats = hybrid.GetStats()
	hybridStats = stats.HybridStats.(map[string]interface{})
	
	if percentage := hybridStats["v2_percentage"].(int32); percentage != 100 {
		t.Errorf("Expected V2 percentage to be clamped to 100, got %d", percentage)
	}
}

func TestHybridEngine_HealthChecks(t *testing.T) {
	v1Engine := NewMockV1Engine()
	
	v2Config := correlation_v2.EngineConfig{
		NumShards:             2,
		BufferSize:            1024, // Must be power of 2
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		BackpressureThreshold: 0.8,
	}
	
	hybridConfig := HybridConfig{
		EnableV2:        false,  // V2 disabled, should be healthy
		V2Percentage:    0,
		MetricsInterval: 1 * time.Second,
	}
	
	hybrid, err := NewHybridEngine(v1Engine, v2Config, hybridConfig)
	if err != nil {
		t.Fatalf("Failed to create hybrid engine: %v", err)
	}
	defer hybrid.Stop()
	
	ctx := context.Background()
	if err := hybrid.Start(ctx); err != nil {
		t.Fatalf("Failed to start hybrid engine: %v", err)
	}
	
	// Test health check
	if err := hybrid.Health(); err != nil {
		t.Errorf("Expected hybrid engine to be healthy: %v", err)
	}
}