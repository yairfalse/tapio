package aggregator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test Rules Engine

func TestProductionRulesEngine_ValidateInsight(t *testing.T) {
	logger := zap.NewNop()
	config := &RulesEngineConfiguration{
		EnabledRules: []string{"confidence_threshold", "evidence_count"},
		RuleConfigs: map[string]interface{}{
			"confidence_threshold": map[string]interface{}{"min": 0.7},
			"evidence_count":       map[string]interface{}{"min": 2},
		},
	}

	re := &productionRulesEngine{
		logger: logger,
		config: config,
		tracer: mockTracer{},
		rules:  make(map[string]*Rule),
	}

	// Add test rules
	re.rules["confidence_threshold"] = &Rule{
		ID:          "confidence_threshold",
		Type:        "validation",
		Priority:    1,
		Description: "Check minimum confidence",
	}
	re.rules["evidence_count"] = &Rule{
		ID:          "evidence_count",
		Type:        "validation",
		Priority:    2,
		Description: "Check evidence count",
	}

	tests := []struct {
		name           string
		insight        *IntelligenceInsight
		expectedResult bool
		expectedIssues int
	}{
		{
			name: "valid_insight",
			insight: &IntelligenceInsight{
				ID:                "test-1",
				OverallConfidence: 0.8,
				Evidence: []*Evidence{
					{Type: "metric", Confidence: 0.8},
					{Type: "log", Confidence: 0.7},
					{Type: "trace", Confidence: 0.9},
				},
			},
			expectedResult: true,
			expectedIssues: 0,
		},
		{
			name: "low_confidence",
			insight: &IntelligenceInsight{
				ID:                "test-2",
				OverallConfidence: 0.6, // Below threshold
				Evidence: []*Evidence{
					{Type: "metric", Confidence: 0.8},
					{Type: "log", Confidence: 0.7},
					{Type: "trace", Confidence: 0.9},
				},
			},
			expectedResult: false,
			expectedIssues: 1,
		},
		{
			name: "insufficient_evidence",
			insight: &IntelligenceInsight{
				ID:                "test-3",
				OverallConfidence: 0.8,
				Evidence: []*Evidence{
					{Type: "metric", Confidence: 0.8}, // Only 1 evidence
				},
			},
			expectedResult: false,
			expectedIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := re.ValidateInsight(context.Background(), tt.insight)
			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.expectedResult, result.Valid)
			assert.Len(t, result.RuleViolations, tt.expectedIssues)
		})
	}
}

func TestProductionRulesEngine_ProcessRules(t *testing.T) {
	re := &productionRulesEngine{
		logger: zap.NewNop(),
		tracer: mockTracer{},
		rules: map[string]*Rule{
			"test-rule": {
				ID:          "test-rule",
				Type:        "enhancement",
				Priority:    1,
				Description: "Test rule",
			},
		},
	}

	insight := &IntelligenceInsight{
		ID:                "test-insight",
		OverallConfidence: 0.8,
	}

	result, err := re.ProcessRules(context.Background(), insight)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.AppliedRules, 1)
	assert.Equal(t, "test-rule", result.AppliedRules[0])
}

func TestProductionRulesEngine_UpdateRule(t *testing.T) {
	re := &productionRulesEngine{
		logger: zap.NewNop(),
		rules:  make(map[string]*Rule),
	}

	rule := &Rule{
		ID:          "new-rule",
		Type:        "validation",
		Priority:    5,
		Description: "New validation rule",
		Enabled:     true,
	}

	err := re.UpdateRule(context.Background(), rule)
	require.NoError(t, err)

	stored, exists := re.rules[rule.ID]
	assert.True(t, exists)
	assert.Equal(t, rule, stored)
}

func TestProductionRulesEngine_GetActiveRules(t *testing.T) {
	re := &productionRulesEngine{
		rules: map[string]*Rule{
			"enabled":  {ID: "enabled", Enabled: true},
			"disabled": {ID: "disabled", Enabled: false},
		},
	}

	activeRules, err := re.GetActiveRules(context.Background())
	require.NoError(t, err)
	assert.Len(t, activeRules, 1)
	assert.Equal(t, "enabled", activeRules[0].ID)
}

// Test Plugin Integrator

func TestProductionPluginIntegrator_RegisterPlugin(t *testing.T) {
	pi := &productionPluginIntegrator{
		logger:  zap.NewNop(),
		plugins: make(map[string]*Plugin),
	}

	plugin := &Plugin{
		ID:          "test-plugin",
		Name:        "Test Plugin",
		Type:        "enhancer",
		Version:     "1.0.0",
		Enabled:     true,
		Config:      map[string]interface{}{"key": "value"},
		Healthcheck: &PluginHealthcheck{Enabled: true},
	}

	err := pi.RegisterPlugin(context.Background(), plugin)
	require.NoError(t, err)

	stored, exists := pi.plugins[plugin.ID]
	assert.True(t, exists)
	assert.Equal(t, plugin, stored)
}

func TestProductionPluginIntegrator_ExecutePlugins(t *testing.T) {
	pi := &productionPluginIntegrator{
		logger:  zap.NewNop(),
		tracer:  mockTracer{},
		plugins: make(map[string]*Plugin),
	}

	// Add enabled plugin
	enabledPlugin := &Plugin{
		ID:      "enabled",
		Name:    "Enabled Plugin",
		Type:    "enhancer",
		Enabled: true,
	}
	pi.plugins[enabledPlugin.ID] = enabledPlugin

	// Add disabled plugin
	disabledPlugin := &Plugin{
		ID:      "disabled",
		Name:    "Disabled Plugin",
		Type:    "enhancer",
		Enabled: false,
	}
	pi.plugins[disabledPlugin.ID] = disabledPlugin

	insight := &IntelligenceInsight{
		ID:   "test-insight",
		Type: "test",
	}

	result, err := pi.ExecutePlugins(context.Background(), insight, "enhancer")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.ExecutedPlugins, 1) // Only enabled plugin
	assert.Equal(t, "enabled", result.ExecutedPlugins[0])
}

func TestProductionPluginIntegrator_GetPlugins(t *testing.T) {
	pi := &productionPluginIntegrator{
		plugins: map[string]*Plugin{
			"enhancer":  {ID: "enhancer", Type: "enhancer"},
			"validator": {ID: "validator", Type: "validator"},
			"enhancer2": {ID: "enhancer2", Type: "enhancer"},
		},
	}

	// Test with specific type
	enhancers, err := pi.GetPlugins(context.Background(), "enhancer")
	require.NoError(t, err)
	assert.Len(t, enhancers, 2)

	// Test with empty type (all plugins)
	allPlugins, err := pi.GetPlugins(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, allPlugins, 3)
}

// Test Worker Pool

func TestProductionWorkerPool_Start_Stop(t *testing.T) {
	config := &WorkerPoolConfiguration{
		WorkerCount:       2,
		QueueSize:         10,
		ShutdownTimeout:   5 * time.Second,
		HealthcheckPeriod: 100 * time.Millisecond,
	}

	wp := &productionWorkerPool{
		logger: zap.NewNop(),
		config: config,
		tracer: mockTracer{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := wp.Start(ctx)
	require.NoError(t, err)
	assert.True(t, wp.IsRunning())

	err = wp.Stop()
	require.NoError(t, err)
	assert.False(t, wp.IsRunning())
}

func TestProductionWorkerPool_Submit(t *testing.T) {
	config := &WorkerPoolConfiguration{
		WorkerCount:       1,
		QueueSize:         2,
		ShutdownTimeout:   1 * time.Second,
		HealthcheckPeriod: 100 * time.Millisecond,
	}

	wp := &productionWorkerPool{
		logger: zap.NewNop(),
		config: config,
		tracer: mockTracer{},
	}

	ctx := context.Background()
	err := wp.Start(ctx)
	require.NoError(t, err)
	defer wp.Stop()

	// Test successful submission
	var executed int32
	task := &WorkerTask{
		ID:   "test-task",
		Type: "test",
		Execute: func(ctx context.Context) error {
			atomic.AddInt32(&executed, 1)
			return nil
		},
	}

	err = wp.Submit(ctx, task)
	require.NoError(t, err)

	// Wait for execution
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(1), atomic.LoadInt32(&executed))

	// Test queue full scenario
	// Fill the queue beyond capacity
	for i := 0; i < config.QueueSize+5; i++ {
		blockingTask := &WorkerTask{
			ID:   fmt.Sprintf("blocking-task-%d", i),
			Type: "blocking",
			Execute: func(ctx context.Context) error {
				time.Sleep(100 * time.Millisecond)
				return nil
			},
		}
		wp.Submit(ctx, blockingTask) // Some will fail when queue is full
	}

	stats := wp.GetStats()
	assert.Greater(t, stats.TasksRejected, int64(0))
}

func TestProductionWorkerPool_GetStats(t *testing.T) {
	wp := &productionWorkerPool{
		logger: zap.NewNop(),
		config: &WorkerPoolConfiguration{
			WorkerCount: 2,
			QueueSize:   10,
		},
		tracer: mockTracer{},
	}

	ctx := context.Background()
	err := wp.Start(ctx)
	require.NoError(t, err)
	defer wp.Stop()

	stats := wp.GetStats()
	assert.NotNil(t, stats)
	assert.Equal(t, 2, stats.WorkerCount)
	assert.Equal(t, int64(0), stats.TasksProcessed)
	assert.Equal(t, int64(0), stats.TasksFailed)
	assert.Equal(t, int64(0), stats.TasksRejected)
}

// Test Cache Manager

func TestProductionCacheManager_Set_Get(t *testing.T) {
	config := &CacheConfiguration{
		DefaultTTL:    1 * time.Second,
		MaxSize:       100,
		CleanupPeriod: 100 * time.Millisecond,
	}

	cm := &productionCacheManager{
		logger: zap.NewNop(),
		config: config,
		tracer: mockTracer{},
		cache:  make(map[string]*CacheEntry),
	}

	ctx := context.Background()

	// Test Set/Get
	key := "test-key"
	value := "test-value"

	err := cm.Set(ctx, key, value, time.Second)
	require.NoError(t, err)

	retrieved, found, err := cm.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, value, retrieved)

	// Test cache miss
	_, found, err = cm.Get(ctx, "nonexistent-key")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestProductionCacheManager_Delete(t *testing.T) {
	cm := &productionCacheManager{
		logger: zap.NewNop(),
		config: &CacheConfiguration{DefaultTTL: time.Hour},
		tracer: mockTracer{},
		cache:  make(map[string]*CacheEntry),
	}

	ctx := context.Background()
	key := "test-key"
	value := "test-value"

	// Set then delete
	err := cm.Set(ctx, key, value, time.Hour)
	require.NoError(t, err)

	err = cm.Delete(ctx, key)
	require.NoError(t, err)

	// Should not be found
	_, found, err := cm.Get(ctx, key)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestProductionCacheManager_Clear(t *testing.T) {
	cm := &productionCacheManager{
		logger: zap.NewNop(),
		config: &CacheConfiguration{DefaultTTL: time.Hour},
		tracer: mockTracer{},
		cache:  make(map[string]*CacheEntry),
	}

	ctx := context.Background()

	// Set multiple entries
	cm.Set(ctx, "key1", "value1", time.Hour)
	cm.Set(ctx, "key2", "value2", time.Hour)

	err := cm.Clear(ctx)
	require.NoError(t, err)

	// Both should be gone
	_, found1, _ := cm.Get(ctx, "key1")
	_, found2, _ := cm.Get(ctx, "key2")
	assert.False(t, found1)
	assert.False(t, found2)
}

func TestProductionCacheManager_GetStats(t *testing.T) {
	cm := &productionCacheManager{
		logger: zap.NewNop(),
		config: &CacheConfiguration{DefaultTTL: time.Hour},
		tracer: mockTracer{},
		cache:  make(map[string]*CacheEntry),
	}

	ctx := context.Background()

	// Initial stats
	stats := cm.GetStats()
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Misses)
	assert.Equal(t, int64(0), stats.Entries)

	// Add entry and test hit
	cm.Set(ctx, "key", "value", time.Hour)
	cm.Get(ctx, "key")

	stats = cm.GetStats()
	assert.Equal(t, int64(1), stats.Hits)
	assert.Equal(t, int64(0), stats.Misses)
	assert.Equal(t, int64(1), stats.Entries)

	// Test miss
	cm.Get(ctx, "nonexistent")
	stats = cm.GetStats()
	assert.Equal(t, int64(1), stats.Hits)
	assert.Equal(t, int64(1), stats.Misses)
}

func TestProductionCacheManager_TTL_Expiration(t *testing.T) {
	cm := &productionCacheManager{
		logger: zap.NewNop(),
		config: &CacheConfiguration{
			DefaultTTL:    50 * time.Millisecond,
			CleanupPeriod: 10 * time.Millisecond,
		},
		tracer: mockTracer{},
		cache:  make(map[string]*CacheEntry),
	}

	ctx := context.Background()

	// Set entry with short TTL
	err := cm.Set(ctx, "short-lived", "value", 50*time.Millisecond)
	require.NoError(t, err)

	// Should be found immediately
	_, found, err := cm.Get(ctx, "short-lived")
	require.NoError(t, err)
	assert.True(t, found)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	_, found, err = cm.Get(ctx, "short-lived")
	require.NoError(t, err)
	assert.False(t, found)
}

// Test Circuit Breaker

func TestProductionCircuitBreaker_Execute_Success(t *testing.T) {
	config := &CircuitBreakerConfiguration{
		FailureThreshold: 5,
		ResetTimeout:     100 * time.Millisecond,
		HalfOpenMaxCalls: 3,
	}

	cb := &productionCircuitBreaker{
		logger: zap.NewNop(),
		config: config,
		tracer: mockTracer{},
		state:  CircuitBreakerStateClosed,
	}

	ctx := context.Background()

	// Test successful execution
	var executed bool
	operation := func(ctx context.Context) error {
		executed = true
		return nil
	}

	err := cb.Execute(ctx, "test-operation", operation)
	require.NoError(t, err)
	assert.True(t, executed)
	assert.Equal(t, CircuitBreakerStateClosed, cb.GetState())
}

func TestProductionCircuitBreaker_Execute_Failures_TriggerOpen(t *testing.T) {
	config := &CircuitBreakerConfiguration{
		FailureThreshold: 2, // Low threshold for testing
		ResetTimeout:     100 * time.Millisecond,
		HalfOpenMaxCalls: 3,
	}

	cb := &productionCircuitBreaker{
		logger: zap.NewNop(),
		config: config,
		tracer: mockTracer{},
		state:  CircuitBreakerStateClosed,
	}

	ctx := context.Background()
	failureOperation := func(ctx context.Context) error {
		return errors.New("operation failed")
	}

	// Execute failures to trigger open state
	for i := 0; i < config.FailureThreshold; i++ {
		err := cb.Execute(ctx, "failing-operation", failureOperation)
		assert.Error(t, err)
	}

	// Should be open now
	assert.Equal(t, CircuitBreakerStateOpen, cb.GetState())

	// Next execution should fail fast
	err := cb.Execute(ctx, "blocked-operation", func(ctx context.Context) error {
		t.Fatal("Should not execute when circuit is open")
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")
}

func TestProductionCircuitBreaker_HalfOpen_Recovery(t *testing.T) {
	config := &CircuitBreakerConfiguration{
		FailureThreshold: 1,
		ResetTimeout:     50 * time.Millisecond, // Short timeout for testing
		HalfOpenMaxCalls: 2,
	}

	cb := &productionCircuitBreaker{
		logger: zap.NewNop(),
		config: config,
		tracer: mockTracer{},
		state:  CircuitBreakerStateClosed,
	}

	ctx := context.Background()

	// Trigger open state
	cb.Execute(ctx, "failing", func(ctx context.Context) error {
		return errors.New("failure")
	})
	assert.Equal(t, CircuitBreakerStateOpen, cb.GetState())

	// Wait for half-open transition
	time.Sleep(100 * time.Millisecond)

	// Should transition to half-open on next call
	err := cb.Execute(ctx, "recovery-test", func(ctx context.Context) error {
		return nil // Success
	})
	require.NoError(t, err)
	assert.Equal(t, CircuitBreakerStateHalfOpen, cb.GetState())

	// Another success should close the circuit
	err = cb.Execute(ctx, "recovery-test-2", func(ctx context.Context) error {
		return nil // Success
	})
	require.NoError(t, err)
	assert.Equal(t, CircuitBreakerStateClosed, cb.GetState())
}

func TestProductionCircuitBreaker_GetStats(t *testing.T) {
	cb := &productionCircuitBreaker{
		logger:     zap.NewNop(),
		config:     &CircuitBreakerConfiguration{FailureThreshold: 5},
		tracer:     mockTracer{},
		state:      CircuitBreakerStateClosed,
		failures:   3,
		successes:  7,
		rejections: 2,
	}

	stats := cb.GetStats()
	assert.Equal(t, CircuitBreakerStateClosed, stats.State)
	assert.Equal(t, int64(3), stats.Failures)
	assert.Equal(t, int64(7), stats.Successes)
	assert.Equal(t, int64(2), stats.Rejections)
	assert.Equal(t, int64(10), stats.TotalCalls) // successes + failures
}

// Test Rate Limiter

func TestProductionRateLimiter_Allow_Success(t *testing.T) {
	config := &RateLimiterConfiguration{
		RequestsPerSecond: 10,
		BurstSize:         5,
		WindowSize:        time.Second,
	}

	rl := &productionRateLimiter{
		logger:     zap.NewNop(),
		config:     config,
		tracer:     mockTracer{},
		tokens:     float64(config.BurstSize),
		lastRefill: time.Now(),
	}

	ctx := context.Background()

	// Should allow requests within burst size
	for i := 0; i < config.BurstSize; i++ {
		allowed, err := rl.Allow(ctx, "test-key")
		require.NoError(t, err)
		assert.True(t, allowed, "Request %d should be allowed", i)
	}

	// Next request should be denied (burst exhausted)
	allowed, err := rl.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestProductionRateLimiter_Allow_Refill(t *testing.T) {
	config := &RateLimiterConfiguration{
		RequestsPerSecond: 2, // 2 tokens per second
		BurstSize:         1,
		WindowSize:        time.Second,
	}

	rl := &productionRateLimiter{
		logger:     zap.NewNop(),
		config:     config,
		tracer:     mockTracer{},
		tokens:     1,
		lastRefill: time.Now().Add(-time.Second), // Force refill
	}

	ctx := context.Background()

	// Should allow (burst + refilled tokens)
	allowed, err := rl.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestProductionRateLimiter_GetStats(t *testing.T) {
	rl := &productionRateLimiter{
		logger:  zap.NewNop(),
		config:  &RateLimiterConfiguration{RequestsPerSecond: 10, BurstSize: 5},
		tracer:  mockTracer{},
		tokens:  3.5,
		allowed: 15,
		denied:  3,
	}

	stats := rl.GetStats()
	assert.Equal(t, int64(15), stats.RequestsAllowed)
	assert.Equal(t, int64(3), stats.RequestsDenied)
	assert.InDelta(t, 3.5, stats.CurrentTokens, 0.1)
	assert.InDelta(t, 10.0, stats.RequestsPerSecond, 0.1)
}

func TestProductionRateLimiter_SetRate(t *testing.T) {
	rl := &productionRateLimiter{
		logger: zap.NewNop(),
		config: &RateLimiterConfiguration{RequestsPerSecond: 5, BurstSize: 3},
		tracer: mockTracer{},
	}

	newConfig := &RateLimiterConfiguration{
		RequestsPerSecond: 20,
		BurstSize:         10,
		WindowSize:        time.Second,
	}

	err := rl.SetRate(context.Background(), newConfig)
	require.NoError(t, err)

	assert.Equal(t, newConfig, rl.config)
	assert.Equal(t, float64(newConfig.BurstSize), rl.tokens) // Tokens reset to burst size
}

// Benchmark tests for performance validation

func BenchmarkWorkerPool_Submit(b *testing.B) {
	config := &WorkerPoolConfiguration{
		WorkerCount:     4,
		QueueSize:       1000,
		ShutdownTimeout: time.Second,
	}

	wp := &productionWorkerPool{
		logger: zap.NewNop(),
		config: config,
		tracer: mockTracer{},
	}

	ctx := context.Background()
	wp.Start(ctx)
	defer wp.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			task := &WorkerTask{
				ID:   fmt.Sprintf("bench-task-%d", i),
				Type: "bench",
				Execute: func(ctx context.Context) error {
					time.Sleep(time.Microsecond) // Simulate minimal work
					return nil
				},
			}
			wp.Submit(ctx, task)
			i++
		}
	})
}

func BenchmarkCacheManager_Get(b *testing.B) {
	cm := &productionCacheManager{
		logger: zap.NewNop(),
		config: &CacheConfiguration{DefaultTTL: time.Hour},
		tracer: mockTracer{},
		cache:  make(map[string]*CacheEntry),
	}

	ctx := context.Background()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key-%d", i)
		cm.Set(ctx, key, fmt.Sprintf("value-%d", i), time.Hour)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key-%d", i%1000)
			cm.Get(ctx, key)
			i++
		}
	})
}

func BenchmarkRateLimiter_Allow(b *testing.B) {
	rl := &productionRateLimiter{
		logger: zap.NewNop(),
		config: &RateLimiterConfiguration{
			RequestsPerSecond: 1000,
			BurstSize:         100,
		},
		tracer:     mockTracer{},
		tokens:     100,
		lastRefill: time.Now(),
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow(ctx, "bench-key")
		}
	})
}
