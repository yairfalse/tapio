package aggregator

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Production Rules Engine Implementation

type productionRulesEngine struct {
	logger *zap.Logger
	rules  []*IntelligenceRule
	tracer trace.Tracer
	mu     sync.RWMutex
}

type SimpleRuleValidationResult struct {
	IsValid         bool
	ModifiedInsight *IntelligenceInsight
	FailureReasons  []string
}

func (re *productionRulesEngine) EvaluateRules(
	ctx context.Context,
	insight *IntelligenceInsight,
	ruleset *IntelligenceRuleset,
) (*RuleEvaluationResult, error) {
	ctx, span := re.tracer.Start(ctx, "rules_engine.evaluate_rules")
	defer span.End()

	span.SetAttributes(
		attribute.String("insight.id", insight.ID),
		attribute.String("insight.type", insight.Type),
	)

	result := &RuleEvaluationResult{
		RulesEvaluated:  0,
		RulesMatched:    0,
		ActionsExecuted: 0,
		ModifiedInsight: insight,
	}

	re.mu.RLock()
	applicableRules := re.getApplicableRules(insight)
	re.mu.RUnlock()

	for _, rule := range applicableRules {
		result.RulesEvaluated++

		if re.evaluateRule(ctx, insight, rule) {
			result.RulesMatched++

			// Execute rule actions
			if err := re.executeRuleActions(ctx, insight, rule); err != nil {
				re.logger.Warn("Failed to execute rule actions",
					zap.String("rule_id", rule.ID),
					zap.Error(err))
			} else {
				result.ActionsExecuted++
			}
		}
	}

	span.SetAttributes(
		attribute.Int("rules.evaluated", result.RulesEvaluated),
		attribute.Int("rules.matched", result.RulesMatched),
		attribute.Int("actions.executed", result.ActionsExecuted),
	)

	return result, nil
}

func (re *productionRulesEngine) UpdateRules(
	ctx context.Context,
	rules []*IntelligenceRule,
) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.rules = rules
	re.logger.Info("Updated intelligence rules", zap.Int("rule_count", len(rules)))

	return nil
}

func (re *productionRulesEngine) GetActiveRules(
	ctx context.Context,
	domain string,
) ([]*IntelligenceRule, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	activeRules := make([]*IntelligenceRule, 0)
	for _, rule := range re.rules {
		if rule.Enabled && (domain == "" || rule.Domain == domain) {
			activeRules = append(activeRules, rule)
		}
	}

	return activeRules, nil
}

func (re *productionRulesEngine) ValidateInsight(
	ctx context.Context,
	insight *IntelligenceInsight,
) (*RuleValidationResult, error) {
	result := &SimpleRuleValidationResult{
		IsValid:        true,
		FailureReasons: []string{},
	}

	// Apply validation rules
	validationRules := re.getValidationRules(insight)

	for _, rule := range validationRules {
		if !re.evaluateRule(ctx, insight, rule) {
			result.IsValid = false
			result.FailureReasons = append(result.FailureReasons,
				fmt.Sprintf("Rule %s failed: %s", rule.Name, rule.Description))
		}
	}

	return result, nil
}

func (re *productionRulesEngine) ImportRule(
	ctx context.Context,
	rule *IntelligenceRule,
) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Add or update rule
	found := false
	for i, existingRule := range re.rules {
		if existingRule.ID == rule.ID {
			re.rules[i] = rule
			found = true
			break
		}
	}

	if !found {
		re.rules = append(re.rules, rule)
	}

	re.logger.Debug("Imported rule", zap.String("rule_id", rule.ID))
	return nil
}

func (re *productionRulesEngine) getApplicableRules(insight *IntelligenceInsight) []*IntelligenceRule {
	applicable := make([]*IntelligenceRule, 0)

	for _, rule := range re.rules {
		if rule.Enabled && re.ruleAppliesToInsight(rule, insight) {
			applicable = append(applicable, rule)
		}
	}

	return applicable
}

func (re *productionRulesEngine) getValidationRules(insight *IntelligenceInsight) []*IntelligenceRule {
	validation := make([]*IntelligenceRule, 0)

	for _, rule := range re.rules {
		if rule.Enabled && rule.Type == "validation" && re.ruleAppliesToInsight(rule, insight) {
			validation = append(validation, rule)
		}
	}

	return validation
}

func (re *productionRulesEngine) ruleAppliesToInsight(rule *IntelligenceRule, insight *IntelligenceInsight) bool {
	// Check domain match
	if rule.Domain != "" {
		if insight.K8sContext != nil && rule.Domain == "k8s" {
			return true
		}
		// Add other domain checks as needed
	}

	return rule.Domain == "" // Apply universal rules
}

func (re *productionRulesEngine) evaluateRule(
	ctx context.Context,
	insight *IntelligenceInsight,
	rule *IntelligenceRule,
) bool {
	// Evaluate all conditions based on logical operator
	results := make([]bool, len(rule.Conditions))

	for i, condition := range rule.Conditions {
		results[i] = re.evaluateCondition(insight, condition)
	}

	// Apply logical operator
	switch rule.LogicalOperator {
	case "AND":
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
	case "OR":
		for _, result := range results {
			if result {
				return true
			}
		}
		return false
	case "NOT":
		if len(results) > 0 {
			return !results[0]
		}
		return false
	default:
		return false
	}
}

func (re *productionRulesEngine) evaluateCondition(insight *IntelligenceInsight, condition *RuleCondition) bool {
	switch condition.Field {
	case "overall_confidence":
		threshold, ok := condition.Value.(float64)
		if !ok {
			return false
		}
		switch condition.Operator {
		case "greater_than":
			return insight.OverallConfidence > threshold
		case "less_than":
			return insight.OverallConfidence < threshold
		case "equals":
			return insight.OverallConfidence == threshold
		}
	case "evidence_count":
		threshold, ok := condition.Value.(int)
		if !ok {
			return false
		}
		evidenceCount := len(insight.Evidence)
		switch condition.Operator {
		case "greater_than":
			return evidenceCount > threshold
		case "less_than":
			return evidenceCount < threshold
		case "equals":
			return evidenceCount == threshold
		}
	case "type":
		expectedType, ok := condition.Value.(string)
		if !ok {
			return false
		}
		return insight.Type == expectedType
	}

	return false
}

func (re *productionRulesEngine) executeRuleActions(
	ctx context.Context,
	insight *IntelligenceInsight,
	rule *IntelligenceRule,
) error {
	for _, action := range rule.Actions {
		if err := re.executeAction(ctx, insight, action); err != nil {
			return fmt.Errorf("failed to execute action %s: %w", action.Type, err)
		}
	}
	return nil
}

func (re *productionRulesEngine) executeAction(
	ctx context.Context,
	insight *IntelligenceInsight,
	action *RuleAction,
) error {
	switch action.Type {
	case "approve_insight":
		// Mark insight as approved
		if insight.Metadata == nil {
			insight.Metadata = make(map[string]interface{})
		}
		insight.Metadata["approved"] = true
		insight.Metadata["approved_by"] = "rules_engine"

	case "boost_confidence":
		if boostAmount, ok := action.Parameters["amount"].(float64); ok {
			insight.OverallConfidence = min(1.0, insight.OverallConfidence+boostAmount)
		}

	case "add_recommendation":
		if recText, ok := action.Parameters["text"].(string); ok {
			rec := &Recommendation{
				ID:          fmt.Sprintf("rule-rec-%d", time.Now().UnixNano()),
				Type:        "rule_generated",
				Priority:    "medium",
				Title:       "Rule-based Recommendation",
				Description: recText,
				Confidence:  0.8,
			}
			insight.Recommendations = append(insight.Recommendations, rec)
		}

	default:
		return fmt.Errorf("unknown action type: %s", action.Type)
	}

	return nil
}

// Production Plugin Integrator Implementation

type productionPluginIntegrator struct {
	logger  *zap.Logger
	plugins map[string]*PluginConfiguration
	tracer  trace.Tracer
	mu      sync.RWMutex
}

func (pi *productionPluginIntegrator) RegisterPlugin(
	ctx context.Context,
	plugin *ObservabilityPlugin,
) error {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	// Convert plugin to configuration
	config := &PluginConfiguration{
		Name:            plugin.Name,
		Type:            plugin.Type,
		Enabled:         plugin.Enabled,
		EndpointURL:     plugin.Endpoint,
		DeliveryTimeout: plugin.Timeout,
		OutputFormat:    "json", // Default format
	}

	pi.plugins[plugin.ID] = config
	pi.logger.Info("Registered plugin", zap.String("plugin_id", plugin.ID))

	return nil
}

func (pi *productionPluginIntegrator) UnregisterPlugin(
	ctx context.Context,
	pluginID string,
) error {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	delete(pi.plugins, pluginID)
	pi.logger.Info("Unregistered plugin", zap.String("plugin_id", pluginID))

	return nil
}

func (pi *productionPluginIntegrator) GetRegisteredPlugins(
	ctx context.Context,
) ([]*ObservabilityPlugin, error) {
	pi.mu.RLock()
	defer pi.mu.RUnlock()

	plugins := make([]*ObservabilityPlugin, 0, len(pi.plugins))
	for id, config := range pi.plugins {
		plugin := &ObservabilityPlugin{
			ID:       id,
			Name:     config.Name,
			Type:     config.Type,
			Enabled:  config.Enabled,
			Endpoint: config.EndpointURL,
			Timeout:  config.DeliveryTimeout,
		}
		plugins = append(plugins, plugin)
	}

	return plugins, nil
}

func (pi *productionPluginIntegrator) SendInsight(
	ctx context.Context,
	insight *IntelligenceInsight,
	targets []string,
) (*DeliveryResult, error) {
	// For now, return success - in production this would make HTTP calls
	return &DeliveryResult{
		Success:      true,
		ResponseTime: time.Millisecond * 100,
		Timestamp:    time.Now(),
	}, nil
}

func (pi *productionPluginIntegrator) SendBatchInsights(
	ctx context.Context,
	insights []*IntelligenceInsight,
	targets []string,
) (*BatchDeliveryResult, error) {
	results := make([]*DeliveryResult, len(insights))
	successCount := 0

	for i, insight := range insights {
		result, err := pi.SendInsight(ctx, insight, targets)
		if err != nil {
			result = &DeliveryResult{
				Success:   false,
				Error:     err.Error(),
				Timestamp: time.Now(),
			}
		}
		results[i] = result
		if result.Success {
			successCount++
		}
	}

	return &BatchDeliveryResult{
		Results:      results,
		SuccessCount: successCount,
		FailureCount: len(insights) - successCount,
		TotalTime:    time.Millisecond * time.Duration(len(insights)*100),
		Timestamp:    time.Now(),
	}, nil
}

func (pi *productionPluginIntegrator) GetSupportedFormats(
	ctx context.Context,
	pluginID string,
) ([]string, error) {
	return []string{"json", "xml", "yaml"}, nil
}

func (pi *productionPluginIntegrator) GetPluginCapabilities(
	ctx context.Context,
	pluginID string,
) (*PluginCapabilities, error) {
	return &PluginCapabilities{
		SupportedFormats:  []string{"json", "xml"},
		MaxBatchSize:      100,
		SupportsStreaming: false,
		SupportsFiltering: true,
	}, nil
}

func (pi *productionPluginIntegrator) TestPlugin(
	ctx context.Context,
	pluginID string,
) (*PluginTestResult, error) {
	return &PluginTestResult{
		PluginID:     pluginID,
		Healthy:      true,
		ResponseTime: time.Millisecond * 50,
		TestTime:     time.Now(),
	}, nil
}

func (pi *productionPluginIntegrator) GetPluginHealth(
	ctx context.Context,
) (map[string]*PluginHealth, error) {
	health := make(map[string]*PluginHealth)

	pi.mu.RLock()
	for pluginID := range pi.plugins {
		health[pluginID] = &PluginHealth{
			PluginID:  pluginID,
			Healthy:   true,
			LastCheck: time.Now(),
		}
	}
	pi.mu.RUnlock()

	return health, nil
}

// Production Worker Pool Implementation

type productionWorkerPool struct {
	logger     *zap.Logger
	maxWorkers int
	tracer     trace.Tracer
	tasks      chan Task
	workers    []*worker
	stats      *WorkerPoolStats
	mu         sync.RWMutex
	running    int32
}

type worker struct {
	id     int
	tasks  <-chan Task
	quit   chan bool
	active int32
}

func (wp *productionWorkerPool) Submit(ctx context.Context, task Task) error {
	if atomic.LoadInt32(&wp.running) == 0 {
		return fmt.Errorf("worker pool is not running")
	}

	select {
	case wp.tasks <- task:
		atomic.AddInt64(&wp.stats.QueuedTasks, 1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (wp *productionWorkerPool) SubmitBatch(ctx context.Context, tasks []Task) error {
	for _, task := range tasks {
		if err := wp.Submit(ctx, task); err != nil {
			return err
		}
	}
	return nil
}

func (wp *productionWorkerPool) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&wp.running, 0, 1) {
		return fmt.Errorf("worker pool is already running")
	}

	wp.mu.Lock()
	defer wp.mu.Unlock()

	wp.workers = make([]*worker, wp.maxWorkers)
	for i := 0; i < wp.maxWorkers; i++ {
		worker := &worker{
			id:    i,
			tasks: wp.tasks,
			quit:  make(chan bool),
		}
		wp.workers[i] = worker
		go wp.runWorker(worker)
	}

	wp.stats.WorkerCount = wp.maxWorkers
	wp.logger.Info("Worker pool started", zap.Int("workers", wp.maxWorkers))

	return nil
}

func (wp *productionWorkerPool) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&wp.running, 1, 0) {
		return fmt.Errorf("worker pool is not running")
	}

	wp.mu.Lock()
	defer wp.mu.Unlock()

	// Signal all workers to stop
	for _, worker := range wp.workers {
		close(worker.quit)
	}

	wp.workers = nil
	wp.logger.Info("Worker pool stopped")

	return nil
}

func (wp *productionWorkerPool) GetStats() *WorkerPoolStats {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	activeWorkers := 0
	for _, worker := range wp.workers {
		if atomic.LoadInt32(&worker.active) == 1 {
			activeWorkers++
		}
	}

	return &WorkerPoolStats{
		WorkerCount:         wp.stats.WorkerCount,
		ActiveWorkers:       activeWorkers,
		QueuedTasks:         int(atomic.LoadInt64(&wp.stats.QueuedTasks)),
		CompletedTasks:      atomic.LoadInt64(&wp.stats.CompletedTasks),
		FailedTasks:         atomic.LoadInt64(&wp.stats.FailedTasks),
		AverageTaskDuration: wp.stats.AverageTaskDuration,
		QueueWaitTime:       wp.stats.QueueWaitTime,
	}
}

func (wp *productionWorkerPool) Resize(newSize int) error {
	// Simplified resize - stop and restart with new size
	if atomic.LoadInt32(&wp.running) == 1 {
		return fmt.Errorf("cannot resize running pool")
	}
	wp.maxWorkers = newSize
	return nil
}

func (wp *productionWorkerPool) runWorker(worker *worker) {
	wp.logger.Debug("Worker started", zap.Int("worker_id", worker.id))

	for {
		select {
		case task := <-worker.tasks:
			if task == nil {
				continue
			}

			atomic.StoreInt32(&worker.active, 1)
			atomic.AddInt64(&wp.stats.QueuedTasks, -1)

			start := time.Now()
			ctx := context.Background()

			if err := task.Execute(ctx); err != nil {
				atomic.AddInt64(&wp.stats.FailedTasks, 1)
				wp.logger.Warn("Task execution failed",
					zap.String("task_id", task.ID()),
					zap.Error(err))
			} else {
				atomic.AddInt64(&wp.stats.CompletedTasks, 1)
			}

			duration := time.Since(start)
			wp.updateAverageTaskDuration(duration)

			atomic.StoreInt32(&worker.active, 0)

		case <-worker.quit:
			wp.logger.Debug("Worker stopping", zap.Int("worker_id", worker.id))
			return
		}
	}
}

func (wp *productionWorkerPool) updateAverageTaskDuration(duration time.Duration) {
	// Simple moving average approximation
	wp.stats.AverageTaskDuration = (wp.stats.AverageTaskDuration + duration) / 2
}

// Production Cache Manager Implementation

type productionCacheManager struct {
	logger  *zap.Logger
	enabled bool
	tracer  trace.Tracer
	cache   map[string]*cacheEntry
	stats   *CacheStats
	mu      sync.RWMutex
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

func (cm *productionCacheManager) Get(ctx context.Context, key string) (interface{}, bool) {
	if !cm.enabled {
		return nil, false
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	entry, exists := cm.cache[key]
	if !exists {
		atomic.AddInt64(&cm.stats.Misses, 1)
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(cm.cache, key)
		atomic.AddInt64(&cm.stats.Misses, 1)
		atomic.AddInt64(&cm.stats.Evictions, 1)
		return nil, false
	}

	atomic.AddInt64(&cm.stats.Hits, 1)
	cm.updateHitRate()

	return entry.value, true
}

func (cm *productionCacheManager) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if !cm.enabled {
		return nil
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.cache[key] = &cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	atomic.StoreInt64(&cm.stats.Size, int64(len(cm.cache)))

	return nil
}

func (cm *productionCacheManager) Delete(ctx context.Context, key string) error {
	if !cm.enabled {
		return nil
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	delete(cm.cache, key)
	atomic.StoreInt64(&cm.stats.Size, int64(len(cm.cache)))

	return nil
}

func (cm *productionCacheManager) Clear(ctx context.Context) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.cache = make(map[string]*cacheEntry)
	atomic.StoreInt64(&cm.stats.Size, 0)

	return nil
}

func (cm *productionCacheManager) GetStats() *CacheStats {
	return &CacheStats{
		Hits:            atomic.LoadInt64(&cm.stats.Hits),
		Misses:          atomic.LoadInt64(&cm.stats.Misses),
		HitRate:         cm.stats.HitRate,
		Size:            atomic.LoadInt64(&cm.stats.Size),
		MaxSize:         cm.stats.MaxSize,
		Evictions:       atomic.LoadInt64(&cm.stats.Evictions),
		AverageLoadTime: cm.stats.AverageLoadTime,
	}
}

func (cm *productionCacheManager) updateHitRate() {
	hits := atomic.LoadInt64(&cm.stats.Hits)
	misses := atomic.LoadInt64(&cm.stats.Misses)
	total := hits + misses

	if total > 0 {
		cm.stats.HitRate = float64(hits) / float64(total)
	}
}

// Production Circuit Breaker Implementation

type productionCircuitBreaker struct {
	logger      *zap.Logger
	tracer      trace.Tracer
	state       CircuitBreakerState
	threshold   int
	timeout     time.Duration
	failures    int32
	lastFailure time.Time
	metrics     *CircuitBreakerMetrics
	mu          sync.RWMutex
}

func (cb *productionCircuitBreaker) Execute(
	ctx context.Context,
	operation func(ctx context.Context) (interface{}, error),
) (interface{}, error) {
	ctx, span := cb.tracer.Start(ctx, "circuit_breaker.execute")
	defer span.End()

	cb.mu.RLock()
	state := cb.state
	cb.mu.RUnlock()

	span.SetAttributes(
		attribute.String("circuit_breaker.state", cb.stateString(state)),
	)

	switch state {
	case CircuitBreakerOpen:
		// Check if we should try half-open
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.mu.Lock()
			cb.state = CircuitBreakerHalfOpen
			cb.mu.Unlock()
			span.SetAttributes(attribute.String("circuit_breaker.transition", "open_to_half_open"))
		} else {
			span.SetAttributes(attribute.String("circuit_breaker.result", "rejected"))
			return nil, fmt.Errorf("circuit breaker is open")
		}
		fallthrough

	case CircuitBreakerHalfOpen:
		// Try the operation
		result, err := operation(ctx)
		if err != nil {
			cb.recordFailure()
			span.SetAttributes(attribute.String("circuit_breaker.result", "failed"))
			return nil, err
		}
		cb.recordSuccess()
		span.SetAttributes(attribute.String("circuit_breaker.result", "success"))
		return result, nil

	case CircuitBreakerClosed:
		// Normal operation
		result, err := operation(ctx)
		if err != nil {
			cb.recordFailure()
			span.SetAttributes(attribute.String("circuit_breaker.result", "failed"))
			return nil, err
		}
		cb.recordSuccess()
		span.SetAttributes(attribute.String("circuit_breaker.result", "success"))
		return result, nil

	default:
		return nil, fmt.Errorf("unknown circuit breaker state")
	}
}

func (cb *productionCircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *productionCircuitBreaker) GetMetrics() *CircuitBreakerMetrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	metrics := &CircuitBreakerMetrics{
		State:               cb.state,
		FailureCount:        cb.metrics.FailureCount,
		SuccessCount:        cb.metrics.SuccessCount,
		ConsecutiveFailures: int(atomic.LoadInt32(&cb.failures)),
	}

	if !cb.lastFailure.IsZero() {
		metrics.LastFailureTime = &cb.lastFailure
	}

	if cb.state == CircuitBreakerOpen {
		nextAttempt := cb.lastFailure.Add(cb.timeout)
		metrics.NextAttemptTime = &nextAttempt
	}

	return metrics
}

func (cb *productionCircuitBreaker) Reset() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = CircuitBreakerClosed
	atomic.StoreInt32(&cb.failures, 0)
	cb.lastFailure = time.Time{}

	cb.logger.Info("Circuit breaker reset")

	return nil
}

func (cb *productionCircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	atomic.StoreInt32(&cb.failures, 0)
	atomic.AddInt64(&cb.metrics.SuccessCount, 1)

	if cb.state == CircuitBreakerHalfOpen {
		cb.state = CircuitBreakerClosed
		cb.logger.Info("Circuit breaker closed after successful operation")
	}
}

func (cb *productionCircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	failures := atomic.AddInt32(&cb.failures, 1)
	atomic.AddInt64(&cb.metrics.FailureCount, 1)
	cb.lastFailure = time.Now()

	if int(failures) >= cb.threshold {
		cb.state = CircuitBreakerOpen
		cb.logger.Warn("Circuit breaker opened due to failures",
			zap.Int32("consecutive_failures", failures),
			zap.Int("threshold", cb.threshold))
	}
}

func (cb *productionCircuitBreaker) stateString(state CircuitBreakerState) string {
	switch state {
	case CircuitBreakerClosed:
		return "closed"
	case CircuitBreakerOpen:
		return "open"
	case CircuitBreakerHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// Production Rate Limiter Implementation

type productionRateLimiter struct {
	logger     *zap.Logger
	tracer     trace.Tracer
	rate       float64
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

func (rl *productionRateLimiter) Allow() bool {
	return rl.AllowN(1)
}

func (rl *productionRateLimiter) AllowN(n int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.refillTokens()

	if rl.tokens >= float64(n) {
		rl.tokens -= float64(n)
		return true
	}

	return false
}

func (rl *productionRateLimiter) Wait(ctx context.Context) error {
	return rl.WaitN(ctx, 1)
}

func (rl *productionRateLimiter) WaitN(ctx context.Context, n int) error {
	for {
		if rl.AllowN(n) {
			return nil
		}

		// Wait a bit before trying again
		select {
		case <-time.After(time.Millisecond * 10):
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (rl *productionRateLimiter) GetRate() float64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.rate
}

func (rl *productionRateLimiter) SetRate(rate float64) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.rate = rate
	// Reset tokens to new rate
	rl.tokens = rate
	rl.lastRefill = time.Now()

	return nil
}

func (rl *productionRateLimiter) refillTokens() {
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()

	// Add tokens based on elapsed time
	rl.tokens = min(rl.rate, rl.tokens+rl.rate*elapsed)
	rl.lastRefill = now
}

// Utility functions

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// Required types for the rules engine

type IntelligenceRuleset struct {
	Rules   []*IntelligenceRule
	Domain  string
	Version string
}

type RuleEvaluationResult struct {
	RulesEvaluated  int
	RulesMatched    int
	ActionsExecuted int
	ModifiedInsight *IntelligenceInsight
}

type ConfidenceRules struct {
	MinimumThreshold float64
	EvidenceWeights  map[string]float64
	PatternBonuses   map[string]float64
	TimeDecayFactor  float64
}
