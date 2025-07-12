package shard

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// ShardRuleEngine manages rule execution within a processing shard
type ShardRuleEngine struct {
	// Rule management
	rules     map[string]*events_correlation.Rule
	rulesList []*events_correlation.Rule // For fast iteration
	rulesLock sync.RWMutex
	
	// Execution control
	maxConcurrentRules int
	ruleSemaphore      chan struct{}
	
	// Performance optimization
	rulePool    *sync.Pool
	
	// Metrics
	rulesExecuted   uint64
	totalExecTime   uint64 // Nanoseconds
	successfulRules uint64
	failedRules     uint64
	
	// Rule-specific metrics
	ruleMetrics map[string]*RuleMetrics
	metricsLock sync.RWMutex
}

// RuleMetrics tracks performance for individual rules
type RuleMetrics struct {
	executions    uint64
	totalTime     uint64 // Nanoseconds
	successes     uint64
	failures      uint64
	lastExecution time.Time
	avgConfidence float64
}

// NewShardRuleEngine creates a new shard rule engine
func NewShardRuleEngine(maxRules int) *ShardRuleEngine {
	maxConcurrent := runtime.NumCPU()
	if maxConcurrent > maxRules {
		maxConcurrent = maxRules
	}
	
	engine := &ShardRuleEngine{
		rules:              make(map[string]*events_correlation.Rule),
		rulesList:          make([]*events_correlation.Rule, 0, maxRules),
		maxConcurrentRules: maxConcurrent,
		ruleSemaphore:      make(chan struct{}, maxConcurrent),
		ruleMetrics:        make(map[string]*RuleMetrics),
	}
	
	// Initialize object pools
	engine.rulePool = &sync.Pool{
		New: func() interface{} {
			return &RuleExecution{
				start:  time.Time{},
				result: nil,
			}
		},
	}
	
	return engine
}

// RuleExecution tracks rule execution state
type RuleExecution struct {
	start  time.Time
	result *events_correlation.Result
}

// RegisterRule adds a rule to the engine
func (sre *ShardRuleEngine) RegisterRule(rule *events_correlation.Rule) error {
	sre.rulesLock.Lock()
	defer sre.rulesLock.Unlock()
	
	// Add to map and list
	sre.rules[rule.ID] = rule
	sre.rulesList = append(sre.rulesList, rule)
	
	// Initialize metrics
	sre.metricsLock.Lock()
	sre.ruleMetrics[rule.ID] = &RuleMetrics{}
	sre.metricsLock.Unlock()
	
	return nil
}

// ProcessBatch processes a batch of events through all rules
func (sre *ShardRuleEngine) ProcessBatch(ctx *events_correlation.Context, events []*events_correlation.Event) []*events_correlation.Result {
	var results []*events_correlation.Result
	var resultsMutex sync.Mutex
	var wg sync.WaitGroup
	
	// Get current rule list (snapshot to avoid locking during execution)
	sre.rulesLock.RLock()
	currentRules := make([]*events_correlation.Rule, len(sre.rulesList))
	copy(currentRules, sre.rulesList)
	sre.rulesLock.RUnlock()
	
	// Execute rules concurrently
	for _, rule := range currentRules {
		// Skip disabled rules
		if !rule.Enabled {
			continue
		}
		
		// Check cooldown
		if sre.isRuleInCooldown(rule) {
			continue
		}
		
		// Acquire semaphore for concurrency control
		sre.ruleSemaphore <- struct{}{}
		
		wg.Add(1)
		go func(r *events_correlation.Rule) {
			defer func() {
				<-sre.ruleSemaphore // Release semaphore
				wg.Done()
			}()
			
			// Execute rule
			if result := sre.executeRule(r, ctx); result != nil {
				resultsMutex.Lock()
				results = append(results, result)
				resultsMutex.Unlock()
			}
		}(rule)
	}
	
	wg.Wait()
	return results
}

// executeRule executes a single rule with performance tracking
func (sre *ShardRuleEngine) executeRule(rule *events_correlation.Rule, ctx *events_correlation.Context) *events_correlation.Result {
	start := time.Now()
	atomic.AddUint64(&sre.rulesExecuted, 1)
	
	// Get execution object from pool
	exec := sre.rulePool.Get().(*RuleExecution)
	defer sre.rulePool.Put(exec)
	
	exec.start = start
	
	// Create rule-specific context
	ruleCtx := sre.createRuleContext(ctx, rule)
	
	// Execute the rule function
	var result *events_correlation.Result
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Rule panicked, log and continue
				atomic.AddUint64(&sre.failedRules, 1)
				sre.updateRuleMetrics(rule.ID, time.Since(start), false, 0.0)
			}
		}()
		
		result = rule.Evaluate(ruleCtx)
	}()
	
	elapsed := time.Since(start)
	
	// Update metrics
	if result != nil {
		atomic.AddUint64(&sre.successfulRules, 1)
		sre.updateRuleMetrics(rule.ID, elapsed, true, result.Confidence)
		
		// Update rule's last execution time for cooldown
		rule.LastExecuted = time.Now()
		atomic.AddUint64(&rule.ExecutionCount, 1)
		
		// Update rule performance metrics
		sre.updateRulePerformance(rule, elapsed, true)
		
		return result
	} else {
		sre.updateRuleMetrics(rule.ID, elapsed, false, 0.0)
		sre.updateRulePerformance(rule, elapsed, false)
	}
	
	return nil
}

// createRuleContext creates a rule-specific context
func (sre *ShardRuleEngine) createRuleContext(baseCtx *events_correlation.Context, rule *events_correlation.Rule) *events_correlation.Context {
	// Get all events from base context
	allEvents := baseCtx.GetEvents(events_correlation.Filter{})
	
	// Filter events based on rule requirements
	var filteredEvents []events_correlation.Event
	for _, event := range allEvents {
		if sre.eventMatchesRule(event, rule) {
			filteredEvents = append(filteredEvents, event)
		}
	}
	
	// Create new context with filtered events
	return events_correlation.NewContext(baseCtx.Window, filteredEvents)
}

// eventMatchesRule checks if an event matches rule requirements
func (sre *ShardRuleEngine) eventMatchesRule(event events_correlation.Event, rule *events_correlation.Rule) bool {
	// Check required sources
	if len(rule.RequiredSources) > 0 {
		found := false
		for _, source := range rule.RequiredSources {
			if event.Source == source {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Event matches rule requirements
	return true
}

// isRuleInCooldown checks if a rule is in cooldown period
func (sre *ShardRuleEngine) isRuleInCooldown(rule *events_correlation.Rule) bool {
	if rule.Cooldown == 0 {
		return false
	}
	
	return time.Since(rule.LastExecuted) < rule.Cooldown
}

// updateRuleMetrics updates performance metrics for a rule
func (sre *ShardRuleEngine) updateRuleMetrics(ruleID string, duration time.Duration, success bool, confidence float64) {
	sre.metricsLock.Lock()
	defer sre.metricsLock.Unlock()
	
	metrics := sre.ruleMetrics[ruleID]
	if metrics == nil {
		metrics = &RuleMetrics{}
		sre.ruleMetrics[ruleID] = metrics
	}
	
	atomic.AddUint64(&metrics.executions, 1)
	atomic.AddUint64(&metrics.totalTime, uint64(duration.Nanoseconds()))
	metrics.lastExecution = time.Now()
	
	if success {
		atomic.AddUint64(&metrics.successes, 1)
		
		// Update average confidence using exponential moving average
		alpha := 0.1 // Smoothing factor
		metrics.avgConfidence = alpha*confidence + (1-alpha)*metrics.avgConfidence
	} else {
		atomic.AddUint64(&metrics.failures, 1)
	}
}

// updateRulePerformance updates the rule's built-in performance metrics
func (sre *ShardRuleEngine) updateRulePerformance(rule *events_correlation.Rule, duration time.Duration, success bool) {
	execCount := atomic.LoadUint64(&rule.ExecutionCount)
	
	// Update average execution time
	if execCount == 1 {
		rule.Performance.AverageExecutionTime = duration
		rule.Performance.MinExecutionTime = duration
		rule.Performance.MaxExecutionTime = duration
	} else {
		// Exponential moving average for performance
		alpha := 2.0 / float64(execCount+1)
		oldAvg := rule.Performance.AverageExecutionTime
		rule.Performance.AverageExecutionTime = time.Duration(float64(oldAvg)*alpha + float64(duration)*(1-alpha))
		
		// Update min/max
		if duration < rule.Performance.MinExecutionTime {
			rule.Performance.MinExecutionTime = duration
		}
		if duration > rule.Performance.MaxExecutionTime {
			rule.Performance.MaxExecutionTime = duration
		}
	}
	
	// Update total execution time
	rule.Performance.TotalExecutionTime += duration
	
	// Update success rate
	if success {
		rule.Performance.SuccessRate = (rule.Performance.SuccessRate*float64(execCount-1) + 1.0) / float64(execCount)
	} else {
		rule.Performance.SuccessRate = (rule.Performance.SuccessRate*float64(execCount-1) + 0.0) / float64(execCount)
	}
}

// GetRuleStats returns statistics for all rules
func (sre *ShardRuleEngine) GetRuleStats() map[string]RuleStats {
	sre.metricsLock.RLock()
	defer sre.metricsLock.RUnlock()
	
	stats := make(map[string]RuleStats)
	
	for ruleID, metrics := range sre.ruleMetrics {
		executions := atomic.LoadUint64(&metrics.executions)
		totalTime := atomic.LoadUint64(&metrics.totalTime)
		successes := atomic.LoadUint64(&metrics.successes)
		failures := atomic.LoadUint64(&metrics.failures)
		
		stat := RuleStats{
			RuleID:           ruleID,
			Executions:       executions,
			Successes:        successes,
			Failures:         failures,
			LastExecution:    metrics.lastExecution,
			AverageConfidence: metrics.avgConfidence,
		}
		
		if executions > 0 {
			stat.AverageExecutionTimeNs = totalTime / executions
			stat.SuccessRate = float64(successes) / float64(executions)
		}
		
		stats[ruleID] = stat
	}
	
	return stats
}

// RuleStats contains performance statistics for a rule
type RuleStats struct {
	RuleID                string    `json:"rule_id"`
	Executions            uint64    `json:"executions"`
	Successes             uint64    `json:"successes"`
	Failures              uint64    `json:"failures"`
	SuccessRate           float64   `json:"success_rate"`
	AverageExecutionTimeNs uint64   `json:"avg_execution_time_ns"`
	LastExecution         time.Time `json:"last_execution"`
	AverageConfidence     float64   `json:"avg_confidence"`
}

// GetEngineStats returns overall engine statistics
func (sre *ShardRuleEngine) GetEngineStats() EngineStats {
	rulesExecuted := atomic.LoadUint64(&sre.rulesExecuted)
	totalExecTime := atomic.LoadUint64(&sre.totalExecTime)
	successfulRules := atomic.LoadUint64(&sre.successfulRules)
	failedRules := atomic.LoadUint64(&sre.failedRules)
	
	stats := EngineStats{
		RegisteredRules:  len(sre.rulesList),
		ExecutedRules:    rulesExecuted,
		SuccessfulRules:  successfulRules,
		FailedRules:      failedRules,
		ConcurrentLimit:  sre.maxConcurrentRules,
	}
	
	if rulesExecuted > 0 {
		stats.AverageExecutionTimeNs = totalExecTime / rulesExecuted
		stats.SuccessRate = float64(successfulRules) / float64(rulesExecuted)
	}
	
	return stats
}

// EngineStats contains overall engine performance statistics
type EngineStats struct {
	RegisteredRules        int     `json:"registered_rules"`
	ExecutedRules          uint64  `json:"executed_rules"`
	SuccessfulRules        uint64  `json:"successful_rules"`
	FailedRules            uint64  `json:"failed_rules"`
	SuccessRate            float64 `json:"success_rate"`
	AverageExecutionTimeNs uint64  `json:"avg_execution_time_ns"`
	ConcurrentLimit        int     `json:"concurrent_limit"`
}

// Reset clears all metrics and state
func (sre *ShardRuleEngine) Reset() {
	atomic.StoreUint64(&sre.rulesExecuted, 0)
	atomic.StoreUint64(&sre.totalExecTime, 0)
	atomic.StoreUint64(&sre.successfulRules, 0)
	atomic.StoreUint64(&sre.failedRules, 0)
	
	sre.metricsLock.Lock()
	sre.ruleMetrics = make(map[string]*RuleMetrics)
	sre.metricsLock.Unlock()
}

// GetRule returns a rule by ID
func (sre *ShardRuleEngine) GetRule(ruleID string) *events_correlation.Rule {
	sre.rulesLock.RLock()
	defer sre.rulesLock.RUnlock()
	
	return sre.rules[ruleID]
}

// ListRules returns all registered rules
func (sre *ShardRuleEngine) ListRules() []*events_correlation.Rule {
	sre.rulesLock.RLock()
	defer sre.rulesLock.RUnlock()
	
	rules := make([]*events_correlation.Rule, len(sre.rulesList))
	copy(rules, sre.rulesList)
	return rules
}