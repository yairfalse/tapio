package hybrid

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// HybridMetrics tracks metrics for the hybrid correlation engine
type HybridMetrics struct {
	// Engine usage counters
	v1UsageCount    atomic.Uint64
	v2UsageCount    atomic.Uint64
	
	// Error tracking
	v1Errors        atomic.Uint64
	v2Errors        atomic.Uint64
	v2Fallbacks     atomic.Uint64
	
	// Performance metrics
	v1Latency       *LatencyTracker
	v2Latency       *LatencyTracker
	processingTime  *LatencyTracker
	
	// Result tracking
	v1Results       atomic.Uint64
	v2Results       atomic.Uint64
	resultMismatches atomic.Uint64
	
	// Configuration changes
	configChanges   []ConfigChange
	configMu        sync.RWMutex
	
	// Rollback tracking
	rollbacks       []RollbackEvent
	rollbackMu      sync.RWMutex
	
	// Startup failures
	v2StartupFailures atomic.Uint64
	
	// Rule registration failures
	ruleFailures    map[string]int
	ruleFailuresMu  sync.RWMutex
}

// ConfigChange represents a configuration change event
type ConfigChange struct {
	Timestamp time.Time
	Parameter string
	OldValue  interface{}
	NewValue  interface{}
}

// RollbackEvent represents a rollback occurrence
type RollbackEvent struct {
	Timestamp time.Time
	Reason    string
	Metrics   map[string]interface{}
}

// NewHybridMetrics creates a new metrics tracker
func NewHybridMetrics() *HybridMetrics {
	return &HybridMetrics{
		v1Latency:      NewLatencyTracker(),
		v2Latency:      NewLatencyTracker(),
		processingTime: NewLatencyTracker(),
		ruleFailures:   make(map[string]int),
	}
}

// IncrementV1Usage increments V1 engine usage counter
func (m *HybridMetrics) IncrementV1Usage() {
	m.v1UsageCount.Add(1)
}

// IncrementV2Usage increments V2 engine usage counter
func (m *HybridMetrics) IncrementV2Usage() {
	m.v2UsageCount.Add(1)
}

// IncrementV2Fallback increments V2 fallback counter
func (m *HybridMetrics) IncrementV2Fallback() {
	m.v2Fallbacks.Add(1)
}

// RecordV1Error records a V1 engine error
func (m *HybridMetrics) RecordV1Error() {
	m.v1Errors.Add(1)
}

// RecordV2Error records a V2 engine error
func (m *HybridMetrics) RecordV2Error() {
	m.v2Errors.Add(1)
}

// RecordV1Latency records V1 processing latency
func (m *HybridMetrics) RecordV1Latency(duration time.Duration) {
	m.v1Latency.Record(duration)
}

// RecordV2Latency records V2 processing latency
func (m *HybridMetrics) RecordV2Latency(duration time.Duration) {
	m.v2Latency.Record(duration)
}

// RecordProcessingLatency records overall processing latency
func (m *HybridMetrics) RecordProcessingLatency(duration time.Duration) {
	m.processingTime.Record(duration)
}

// RecordV1Results records V1 result count
func (m *HybridMetrics) RecordV1Results(count int) {
	m.v1Results.Add(uint64(count))
}

// RecordV2Results records V2 result count
func (m *HybridMetrics) RecordV2Results(count int) {
	m.v2Results.Add(uint64(count))
}

// RecordV2Processed records V2 processed event count
func (m *HybridMetrics) RecordV2Processed(count int) {
	// Track processed events
}

// RecordResultMismatch records when V1 and V2 produce different results
func (m *HybridMetrics) RecordResultMismatch() {
	m.resultMismatches.Add(1)
}

// RecordComparison records a result comparison
func (m *HybridMetrics) RecordComparison(comparison ResultComparison) {
	if comparison.Mismatch {
		m.RecordResultMismatch()
	}
}

// RecordConfigChange records a configuration change
func (m *HybridMetrics) RecordConfigChange(parameter string, newValue interface{}) {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	
	m.configChanges = append(m.configChanges, ConfigChange{
		Timestamp: time.Now(),
		Parameter: parameter,
		NewValue:  newValue,
	})
	
	// Keep only last 100 changes
	if len(m.configChanges) > 100 {
		m.configChanges = m.configChanges[len(m.configChanges)-100:]
	}
}

// RecordRollback records a rollback event
func (m *HybridMetrics) RecordRollback(reason string) {
	m.rollbackMu.Lock()
	defer m.rollbackMu.Unlock()
	
	m.rollbacks = append(m.rollbacks, RollbackEvent{
		Timestamp: time.Now(),
		Reason:    reason,
		Metrics:   m.GetSummary(),
	})
}

// RecordV2StartupFailure records V2 startup failure
func (m *HybridMetrics) RecordV2StartupFailure() {
	m.v2StartupFailures.Add(1)
}

// RecordV2RuleRegistrationFailure records V2 rule registration failure
func (m *HybridMetrics) RecordV2RuleRegistrationFailure(ruleID string) {
	m.ruleFailuresMu.Lock()
	defer m.ruleFailuresMu.Unlock()
	
	m.ruleFailures[ruleID]++
}

// GetV2ErrorRate returns the V2 error rate
func (m *HybridMetrics) GetV2ErrorRate() float64 {
	total := m.v2UsageCount.Load()
	if total == 0 {
		return 0
	}
	
	errors := m.v2Errors.Load()
	return float64(errors) / float64(total)
}

// GetSummary returns a summary of all metrics
func (m *HybridMetrics) GetSummary() map[string]interface{} {
	v1Count := m.v1UsageCount.Load()
	v2Count := m.v2UsageCount.Load()
	totalCount := v1Count + v2Count
	
	var v1Percentage, v2Percentage float64
	if totalCount > 0 {
		v1Percentage = float64(v1Count) / float64(totalCount) * 100
		v2Percentage = float64(v2Count) / float64(totalCount) * 100
	}
	
	return map[string]interface{}{
		"usage": map[string]interface{}{
			"v1_count":      v1Count,
			"v2_count":      v2Count,
			"v1_percentage": fmt.Sprintf("%.2f%%", v1Percentage),
			"v2_percentage": fmt.Sprintf("%.2f%%", v2Percentage),
		},
		"errors": map[string]interface{}{
			"v1_errors":     m.v1Errors.Load(),
			"v2_errors":     m.v2Errors.Load(),
			"v2_fallbacks":  m.v2Fallbacks.Load(),
			"v2_error_rate": fmt.Sprintf("%.4f", m.GetV2ErrorRate()),
		},
		"latency": map[string]interface{}{
			"v1_p50":  m.v1Latency.P50(),
			"v1_p90":  m.v1Latency.P90(),
			"v1_p99":  m.v1Latency.P99(),
			"v2_p50":  m.v2Latency.P50(),
			"v2_p90":  m.v2Latency.P90(),
			"v2_p99":  m.v2Latency.P99(),
		},
		"results": map[string]interface{}{
			"v1_results":      m.v1Results.Load(),
			"v2_results":      m.v2Results.Load(),
			"mismatches":      m.resultMismatches.Load(),
		},
		"rollbacks": len(m.rollbacks),
		"v2_startup_failures": m.v2StartupFailures.Load(),
	}
}

// Report prints a metrics report
func (m *HybridMetrics) Report() {
	summary := m.GetSummary()
	
	fmt.Println("=== Hybrid Engine Metrics ===")
	fmt.Printf("Usage Distribution: V1=%.2f%%, V2=%.2f%%\n",
		summary["usage"].(map[string]interface{})["v1_percentage"],
		summary["usage"].(map[string]interface{})["v2_percentage"])
	
	fmt.Printf("Error Rates: V1=%d, V2=%d (%.4f), Fallbacks=%d\n",
		summary["errors"].(map[string]interface{})["v1_errors"],
		summary["errors"].(map[string]interface{})["v2_errors"],
		summary["errors"].(map[string]interface{})["v2_error_rate"],
		summary["errors"].(map[string]interface{})["v2_fallbacks"])
	
	latency := summary["latency"].(map[string]interface{})
	fmt.Printf("V1 Latency: P50=%v, P90=%v, P99=%v\n",
		latency["v1_p50"], latency["v1_p90"], latency["v1_p99"])
	fmt.Printf("V2 Latency: P50=%v, P90=%v, P99=%v\n",
		latency["v2_p50"], latency["v2_p90"], latency["v2_p99"])
	
	fmt.Printf("Results: V1=%d, V2=%d, Mismatches=%d\n",
		summary["results"].(map[string]interface{})["v1_results"],
		summary["results"].(map[string]interface{})["v2_results"],
		summary["results"].(map[string]interface{})["mismatches"])
}

// LatencyTracker tracks latency percentiles
type LatencyTracker struct {
	samples  []time.Duration
	maxSize  int
	mu       sync.RWMutex
}

// NewLatencyTracker creates a new latency tracker
func NewLatencyTracker() *LatencyTracker {
	return &LatencyTracker{
		samples: make([]time.Duration, 0, 1000),
		maxSize: 1000,
	}
}

// Record records a latency sample
func (l *LatencyTracker) Record(duration time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.samples = append(l.samples, duration)
	
	// Keep only recent samples
	if len(l.samples) > l.maxSize {
		l.samples = l.samples[len(l.samples)-l.maxSize:]
	}
}

// P50 returns the 50th percentile latency
func (l *LatencyTracker) P50() time.Duration {
	return l.percentile(0.5)
}

// P90 returns the 90th percentile latency
func (l *LatencyTracker) P90() time.Duration {
	return l.percentile(0.9)
}

// P99 returns the 99th percentile latency
func (l *LatencyTracker) P99() time.Duration {
	return l.percentile(0.99)
}

// percentile calculates the given percentile
func (l *LatencyTracker) percentile(p float64) time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	if len(l.samples) == 0 {
		return 0
	}
	
	// Simple implementation - in production use a proper percentile algorithm
	index := int(float64(len(l.samples)) * p)
	if index >= len(l.samples) {
		index = len(l.samples) - 1
	}
	
	return l.samples[index]
}