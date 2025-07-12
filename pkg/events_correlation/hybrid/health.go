package hybrid

import (
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// HealthMonitor monitors the health of the hybrid engine
type HealthMonitor struct {
	engine    *HybridCorrelationEngine
	config    RollbackConfig
	
	// Health metrics window
	window    *MetricsWindow
	mu        sync.RWMutex
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(engine *HybridCorrelationEngine, config RollbackConfig) *HealthMonitor {
	return &HealthMonitor{
		engine: engine,
		config: config,
		window: NewMetricsWindow(config.WindowSize),
	}
}

// ShouldRollback determines if we should rollback to V1-only
func (h *HealthMonitor) ShouldRollback() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	// Get current metrics
	metrics := h.window.GetMetrics()
	
	// Need minimum samples before making decision
	if metrics.SampleCount < h.config.MinSamples {
		return false
	}
	
	// Check error rate
	if metrics.ErrorRate > h.config.ErrorThreshold {
		return true
	}
	
	// Check latency
	if metrics.P99Latency > h.config.LatencyThreshold {
		return true
	}
	
	// Check circuit breaker state
	if h.engine.v2Circuit.State() == StateOpen {
		// Circuit has been open for too long
		cbStats := h.engine.v2Circuit.GetStats()
		if cbStats.TimeInState > 5*time.Minute {
			return true
		}
	}
	
	return false
}

// RecordV2Metrics records V2 engine metrics
func (h *HealthMonitor) RecordV2Metrics(latency time.Duration, success bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	h.window.Record(MetricSample{
		Timestamp: time.Now(),
		Latency:   latency,
		Success:   success,
	})
}

// GetHealthStatus returns the current health status
func (h *HealthMonitor) GetHealthStatus() HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	metrics := h.window.GetMetrics()
	
	status := HealthStatus{
		Healthy:       !h.ShouldRollback(),
		ErrorRate:     metrics.ErrorRate,
		P99Latency:    metrics.P99Latency,
		SampleCount:   metrics.SampleCount,
		CircuitState:  h.engine.v2Circuit.State().String(),
		LastUpdated:   time.Now(),
	}
	
	// Determine health level
	if status.ErrorRate > 0.1 || status.P99Latency > 500*time.Millisecond {
		status.Level = "critical"
	} else if status.ErrorRate > 0.05 || status.P99Latency > 200*time.Millisecond {
		status.Level = "warning"
	} else {
		status.Level = "healthy"
	}
	
	return status
}

// HealthStatus represents the health status of the hybrid engine
type HealthStatus struct {
	Healthy      bool
	Level        string // "healthy", "warning", "critical"
	ErrorRate    float64
	P99Latency   time.Duration
	SampleCount  int
	CircuitState string
	LastUpdated  time.Time
}

// MetricsWindow maintains a sliding window of metrics
type MetricsWindow struct {
	samples    []MetricSample
	windowSize time.Duration
	mu         sync.RWMutex
}

// MetricSample represents a single metric sample
type MetricSample struct {
	Timestamp time.Time
	Latency   time.Duration
	Success   bool
}

// NewMetricsWindow creates a new metrics window
func NewMetricsWindow(windowSize time.Duration) *MetricsWindow {
	return &MetricsWindow{
		samples:    make([]MetricSample, 0, 1000),
		windowSize: windowSize,
	}
}

// Record adds a new metric sample
func (w *MetricsWindow) Record(sample MetricSample) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// Add sample
	w.samples = append(w.samples, sample)
	
	// Remove old samples
	cutoff := time.Now().Add(-w.windowSize)
	validSamples := make([]MetricSample, 0, len(w.samples))
	
	for _, s := range w.samples {
		if s.Timestamp.After(cutoff) {
			validSamples = append(validSamples, s)
		}
	}
	
	w.samples = validSamples
}

// GetMetrics calculates metrics for the current window
func (w *MetricsWindow) GetMetrics() WindowMetrics {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	if len(w.samples) == 0 {
		return WindowMetrics{}
	}
	
	// Calculate error rate
	var errors int
	latencies := make([]time.Duration, 0, len(w.samples))
	
	for _, s := range w.samples {
		if !s.Success {
			errors++
		}
		latencies = append(latencies, s.Latency)
	}
	
	errorRate := float64(errors) / float64(len(w.samples))
	
	// Calculate P99 latency (simple implementation)
	p99Index := int(float64(len(latencies)) * 0.99)
	if p99Index >= len(latencies) {
		p99Index = len(latencies) - 1
	}
	
	return WindowMetrics{
		ErrorRate:   errorRate,
		P99Latency:  latencies[p99Index],
		SampleCount: len(w.samples),
	}
}

// WindowMetrics contains metrics for a time window
type WindowMetrics struct {
	ErrorRate   float64
	P99Latency  time.Duration
	SampleCount int
}

// ResultComparator compares results from V1 and V2 engines
type ResultComparator struct {
	mu sync.RWMutex
}

// NewResultComparator creates a new result comparator
func NewResultComparator() *ResultComparator {
	return &ResultComparator{}
}

// Compare compares two sets of results
func (c *ResultComparator) Compare(v1Results, v2Results []*events_correlation.Result) ResultComparison {
	comparison := ResultComparison{
		V1Count:   len(v1Results),
		V2Count:   len(v2Results),
		Timestamp: time.Now(),
	}
	
	// Create maps for easier comparison
	v1Map := make(map[string]*events_correlation.Result)
	for _, r := range v1Results {
		key := c.resultKey(r)
		v1Map[key] = r
	}
	
	v2Map := make(map[string]*events_correlation.Result)
	for _, r := range v2Results {
		key := c.resultKey(r)
		v2Map[key] = r
	}
	
	// Find matches and differences
	for key, v1Result := range v1Map {
		if v2Result, exists := v2Map[key]; exists {
			// Both engines found this correlation
			comparison.Matches++
			
			// Check if details match
			if !c.resultsMatch(v1Result, v2Result) {
				comparison.DetailMismatches++
			}
			
			delete(v2Map, key)
		} else {
			// Only V1 found this
			comparison.V1Only++
		}
	}
	
	// Remaining in v2Map are V2-only results
	comparison.V2Only = len(v2Map)
	
	// Determine if there's a significant mismatch
	totalUnique := comparison.V1Count + comparison.V2Count
	if totalUnique > 0 {
		matchRate := float64(comparison.Matches*2) / float64(totalUnique)
		comparison.Mismatch = matchRate < 0.8 // Less than 80% match rate
	}
	
	return comparison
}

// resultKey generates a key for result comparison
func (c *ResultComparator) resultKey(r *events_correlation.Result) string {
	// Use rule ID and primary entity as key
	key := r.RuleID
	if len(r.Evidence.Entities) > 0 {
		key += ":" + r.Evidence.Entities[0].UID
	}
	return key
}

// resultsMatch checks if two results match in detail
func (c *ResultComparator) resultsMatch(r1, r2 *events_correlation.Result) bool {
	// Compare key fields
	if r1.RuleID != r2.RuleID {
		return false
	}
	
	if r1.Severity != r2.Severity {
		return false
	}
	
	if r1.Category != r2.Category {
		return false
	}
	
	// Allow some tolerance in confidence
	confidenceDiff := r1.Confidence - r2.Confidence
	if confidenceDiff < -0.1 || confidenceDiff > 0.1 {
		return false
	}
	
	return true
}

// ResultComparison contains the comparison between V1 and V2 results
type ResultComparison struct {
	V1Count          int
	V2Count          int
	Matches          int
	V1Only           int
	V2Only           int
	DetailMismatches int
	Mismatch         bool
	Timestamp        time.Time
}

// ResultDeduplicator removes duplicate results
type ResultDeduplicator struct {
	seen      map[string]time.Time
	ttl       time.Duration
	mu        sync.RWMutex
}

// NewResultDeduplicator creates a new result deduplicator
func NewResultDeduplicator(ttl time.Duration) *ResultDeduplicator {
	d := &ResultDeduplicator{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
	
	// Start cleanup routine
	go d.cleanup()
	
	return d
}

// Deduplicate removes duplicate results
func (d *ResultDeduplicator) Deduplicate(results []*events_correlation.Result) []*events_correlation.Result {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	now := time.Now()
	deduped := make([]*events_correlation.Result, 0, len(results))
	
	for _, result := range results {
		key := d.resultKey(result)
		
		if lastSeen, exists := d.seen[key]; exists {
			// Check if it's within deduplication window
			if now.Sub(lastSeen) < d.ttl {
				continue // Skip duplicate
			}
		}
		
		d.seen[key] = now
		deduped = append(deduped, result)
	}
	
	return deduped
}

// resultKey generates a deduplication key
func (d *ResultDeduplicator) resultKey(r *events_correlation.Result) string {
	key := r.RuleID + ":" + r.Title
	if len(r.Evidence.Entities) > 0 {
		key += ":" + r.Evidence.Entities[0].UID
	}
	return key
}

// cleanup periodically removes old entries
func (d *ResultDeduplicator) cleanup() {
	ticker := time.NewTicker(d.ttl)
	defer ticker.Stop()
	
	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for key, lastSeen := range d.seen {
			if now.Sub(lastSeen) > d.ttl {
				delete(d.seen, key)
			}
		}
		d.mu.Unlock()
	}
}

// ResultHandler handles correlation results
type ResultHandler interface {
	HandleResult(result *events_correlation.Result) error
}

// DefaultResultHandler provides basic result handling
type DefaultResultHandler struct{}

// NewDefaultResultHandler creates a new default result handler
func NewDefaultResultHandler() *DefaultResultHandler {
	return &DefaultResultHandler{}
}

// HandleResult handles a correlation result
func (h *DefaultResultHandler) HandleResult(result *events_correlation.Result) error {
	// Default implementation - just log the result
	// In production, this would send to alerting, storage, etc.
	return nil
}