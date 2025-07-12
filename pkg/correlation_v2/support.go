package correlation_v2

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/correlation_v2/shard"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// LoadBalancer manages load distribution across shards
type LoadBalancer struct {
	shards       []*shard.ProcessingShard
	lastBalance  time.Time
	balanceInterval time.Duration
	mu           sync.RWMutex
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(shards []*shard.ProcessingShard) *LoadBalancer {
	return &LoadBalancer{
		shards:          shards,
		balanceInterval: 30 * time.Second,
	}
}

// RebalanceIfNeeded checks if rebalancing is needed and performs it
func (lb *LoadBalancer) RebalanceIfNeeded() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	now := time.Now()
	if now.Sub(lb.lastBalance) < lb.balanceInterval {
		return
	}
	
	// Check load distribution
	loadScores := make([]float64, len(lb.shards))
	totalLoad := 0.0
	
	for i, shard := range lb.shards {
		loadScores[i] = shard.GetLoadScore()
		totalLoad += loadScores[i]
	}
	
	if len(lb.shards) == 0 {
		return
	}
	
	avgLoad := totalLoad / float64(len(lb.shards))
	
	// Check if rebalancing is needed (if any shard is significantly over/under loaded)
	needsRebalance := false
	for _, score := range loadScores {
		if score > avgLoad*1.5 || score < avgLoad*0.5 {
			needsRebalance = true
			break
		}
	}
	
	if needsRebalance {
		// TODO: Implement actual rebalancing logic
		// This could involve migrating some workload between shards
	}
	
	lb.lastBalance = now
}

// BackpressureController manages system backpressure
type BackpressureController struct {
	threshold       float64
	currentLoad     uint64  // Atomic, scaled by 1000
	dropProbability uint64  // Atomic, scaled by 1000
	lastUpdate      time.Time
	mu              sync.RWMutex
}

// NewBackpressureController creates a new backpressure controller
func NewBackpressureController(threshold float64) *BackpressureController {
	return &BackpressureController{
		threshold: threshold,
	}
}

// UpdateMetrics updates the backpressure controller with current metrics
func (bc *BackpressureController) UpdateMetrics(utilization, dropRate float64) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	
	// Update current load
	atomic.StoreUint64(&bc.currentLoad, uint64(utilization*1000))
	
	// Calculate drop probability based on load
	if utilization > bc.threshold {
		// Exponential backoff when over threshold
		excess := utilization - bc.threshold
		probability := excess * excess * 1000 // Square for exponential effect
		if probability > 1000 {
			probability = 1000 // Cap at 100%
		}
		atomic.StoreUint64(&bc.dropProbability, uint64(probability))
	} else {
		atomic.StoreUint64(&bc.dropProbability, 0)
	}
	
	bc.lastUpdate = time.Now()
}

// ShouldDrop returns true if an event should be dropped due to backpressure
func (bc *BackpressureController) ShouldDrop() bool {
	probability := atomic.LoadUint64(&bc.dropProbability)
	if probability == 0 {
		return false
	}
	
	// Simple pseudo-random decision
	return uint64(time.Now().UnixNano()%1000) < probability
}

// HealthChecker monitors engine health
type HealthChecker struct {
	engine       *HighPerformanceEngine
	lastCheck    time.Time
	healthScore  float64
	mu           sync.RWMutex
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(engine *HighPerformanceEngine) *HealthChecker {
	return &HealthChecker{
		engine:      engine,
		healthScore: 1.0,
	}
}

// CheckHealth performs a comprehensive health check
func (hc *HealthChecker) CheckHealth() bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	score := 1.0
	
	// Check shard health
	healthyShards := 0
	for _, shard := range hc.engine.shards {
		if shard.IsHealthy() {
			healthyShards++
		}
	}
	
	shardHealthRatio := float64(healthyShards) / float64(len(hc.engine.shards))
	score *= shardHealthRatio
	
	// Check event processing rate
	stats := hc.engine.eventRouter.Stats()
	if stats.DropRate > 0.1 { // More than 10% drop rate is concerning
		score *= (1.0 - stats.DropRate)
	}
	
	// Check memory pressure
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	if hc.engine.config.MaxMemoryMB > 0 {
		memoryRatio := float64(memStats.Alloc) / float64(hc.engine.config.MaxMemoryMB*1024*1024)
		if memoryRatio > 0.9 { // Over 90% memory usage
			score *= (1.0 - (memoryRatio-0.9)*10) // Reduce score significantly
		}
	}
	
	hc.healthScore = score
	hc.lastCheck = time.Now()
	
	return score > 0.7 // Healthy if score > 70%
}

// GetHealthScore returns the current health score (0.0-1.0)
func (hc *HealthChecker) GetHealthScore() float64 {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.healthScore
}

// ResultHandler processes correlation results
type ResultHandler interface {
	HandleResult(result *events_correlation.Result)
}

// DefaultResultHandler provides basic result handling
type DefaultResultHandler struct {
	resultsProcessed uint64
	lastProcessed    time.Time
	mu               sync.RWMutex
}

// NewDefaultResultHandler creates a new default result handler
func NewDefaultResultHandler() *DefaultResultHandler {
	return &DefaultResultHandler{}
}

// HandleResult processes a correlation result
func (drh *DefaultResultHandler) HandleResult(result *events_correlation.Result) {
	drh.mu.Lock()
	defer drh.mu.Unlock()
	
	atomic.AddUint64(&drh.resultsProcessed, 1)
	drh.lastProcessed = time.Now()
	
	// TODO: Implement actual result processing
	// This could involve:
	// - Sending alerts
	// - Storing results
	// - Triggering automated responses
	// - Updating dashboards
}

// GetStats returns result handler statistics
func (drh *DefaultResultHandler) GetStats() ResultHandlerStats {
	drh.mu.RLock()
	defer drh.mu.RUnlock()
	
	return ResultHandlerStats{
		ResultsProcessed: atomic.LoadUint64(&drh.resultsProcessed),
		LastProcessed:    drh.lastProcessed,
	}
}

// ResultHandlerStats contains result handler performance metrics
type ResultHandlerStats struct {
	ResultsProcessed uint64    `json:"results_processed"`
	LastProcessed    time.Time `json:"last_processed"`
}