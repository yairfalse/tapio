package correlation_v2

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/correlation_v2/router"
	"github.com/yairfalse/tapio/pkg/correlation_v2/shard"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// HighPerformanceEngine implements a killer correlation engine
// Designed for 1M+ events/second with <1ms latency
type HighPerformanceEngine struct {
	// Configuration
	config EngineConfig
	
	// Core components
	eventRouter *router.EventRouter
	shards      []*shard.ProcessingShard
	
	// Result handling
	resultsChan   chan *events_correlation.Result
	resultHandler ResultHandler
	
	// Load management
	loadBalancer  *LoadBalancer
	backpressure  *BackpressureController
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Performance metrics
	totalEvents      uint64
	processedEvents  uint64
	droppedEvents    uint64
	generatedResults uint64
	startTime        time.Time
	
	// Health monitoring
	healthChecker *HealthChecker
	isHealthy     int32 // Atomic boolean
}

// EngineConfig configures the high-performance engine
type EngineConfig struct {
	// Sharding configuration
	NumShards    int `json:"num_shards"`
	BufferSize   uint64 `json:"buffer_size"`
	
	// Performance tuning
	BatchSize           int           `json:"batch_size"`
	BatchTimeout        time.Duration `json:"batch_timeout"`
	MaxConcurrentRules  int           `json:"max_concurrent_rules"`
	
	// Load management
	BackpressureThreshold float64       `json:"backpressure_threshold"`
	MaxBackpressureTime   time.Duration `json:"max_backpressure_time"`
	LoadBalancingEnabled  bool          `json:"load_balancing_enabled"`
	
	// Monitoring
	HealthCheckInterval   time.Duration `json:"health_check_interval"`
	MetricsInterval       time.Duration `json:"metrics_interval"`
	EnableProfiling       bool          `json:"enable_profiling"`
	
	// Memory management
	MaxMemoryMB           int  `json:"max_memory_mb"`
	EnableGCOptimization  bool `json:"enable_gc_optimization"`
}

// DefaultEngineConfig returns optimized default configuration
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		NumShards:             runtime.NumCPU(),
		BufferSize:            65536, // 64K per shard
		BatchSize:             256,
		BatchTimeout:          10 * time.Millisecond,
		MaxConcurrentRules:    1000,
		BackpressureThreshold: 0.8,
		MaxBackpressureTime:   100 * time.Millisecond,
		LoadBalancingEnabled:  true,
		HealthCheckInterval:   30 * time.Second,
		MetricsInterval:       10 * time.Second,
		EnableProfiling:       false,
		MaxMemoryMB:           512,
		EnableGCOptimization:  true,
	}
}

// NewHighPerformanceEngine creates a new killer correlation engine
func NewHighPerformanceEngine(config EngineConfig) *HighPerformanceEngine {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create event router
	routerConfig := router.RouterConfig{
		NumShards:             config.NumShards,
		BufferSize:            config.BufferSize,
		BackpressureThreshold: config.BackpressureThreshold,
		MaxBackpressureTime:   config.MaxBackpressureTime,
		EnableNUMA:            true,
	}
	eventRouter := router.NewEventRouter(routerConfig)
	
	// Create processing shards
	shards := make([]*shard.ProcessingShard, config.NumShards)
	for i := 0; i < config.NumShards; i++ {
		shardConfig := shard.DefaultShardConfig(i)
		shardConfig.BatchSize = config.BatchSize
		shardConfig.BatchTimeout = config.BatchTimeout
		shardConfig.MaxRules = config.MaxConcurrentRules / config.NumShards
		shardConfig.EnableProfiling = config.EnableProfiling
		
		ringBuffer := eventRouter.GetShardBuffer(i)
		shards[i] = shard.NewProcessingShard(ringBuffer, shardConfig)
	}
	
	engine := &HighPerformanceEngine{
		config:       config,
		eventRouter:  eventRouter,
		shards:       shards,
		resultsChan:  make(chan *events_correlation.Result, 10000),
		ctx:          ctx,
		cancel:       cancel,
		startTime:    time.Now(),
	}
	
	// Initialize components
	engine.loadBalancer = NewLoadBalancer(engine.shards)
	engine.backpressure = NewBackpressureController(config.BackpressureThreshold)
	engine.healthChecker = NewHealthChecker(engine)
	engine.resultHandler = NewDefaultResultHandler()
	
	// Set initial health status
	atomic.StoreInt32(&engine.isHealthy, 1)
	
	return engine
}

// Start begins the high-performance correlation engine
func (hpe *HighPerformanceEngine) Start() error {
	// Start all processing shards
	for i, shard := range hpe.shards {
		if err := shard.Start(); err != nil {
			return fmt.Errorf("failed to start shard %d: %w", i, err)
		}
	}
	
	// Start result processing
	hpe.wg.Add(1)
	go hpe.processResults()
	
	// Start health monitoring
	hpe.wg.Add(1)
	go hpe.monitorHealth()
	
	// Start metrics collection
	hpe.wg.Add(1)
	go hpe.collectMetrics()
	
	// Apply GC optimizations if enabled
	if hpe.config.EnableGCOptimization {
		hpe.optimizeGC()
	}
	
	return nil
}

// ProcessEvent processes a single event through the correlation engine
func (hpe *HighPerformanceEngine) ProcessEvent(event *events_correlation.Event) bool {
	atomic.AddUint64(&hpe.totalEvents, 1)
	
	// Check backpressure
	if hpe.backpressure.ShouldDrop() {
		atomic.AddUint64(&hpe.droppedEvents, 1)
		return false
	}
	
	// Route event to appropriate shard
	if hpe.eventRouter.RouteEvent(event) {
		atomic.AddUint64(&hpe.processedEvents, 1)
		return true
	} else {
		atomic.AddUint64(&hpe.droppedEvents, 1)
		return false
	}
}

// ProcessBatch processes multiple events efficiently
func (hpe *HighPerformanceEngine) ProcessBatch(events []*events_correlation.Event) int {
	processed := 0
	
	for _, event := range events {
		if hpe.ProcessEvent(event) {
			processed++
		}
	}
	
	return processed
}

// RegisterRule registers a correlation rule with all shards
func (hpe *HighPerformanceEngine) RegisterRule(rule *events_correlation.Rule) error {
	// Register rule with all shards for parallel processing
	for i, shard := range hpe.shards {
		if err := shard.RegisterRule(rule); err != nil {
			return fmt.Errorf("failed to register rule with shard %d: %w", i, err)
		}
	}
	
	return nil
}

// processResults handles correlation results from all shards
func (hpe *HighPerformanceEngine) processResults() {
	defer hpe.wg.Done()
	
	// TODO: Collect results from all shards
	// This would involve reading from result channels of each shard
	// For now, we'll implement a basic result processing loop
	
	for {
		select {
		case <-hpe.ctx.Done():
			return
		case result := <-hpe.resultsChan:
			atomic.AddUint64(&hpe.generatedResults, 1)
			
			// Handle the result
			if hpe.resultHandler != nil {
				hpe.resultHandler.HandleResult(result)
			}
		}
	}
}

// monitorHealth continuously monitors engine health
func (hpe *HighPerformanceEngine) monitorHealth() {
	defer hpe.wg.Done()
	
	ticker := time.NewTicker(hpe.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hpe.ctx.Done():
			return
		case <-ticker.C:
			healthy := hpe.healthChecker.CheckHealth()
			if healthy {
				atomic.StoreInt32(&hpe.isHealthy, 1)
			} else {
				atomic.StoreInt32(&hpe.isHealthy, 0)
			}
		}
	}
}

// collectMetrics periodically collects performance metrics
func (hpe *HighPerformanceEngine) collectMetrics() {
	defer hpe.wg.Done()
	
	ticker := time.NewTicker(hpe.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hpe.ctx.Done():
			return
		case <-ticker.C:
			hpe.updateMetrics()
		}
	}
}

// updateMetrics updates backpressure and load balancing based on current metrics
func (hpe *HighPerformanceEngine) updateMetrics() {
	// Update backpressure controller
	routerStats := hpe.eventRouter.Stats()
	hpe.backpressure.UpdateMetrics(routerStats.AvgUtilization, routerStats.DropRate)
	
	// Update load balancer if enabled
	if hpe.config.LoadBalancingEnabled {
		hpe.loadBalancer.RebalanceIfNeeded()
	}
}

// optimizeGC applies garbage collection optimizations
func (hpe *HighPerformanceEngine) optimizeGC() {
	// Set GC target to reduce frequency
	debug.SetGCPercent(200) // Only GC when heap grows by 200%
	
	// Set max memory limit
	if hpe.config.MaxMemoryMB > 0 {
		debug.SetMemoryLimit(int64(hpe.config.MaxMemoryMB) * 1024 * 1024)
	}
}

// Stats returns comprehensive engine statistics
func (hpe *HighPerformanceEngine) Stats() EngineStats {
	totalEvents := atomic.LoadUint64(&hpe.totalEvents)
	processedEvents := atomic.LoadUint64(&hpe.processedEvents)
	droppedEvents := atomic.LoadUint64(&hpe.droppedEvents)
	generatedResults := atomic.LoadUint64(&hpe.generatedResults)
	
	uptime := time.Since(hpe.startTime)
	
	stats := EngineStats{
		TotalEvents:      totalEvents,
		ProcessedEvents:  processedEvents,
		DroppedEvents:    droppedEvents,
		GeneratedResults: generatedResults,
		IsHealthy:        atomic.LoadInt32(&hpe.isHealthy) == 1,
		Uptime:           uptime,
		NumShards:        len(hpe.shards),
	}
	
	// Calculate rates
	if uptime.Seconds() > 0 {
		stats.EventsPerSecond = float64(processedEvents) / uptime.Seconds()
		stats.ResultsPerSecond = float64(generatedResults) / uptime.Seconds()
	}
	
	// Calculate drop rate
	if totalEvents > 0 {
		stats.DropRate = float64(droppedEvents) / float64(totalEvents)
	}
	
	// Get router statistics
	stats.RouterStats = hpe.eventRouter.Stats()
	
	// Get shard statistics
	stats.ShardStats = make([]shard.ShardStats, len(hpe.shards))
	for i, shard := range hpe.shards {
		stats.ShardStats[i] = shard.Stats()
	}
	
	return stats
}

// EngineStats contains comprehensive engine performance metrics
type EngineStats struct {
	// Event processing
	TotalEvents      uint64  `json:"total_events"`
	ProcessedEvents  uint64  `json:"processed_events"`
	DroppedEvents    uint64  `json:"dropped_events"`
	GeneratedResults uint64  `json:"generated_results"`
	EventsPerSecond  float64 `json:"events_per_second"`
	ResultsPerSecond float64 `json:"results_per_second"`
	DropRate         float64 `json:"drop_rate"`
	
	// System health
	IsHealthy bool          `json:"is_healthy"`
	Uptime    time.Duration `json:"uptime"`
	NumShards int           `json:"num_shards"`
	
	// Component statistics
	RouterStats router.RouterStats   `json:"router_stats"`
	ShardStats  []shard.ShardStats   `json:"shard_stats"`
}

// IsHealthy returns true if the engine is operating normally
func (hpe *HighPerformanceEngine) IsHealthy() bool {
	return atomic.LoadInt32(&hpe.isHealthy) == 1
}

// Stop gracefully stops the correlation engine
func (hpe *HighPerformanceEngine) Stop() error {
	// Cancel context to stop all goroutines
	hpe.cancel()
	
	// Stop all shards
	for i, shard := range hpe.shards {
		if err := shard.Stop(); err != nil {
			fmt.Printf("Error stopping shard %d: %v\n", i, err)
		}
	}
	
	// Stop router
	hpe.eventRouter.Shutdown()
	
	// Wait for all goroutines to finish
	hpe.wg.Wait()
	
	// Close results channel
	close(hpe.resultsChan)
	
	return nil
}

// Reset clears all statistics and state
func (hpe *HighPerformanceEngine) Reset() {
	atomic.StoreUint64(&hpe.totalEvents, 0)
	atomic.StoreUint64(&hpe.processedEvents, 0)
	atomic.StoreUint64(&hpe.droppedEvents, 0)
	atomic.StoreUint64(&hpe.generatedResults, 0)
	hpe.startTime = time.Now()
	
	hpe.eventRouter.Reset()
	
	for _, shard := range hpe.shards {
		shard.Reset()
	}
}

// GetResults returns the results channel for consumption
func (hpe *HighPerformanceEngine) GetResults() <-chan *events_correlation.Result {
	return hpe.resultsChan
}
// GetMetrics returns engine performance metrics
func (hpe *HighPerformanceEngine) GetMetrics() EngineMetrics {
	now := time.Now()
	uptime := now.Sub(hpe.startTime)
	
	// Calculate average latency
	var avgLatency time.Duration
	processed := atomic.LoadUint64(&hpe.processedEvents)
	if processed > 0 {
		// Simple estimate based on processing rate
		avgLatency = time.Second / time.Duration(processed)
	}
	
	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	return EngineMetrics{
		EventsProcessed:   atomic.LoadUint64(&hpe.processedEvents),
		EventsDropped:     atomic.LoadUint64(&hpe.droppedEvents),
		ResultsGenerated:  atomic.LoadUint64(&hpe.generatedResults),
		ProcessingLatency: avgLatency,
		MemoryUsage:       memStats.Alloc,
		ActiveShards:      len(hpe.shards),
		HealthScore:       hpe.healthChecker.GetHealthScore(),
		Uptime:           uptime,
	}
}
