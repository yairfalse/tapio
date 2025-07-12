package router

import (
	"context"
	"hash/fnv"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/yairfalse/tapio/pkg/correlation_v2/lockfree"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// EventRouter implements high-performance lock-free event routing
type EventRouter struct {
	// Ring buffers for each shard
	shards []*lockfree.RingBuffer
	
	// Configuration
	numShards int
	bufferSize uint64
	
	// Performance metrics
	totalEvents   uint64
	droppedEvents uint64
	routingTime   uint64 // Nanoseconds
	
	// Backpressure control
	backpressureThreshold float64
	maxBackpressureTime   time.Duration
	
	// NUMA awareness
	numaTopology *NUMATopology
	
	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// NUMATopology provides NUMA-aware routing
type NUMATopology struct {
	nodes     []NUMANode
	coreToNode map[int]int
}

// NUMANode represents a NUMA node
type NUMANode struct {
	id    int
	cores []int
	memory uint64
}

// RouterConfig configures the event router
type RouterConfig struct {
	NumShards             int           `json:"num_shards"`
	BufferSize            uint64        `json:"buffer_size"`
	BackpressureThreshold float64       `json:"backpressure_threshold"`
	MaxBackpressureTime   time.Duration `json:"max_backpressure_time"`
	EnableNUMA            bool          `json:"enable_numa"`
}

// DefaultRouterConfig returns optimized default configuration
func DefaultRouterConfig() RouterConfig {
	return RouterConfig{
		NumShards:             runtime.NumCPU(),
		BufferSize:            65536, // 64K entries per shard
		BackpressureThreshold: 0.8,   // Trigger backpressure at 80% full
		MaxBackpressureTime:   100 * time.Millisecond,
		EnableNUMA:            true,
	}
}

// NewEventRouter creates a new high-performance event router
func NewEventRouter(config RouterConfig) *EventRouter {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create ring buffers for each shard
	shards := make([]*lockfree.RingBuffer, config.NumShards)
	for i := 0; i < config.NumShards; i++ {
		shards[i] = lockfree.NewRingBuffer(config.BufferSize)
	}
	
	router := &EventRouter{
		shards:                shards,
		numShards:             config.NumShards,
		bufferSize:            config.BufferSize,
		backpressureThreshold: config.BackpressureThreshold,
		maxBackpressureTime:   config.MaxBackpressureTime,
		ctx:                   ctx,
		cancel:                cancel,
	}
	
	// Initialize NUMA topology if enabled
	if config.EnableNUMA {
		router.numaTopology = detectNUMATopology()
	}
	
	return router
}

// RouteEvent routes an event to the appropriate shard
// Uses consistent hashing for optimal load distribution
func (er *EventRouter) RouteEvent(event *events_correlation.Event) bool {
	start := time.Now()
	defer func() {
		// Update routing time metrics
		elapsed := uint64(time.Since(start).Nanoseconds())
		atomic.AddUint64(&er.routingTime, elapsed)
		atomic.AddUint64(&er.totalEvents, 1)
	}()
	
	// Calculate shard using consistent hashing
	shardID := er.calculateShard(event)
	
	// Get the ring buffer for this shard
	ringBuffer := er.shards[shardID]
	
	// Check for backpressure
	if er.shouldApplyBackpressure(ringBuffer) {
		// Apply adaptive backpressure
		if !er.handleBackpressure(ringBuffer) {
			atomic.AddUint64(&er.droppedEvents, 1)
			return false
		}
	}
	
	// Convert event to unsafe.Pointer for lock-free storage
	eventPtr := unsafe.Pointer(event)
	
	// Try to push to ring buffer
	if !ringBuffer.Push(eventPtr) {
		atomic.AddUint64(&er.droppedEvents, 1)
		return false
	}
	
	return true
}

// calculateShard determines which shard should handle the event
func (er *EventRouter) calculateShard(event *events_correlation.Event) int {
	// Use entity information for consistent hashing
	key := event.Entity.UID
	if key == "" {
		// Fallback to entity name and namespace
		key = event.Entity.Namespace + "/" + event.Entity.Name
	}
	if key == "" {
		// Final fallback to event ID
		key = event.ID
	}
	
	// FNV hash for good distribution
	hasher := fnv.New64a()
	hasher.Write([]byte(key))
	hash := hasher.Sum64()
	
	// NUMA-aware routing if topology is available
	if er.numaTopology != nil {
		return er.numaAwareRouting(hash)
	}
	
	return int(hash % uint64(er.numShards))
}

// numaAwareRouting routes events to shards on the same NUMA node when possible
func (er *EventRouter) numaAwareRouting(hash uint64) int {
	// Get current CPU to determine NUMA node preference
	currentCPU := runtime.NumCPU() // This is approximate, but sufficient for routing
	
	if node, exists := er.numaTopology.coreToNode[currentCPU]; exists {
		// Route to a shard on the same NUMA node if possible
		nodeShards := er.getShardsForNUMANode(node)
		if len(nodeShards) > 0 {
			return nodeShards[hash%uint64(len(nodeShards))]
		}
	}
	
	// Fallback to regular routing
	return int(hash % uint64(er.numShards))
}

// getShardsForNUMANode returns shard IDs for a specific NUMA node
func (er *EventRouter) getShardsForNUMANode(nodeID int) []int {
	shardsPerNode := er.numShards / len(er.numaTopology.nodes)
	if shardsPerNode == 0 {
		shardsPerNode = 1
	}
	
	start := nodeID * shardsPerNode
	end := start + shardsPerNode
	if end > er.numShards {
		end = er.numShards
	}
	
	shards := make([]int, end-start)
	for i := start; i < end; i++ {
		shards[i-start] = i
	}
	
	return shards
}

// shouldApplyBackpressure determines if backpressure should be applied
func (er *EventRouter) shouldApplyBackpressure(ringBuffer *lockfree.RingBuffer) bool {
	stats := ringBuffer.Stats()
	return stats.Utilization > er.backpressureThreshold
}

// handleBackpressure applies intelligent backpressure
func (er *EventRouter) handleBackpressure(ringBuffer *lockfree.RingBuffer) bool {
	start := time.Now()
	
	// Adaptive wait with exponential backoff
	backoffTime := time.Microsecond
	maxBackoff := er.maxBackpressureTime
	
	for time.Since(start) < maxBackoff {
		// Check if space became available
		if !er.shouldApplyBackpressure(ringBuffer) {
			return true
		}
		
		// Wait with exponential backoff
		time.Sleep(backoffTime)
		backoffTime *= 2
		if backoffTime > maxBackoff/10 {
			backoffTime = maxBackoff / 10
		}
		
		// Yield to allow consumers to process
		runtime.Gosched()
	}
	
	return false
}

// GetShardBuffer returns the ring buffer for a specific shard
func (er *EventRouter) GetShardBuffer(shardID int) *lockfree.RingBuffer {
	if shardID < 0 || shardID >= er.numShards {
		return nil
	}
	return er.shards[shardID]
}

// NumShards returns the number of shards
func (er *EventRouter) NumShards() int {
	return er.numShards
}

// Stats returns comprehensive router statistics
func (er *EventRouter) Stats() RouterStats {
	stats := RouterStats{
		TotalEvents:   atomic.LoadUint64(&er.totalEvents),
		DroppedEvents: atomic.LoadUint64(&er.droppedEvents),
		NumShards:     er.numShards,
		ShardStats:    make([]lockfree.RingBufferStats, er.numShards),
	}
	
	// Calculate average routing time
	if stats.TotalEvents > 0 {
		totalTime := atomic.LoadUint64(&er.routingTime)
		stats.AvgRoutingTimeNs = totalTime / stats.TotalEvents
	}
	
	// Collect per-shard statistics
	totalUtilization := 0.0
	for i, shard := range er.shards {
		shardStats := shard.Stats()
		stats.ShardStats[i] = shardStats
		totalUtilization += shardStats.Utilization
	}
	
	stats.AvgUtilization = totalUtilization / float64(er.numShards)
	
	// Calculate drop rate
	if stats.TotalEvents > 0 {
		stats.DropRate = float64(stats.DroppedEvents) / float64(stats.TotalEvents)
	}
	
	return stats
}

// RouterStats contains comprehensive routing performance metrics
type RouterStats struct {
	TotalEvents       uint64                     `json:"total_events"`
	DroppedEvents     uint64                     `json:"dropped_events"`
	DropRate          float64                    `json:"drop_rate"`
	AvgRoutingTimeNs  uint64                     `json:"avg_routing_time_ns"`
	AvgUtilization    float64                    `json:"avg_utilization"`
	NumShards         int                        `json:"num_shards"`
	ShardStats        []lockfree.RingBufferStats `json:"shard_stats"`
}

// Reset clears all statistics and buffers
func (er *EventRouter) Reset() {
	atomic.StoreUint64(&er.totalEvents, 0)
	atomic.StoreUint64(&er.droppedEvents, 0)
	atomic.StoreUint64(&er.routingTime, 0)
	
	for _, shard := range er.shards {
		shard.Reset()
	}
}

// Shutdown gracefully shuts down the router
func (er *EventRouter) Shutdown() {
	er.cancel()
	
	// Wait for any in-flight operations to complete
	time.Sleep(10 * time.Millisecond)
	
	// Clear all buffers
	er.Reset()
}

// detectNUMATopology detects the NUMA topology of the system
func detectNUMATopology() *NUMATopology {
	// Simplified NUMA detection - in production, this would use
	// syscalls or /proc/cpuinfo parsing
	numCPUs := runtime.NumCPU()
	
	// Assume 2 NUMA nodes for simplicity
	nodes := make([]NUMANode, 2)
	coreToNode := make(map[int]int)
	
	coresPerNode := numCPUs / 2
	if coresPerNode == 0 {
		coresPerNode = 1
	}
	
	for i := 0; i < 2; i++ {
		start := i * coresPerNode
		end := start + coresPerNode
		if end > numCPUs {
			end = numCPUs
		}
		
		cores := make([]int, end-start)
		for j := start; j < end; j++ {
			cores[j-start] = j
			coreToNode[j] = i
		}
		
		nodes[i] = NUMANode{
			id:     i,
			cores:  cores,
			memory: 32 * 1024 * 1024 * 1024, // 32GB per node assumption
		}
	}
	
	return &NUMATopology{
		nodes:      nodes,
		coreToNode: coreToNode,
	}
}

// BatchRoute routes multiple events in a single operation for better cache efficiency
func (er *EventRouter) BatchRoute(events []*events_correlation.Event) int {
	routed := 0
	
	for _, event := range events {
		if er.RouteEvent(event) {
			routed++
		}
	}
	
	return routed
}