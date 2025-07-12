package correlation_v2

import (
	"time"

	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// Result represents a correlation result from V2 engine
type Result struct {
	RuleID          string                           `json:"rule_id"`
	RuleName        string                           `json:"rule_name"`
	Timestamp       time.Time                        `json:"timestamp"`
	Confidence      float64                          `json:"confidence"`
	Severity        string                           `json:"severity"`
	Category        string                           `json:"category"`
	Title           string                           `json:"title"`
	Description     string                           `json:"description"`
	Events          []Event                          `json:"events"`
	Entities        []Entity                         `json:"entities"`
	Metrics         map[string]interface{}           `json:"metrics"`
	Recommendations []string                         `json:"recommendations"`
	Actions         []Action                         `json:"actions"`
	TTL             time.Duration                    `json:"ttl"`
	Metadata        map[string]interface{}           `json:"metadata"`
}

// Event represents an event in V2 format (currently same as V1)
type Event = events_correlation.Event

// Entity represents an entity in V2 format (currently same as V1)
type Entity = events_correlation.Entity

// Action represents an automated action
type Action struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Enabled     bool                   `json:"enabled"`
}

// EngineMetrics contains performance metrics for the V2 engine
type EngineMetrics struct {
	EventsProcessed   uint64        `json:"events_processed"`
	EventsDropped     uint64        `json:"events_dropped"`
	ResultsGenerated  uint64        `json:"results_generated"`
	ProcessingLatency time.Duration `json:"processing_latency"`
	MemoryUsage       uint64        `json:"memory_usage"`
	ActiveShards      int           `json:"active_shards"`
	HealthScore       float64       `json:"health_score"`
	Uptime           time.Duration `json:"uptime"`
}

// ShardMetrics contains metrics for a processing shard
type ShardMetrics struct {
	ID               int           `json:"id"`
	EventsProcessed  uint64        `json:"events_processed"`
	ActiveRules      int           `json:"active_rules"`
	BufferUtilization float64       `json:"buffer_utilization"`
	ProcessingLatency time.Duration `json:"processing_latency"`
	IsHealthy        bool          `json:"is_healthy"`
	LastActivity     time.Time     `json:"last_activity"`
}

// RouterStats contains event router statistics
type RouterStats struct {
	EventsRouted     uint64  `json:"events_routed"`
	EventsDropped    uint64  `json:"events_dropped"`
	DropRate         float64 `json:"drop_rate"`
	AverageLatency   time.Duration `json:"average_latency"`
	BackpressureActive bool    `json:"backpressure_active"`
}

// TimelineStats contains timeline storage statistics
type TimelineStats struct {
	TotalEvents      uint64    `json:"total_events"`
	HotEvents        uint64    `json:"hot_events"`
	WarmEvents       uint64    `json:"warm_events"`
	ColdEvents       uint64    `json:"cold_events"`
	CompressionRatio float64   `json:"compression_ratio"`
	LastCompaction   time.Time `json:"last_compaction"`
}