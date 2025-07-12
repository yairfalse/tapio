package hybrid

import (
	"hash/fnv"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// RouteDecision represents the routing decision for events
type RouteDecision int

const (
	RouteToV1 RouteDecision = iota
	RouteToV2
	RouteSplit
)

// TrafficRouter manages traffic routing between V1 and V2 engines
type TrafficRouter struct {
	strategy        RoutingStrategy
	v2Percentage    atomic.Int32
	
	// Rule-based routing
	ruleRouting     map[string]RouteDecision
	ruleRoutingMu   sync.RWMutex
	
	// Entity-based routing
	entityRouting   map[string]RouteDecision
	entityRoutingMu sync.RWMutex
	
	// Progressive routing state
	progressiveState *ProgressiveState
	
	// Load-based routing
	loadMonitor     *LoadMonitor
	
	// Consistent hashing for stable routing
	hasher          *ConsistentHasher
}

// ProgressiveState manages progressive rollout
type ProgressiveState struct {
	startTime       time.Time
	stages          []ProgressiveStage
	currentStage    int
	mu              sync.RWMutex
}

// ProgressiveStage defines a rollout stage
type ProgressiveStage struct {
	Percentage      int32
	Duration        time.Duration
	MinEvents       int64
	SuccessCriteria func(metrics *HybridMetrics) bool
}

// NewTrafficRouter creates a new traffic router
func NewTrafficRouter(strategy RoutingStrategy, initialV2Percentage int32) *TrafficRouter {
	router := &TrafficRouter{
		strategy:      strategy,
		ruleRouting:   make(map[string]RouteDecision),
		entityRouting: make(map[string]RouteDecision),
		hasher:        NewConsistentHasher(),
		loadMonitor:   NewLoadMonitor(),
	}
	
	router.v2Percentage.Store(initialV2Percentage)
	
	// Initialize progressive routing if needed
	if strategy == RoutingProgressive {
		router.progressiveState = &ProgressiveState{
			startTime: time.Now(),
			stages: []ProgressiveStage{
				{Percentage: 1, Duration: 1 * time.Hour, MinEvents: 1000},
				{Percentage: 5, Duration: 4 * time.Hour, MinEvents: 10000},
				{Percentage: 10, Duration: 12 * time.Hour, MinEvents: 50000},
				{Percentage: 25, Duration: 24 * time.Hour, MinEvents: 100000},
				{Percentage: 50, Duration: 48 * time.Hour, MinEvents: 500000},
				{Percentage: 75, Duration: 72 * time.Hour, MinEvents: 1000000},
				{Percentage: 100, Duration: 0, MinEvents: 0},
			},
		}
	}
	
	return router
}

// RouteDecision determines where to route the events
func (r *TrafficRouter) RouteDecision(events []events_correlation.Event) RouteDecision {
	if len(events) == 0 {
		return RouteToV1
	}
	
	v2Percentage := r.GetV2Percentage()
	
	// If V2 is disabled, always route to V1
	if v2Percentage == 0 {
		return RouteToV1
	}
	
	// If V2 is at 100%, always route to V2
	if v2Percentage == 100 {
		return RouteToV2
	}
	
	// Apply routing strategy
	switch r.strategy {
	case RoutingRandom:
		return r.randomRoute(v2Percentage)
		
	case RoutingRuleBased:
		return r.ruleBasedRoute(events)
		
	case RoutingEntityBased:
		return r.entityBasedRoute(events)
		
	case RoutingProgressive:
		return r.progressiveRoute(events)
		
	case RoutingLoadBased:
		return r.loadBasedRoute(events, v2Percentage)
		
	default:
		return r.randomRoute(v2Percentage)
	}
}

// randomRoute uses random routing based on percentage
func (r *TrafficRouter) randomRoute(v2Percentage int32) RouteDecision {
	if rand.Int31n(100) < v2Percentage {
		return RouteToV2
	}
	return RouteToV1
}

// ruleBasedRoute routes based on rule configuration
func (r *TrafficRouter) ruleBasedRoute(events []events_correlation.Event) RouteDecision {
	// Check if any event has a rule override
	r.ruleRoutingMu.RLock()
	defer r.ruleRoutingMu.RUnlock()
	
	v1Count := 0
	v2Count := 0
	
	for _, event := range events {
		// Extract rule ID from event metadata
		if ruleID, ok := event.Labels["rule_id"]; ok {
			if decision, exists := r.ruleRouting[ruleID]; exists {
				switch decision {
				case RouteToV1:
					v1Count++
				case RouteToV2:
					v2Count++
				}
			}
		}
	}
	
	// If we have specific routing preferences, use them
	if v1Count > 0 && v2Count == 0 {
		return RouteToV1
	}
	if v2Count > 0 && v1Count == 0 {
		return RouteToV2
	}
	if v1Count > 0 && v2Count > 0 {
		return RouteSplit
	}
	
	// Fall back to percentage-based routing
	return r.randomRoute(r.GetV2Percentage())
}

// entityBasedRoute routes based on entity configuration
func (r *TrafficRouter) entityBasedRoute(events []events_correlation.Event) RouteDecision {
	r.entityRoutingMu.RLock()
	defer r.entityRoutingMu.RUnlock()
	
	// Use consistent hashing for stable routing by entity
	if len(events) > 0 {
		entity := events[0].Entity
		entityKey := entity.UID
		
		// Check explicit routing
		if decision, exists := r.entityRouting[entityKey]; exists {
			return decision
		}
		
		// Use consistent hashing for stable routing
		if r.hasher.RouteToV2(entityKey, r.GetV2Percentage()) {
			return RouteToV2
		}
	}
	
	return RouteToV1
}

// progressiveRoute implements progressive rollout
func (r *TrafficRouter) progressiveRoute(events []events_correlation.Event) RouteDecision {
	r.progressiveState.mu.RLock()
	currentStage := r.progressiveState.currentStage
	stages := r.progressiveState.stages
	r.progressiveState.mu.RUnlock()
	
	// Check if we should advance to next stage
	if currentStage < len(stages)-1 {
		stage := stages[currentStage]
		elapsed := time.Since(r.progressiveState.startTime)
		
		if elapsed >= stage.Duration {
			// Advance to next stage
			r.progressiveState.mu.Lock()
			r.progressiveState.currentStage++
			newStage := r.progressiveState.stages[r.progressiveState.currentStage]
			r.SetV2Percentage(newStage.Percentage)
			r.progressiveState.mu.Unlock()
		}
	}
	
	return r.randomRoute(r.GetV2Percentage())
}

// loadBasedRoute routes based on system load
func (r *TrafficRouter) loadBasedRoute(events []events_correlation.Event, basePercentage int32) RouteDecision {
	load := r.loadMonitor.GetCurrentLoad()
	
	// Adjust percentage based on load
	adjustedPercentage := basePercentage
	
	if load.V1Load > 0.8 && load.V2Load < 0.5 {
		// V1 is loaded, route more to V2
		adjustedPercentage = min(100, basePercentage+20)
	} else if load.V2Load > 0.8 && load.V1Load < 0.5 {
		// V2 is loaded, route more to V1
		adjustedPercentage = max(0, basePercentage-20)
	}
	
	return r.randomRoute(adjustedPercentage)
}

// SplitEvents splits events between V1 and V2 based on percentage
func (r *TrafficRouter) SplitEvents(events []events_correlation.Event, v2Percentage int32) (v1Events, v2Events []events_correlation.Event) {
	for _, event := range events {
		if r.shouldRouteToV2(event, v2Percentage) {
			v2Events = append(v2Events, event)
		} else {
			v1Events = append(v1Events, event)
		}
	}
	
	return v1Events, v2Events
}

// shouldRouteToV2 determines if a specific event should go to V2
func (r *TrafficRouter) shouldRouteToV2(event events_correlation.Event, v2Percentage int32) bool {
	// Use consistent hashing based on event fingerprint
	return r.hasher.RouteToV2(event.Fingerprint, v2Percentage)
}

// SetV2Percentage updates the V2 routing percentage
func (r *TrafficRouter) SetV2Percentage(percentage int32) {
	if percentage < 0 {
		percentage = 0
	} else if percentage > 100 {
		percentage = 100
	}
	r.v2Percentage.Store(percentage)
}

// GetV2Percentage returns the current V2 routing percentage
func (r *TrafficRouter) GetV2Percentage() int32 {
	return r.v2Percentage.Load()
}

// SetRuleRouting configures routing for a specific rule
func (r *TrafficRouter) SetRuleRouting(ruleID string, decision RouteDecision) {
	r.ruleRoutingMu.Lock()
	defer r.ruleRoutingMu.Unlock()
	r.ruleRouting[ruleID] = decision
}

// SetEntityRouting configures routing for a specific entity
func (r *TrafficRouter) SetEntityRouting(entityID string, decision RouteDecision) {
	r.entityRoutingMu.Lock()
	defer r.entityRoutingMu.Unlock()
	r.entityRouting[entityID] = decision
}

// ConsistentHasher provides consistent hashing for stable routing
type ConsistentHasher struct {
	nodes []uint32
}

// NewConsistentHasher creates a new consistent hasher
func NewConsistentHasher() *ConsistentHasher {
	// Create virtual nodes for percentage buckets
	nodes := make([]uint32, 100)
	for i := 0; i < 100; i++ {
		nodes[i] = uint32(i)
	}
	
	return &ConsistentHasher{
		nodes: nodes,
	}
}

// RouteToV2 determines if an item should route to V2 based on consistent hash
func (h *ConsistentHasher) RouteToV2(key string, v2Percentage int32) bool {
	hash := h.hash(key)
	bucket := hash % 100
	return bucket < uint32(v2Percentage)
}

// hash generates a consistent hash for a string
func (h *ConsistentHasher) hash(s string) uint32 {
	hasher := fnv.New32a()
	hasher.Write([]byte(s))
	return hasher.Sum32()
}

// LoadMonitor monitors load on both engines
type LoadMonitor struct {
	v1Load atomic.Uint64 // Represented as percentage * 100
	v2Load atomic.Uint64
	
	v1Events atomic.Uint64
	v2Events atomic.Uint64
	
	lastReset time.Time
	mu        sync.Mutex
}

// NewLoadMonitor creates a new load monitor
func NewLoadMonitor() *LoadMonitor {
	return &LoadMonitor{
		lastReset: time.Now(),
	}
}

// UpdateV1Load updates V1 engine load
func (m *LoadMonitor) UpdateV1Load(events int) {
	m.v1Events.Add(uint64(events))
}

// UpdateV2Load updates V2 engine load
func (m *LoadMonitor) UpdateV2Load(events int) {
	m.v2Events.Add(uint64(events))
}

// GetCurrentLoad returns current load metrics
func (m *LoadMonitor) GetCurrentLoad() LoadMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Reset every minute
	if time.Since(m.lastReset) > time.Minute {
		m.v1Events.Store(0)
		m.v2Events.Store(0)
		m.lastReset = time.Now()
	}
	
	v1Events := m.v1Events.Load()
	v2Events := m.v2Events.Load()
	total := v1Events + v2Events
	
	var v1Load, v2Load float64
	if total > 0 {
		v1Load = float64(v1Events) / float64(total)
		v2Load = float64(v2Events) / float64(total)
	}
	
	return LoadMetrics{
		V1Load:   v1Load,
		V2Load:   v2Load,
		V1Events: v1Events,
		V2Events: v2Events,
	}
}

// LoadMetrics contains load information for both engines
type LoadMetrics struct {
	V1Load   float64
	V2Load   float64
	V1Events uint64
	V2Events uint64
}

// Helper functions
func min(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}