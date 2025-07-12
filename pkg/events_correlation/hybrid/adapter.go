package hybrid

import (
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/correlation_v2"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// EventAdapter converts between V1 and V2 event formats
type EventAdapter struct {
	// Object pools for zero-allocation conversions
	v2EventPool sync.Pool
	
	// Caching for repeated conversions
	conversionCache *ConversionCache
	
	// Metrics
	conversions     uint64
	conversionTime  time.Duration
}

// NewEventAdapter creates a new event adapter
func NewEventAdapter() *EventAdapter {
	return &EventAdapter{
		v2EventPool: sync.Pool{
			New: func() interface{} {
				return &correlation_v2.Event{}
			},
		},
		conversionCache: NewConversionCache(10000, 5*time.Minute),
	}
}

// ConvertEventsToV2 converts a batch of V1 events to V2 format
func (a *EventAdapter) ConvertEventsToV2(v1Events []events_correlation.Event) []*events_correlation.Event {
	v2Events := make([]*events_correlation.Event, 0, len(v1Events))
	
	for i := range v1Events {
		if v2Event := a.ConvertEventToV2(&v1Events[i]); v2Event != nil {
			v2Events = append(v2Events, v2Event)
		}
	}
	
	return v2Events
}

// ConvertEventToV2 converts a single V1 event to V2 format
func (a *EventAdapter) ConvertEventToV2(v1Event *events_correlation.Event) *events_correlation.Event {
	if v1Event == nil {
		return nil
	}
	
	// Check cache first
	if cached := a.conversionCache.Get(v1Event.ID); cached != nil {
		return cached
	}
	
	start := time.Now()
	defer func() {
		a.conversionTime += time.Since(start)
		a.conversions++
	}()
	
	// For now, V1 and V2 use the same event type, so we can return as-is
	// In a real implementation, we'd need to convert between different formats
	
	// Clone the event to avoid mutations
	v2Event := &events_correlation.Event{
		ID:          v1Event.ID,
		Timestamp:   v1Event.Timestamp,
		Source:      v1Event.Source,
		Type:        v1Event.Type,
		Entity:      v1Event.Entity,
		Attributes:  a.cloneAttributes(v1Event.Attributes),
		Fingerprint: v1Event.Fingerprint,
		Labels:      a.cloneLabels(v1Event.Labels),
	}
	
	// Cache the conversion
	a.conversionCache.Put(v1Event.ID, v2Event)
	
	return v2Event
}

// ConvertRuleToV2 converts a V1 rule to V2 format
func (a *EventAdapter) ConvertRuleToV2(v1Rule *events_correlation.Rule) *events_correlation.Rule {
	if v1Rule == nil {
		return nil
	}
	
	// Check if rule is V2 compatible
	if !a.isV2Compatible(v1Rule) {
		return nil
	}
	
	// For now, return the same rule as V1 and V2 use the same format
	// In a real implementation, we'd need to adapt the rule evaluation function
	return v1Rule
}

// ConvertResultFromV2 converts a V2 result back to V1 format
func (a *EventAdapter) ConvertResultFromV2(v2Result *correlation_v2.Result) *events_correlation.Result {
	if v2Result == nil {
		return nil
	}
	
	// Map V2 result to V1 format
	return &events_correlation.Result{
		RuleID:      v2Result.RuleID,
		RuleName:    v2Result.RuleName,
		Timestamp:   v2Result.Timestamp,
		Confidence:  v2Result.Confidence,
		Severity:    a.mapSeverity(v2Result.Severity),
		Category:    a.mapCategory(v2Result.Category),
		Title:       v2Result.Title,
		Description: v2Result.Description,
		Evidence: events_correlation.Evidence{
			Events:   a.convertEvents(v2Result.Events),
			Entities: a.convertEntities(v2Result.Entities),
			Metrics:  a.convertMetrics(v2Result.Metrics),
		},
		Recommendations: v2Result.Recommendations,
		Actions:         a.convertActions(v2Result.Actions),
		TTL:             v2Result.TTL,
		Metadata:        a.convertMetadata(v2Result.Metadata),
	}
}

// isV2Compatible checks if a rule can run on V2 engine
func (a *EventAdapter) isV2Compatible(rule *events_correlation.Rule) bool {
	// Check various compatibility criteria
	
	// 1. Check if rule requires sources that V2 supports
	supportedSources := map[events_correlation.EventSource]bool{
		events_correlation.SourceEBPF:       true,
		events_correlation.SourceKubernetes: true,
		events_correlation.SourceMetrics:    true,
	}
	
	for _, source := range rule.RequiredSources {
		if !supportedSources[source] {
			return false
		}
	}
	
	// 2. Check if rule has specific tags indicating V2 support
	for _, tag := range rule.Tags {
		if tag == "v2-compatible" {
			return true
		}
		if tag == "v1-only" {
			return false
		}
	}
	
	// 3. Check rule category - some categories might not be ready for V2
	switch rule.Category {
	case events_correlation.CategoryResource:
		return true // Resource rules are V2 ready
	case events_correlation.CategoryPerformance:
		return true // Performance rules are V2 ready
	default:
		// Be conservative for other categories
		return false
	}
}

// cloneAttributes creates a deep copy of attributes
func (a *EventAdapter) cloneAttributes(attrs map[string]interface{}) map[string]interface{} {
	if attrs == nil {
		return nil
	}
	
	cloned := make(map[string]interface{}, len(attrs))
	for k, v := range attrs {
		cloned[k] = v
	}
	return cloned
}

// cloneLabels creates a deep copy of labels
func (a *EventAdapter) cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	
	cloned := make(map[string]string, len(labels))
	for k, v := range labels {
		cloned[k] = v
	}
	return cloned
}

// mapSeverity maps V2 severity to V1 format
func (a *EventAdapter) mapSeverity(v2Severity string) events_correlation.Severity {
	// Assuming V2 uses string severity, map to V1 enum
	switch v2Severity {
	case "low":
		return events_correlation.SeverityLow
	case "medium":
		return events_correlation.SeverityMedium
	case "high":
		return events_correlation.SeverityHigh
	case "critical":
		return events_correlation.SeverityCritical
	default:
		return events_correlation.SeverityMedium
	}
}

// mapCategory maps V2 category to V1 format
func (a *EventAdapter) mapCategory(v2Category string) events_correlation.Category {
	// Assuming V2 uses string category, map to V1 enum
	switch v2Category {
	case "resource":
		return events_correlation.CategoryResource
	case "performance":
		return events_correlation.CategoryPerformance
	case "reliability":
		return events_correlation.CategoryReliability
	case "security":
		return events_correlation.CategorySecurity
	case "network":
		return events_correlation.CategoryNetwork
	default:
		return events_correlation.CategoryReliability
	}
}

// convertEvents converts V2 events to V1 format
func (a *EventAdapter) convertEvents(v2Events []correlation_v2.Event) []events_correlation.Event {
	// Placeholder - would need actual conversion logic
	return []events_correlation.Event{}
}

// convertEntities converts V2 entities to V1 format
func (a *EventAdapter) convertEntities(v2Entities []correlation_v2.Entity) []events_correlation.Entity {
	// Placeholder - would need actual conversion logic
	return []events_correlation.Entity{}
}

// convertMetrics converts V2 metrics to V1 format
func (a *EventAdapter) convertMetrics(v2Metrics map[string]interface{}) map[string]float64 {
	if v2Metrics == nil {
		return nil
	}
	
	metrics := make(map[string]float64)
	for k, v := range v2Metrics {
		if floatVal, ok := v.(float64); ok {
			metrics[k] = floatVal
		}
	}
	return metrics
}

// convertMetadata converts V2 metadata to V1 format
func (a *EventAdapter) convertMetadata(v2Metadata map[string]interface{}) map[string]string {
	if v2Metadata == nil {
		return nil
	}
	
	metadata := make(map[string]string)
	for k, v := range v2Metadata {
		if strVal, ok := v.(string); ok {
			metadata[k] = strVal
		} else {
			metadata[k] = fmt.Sprintf("%v", v)
		}
	}
	return metadata
}

// convertActions converts V2 actions to V1 format
func (a *EventAdapter) convertActions(v2Actions []correlation_v2.Action) []events_correlation.Action {
	if v2Actions == nil {
		return nil
	}
	
	actions := make([]events_correlation.Action, len(v2Actions))
	for i, v2Action := range v2Actions {
		actions[i] = events_correlation.Action{
			Type:       v2Action.Type,
			Target:     v2Action.Description, // Use description as target
			Parameters: a.convertActionParams(v2Action.Parameters),
		}
	}
	return actions
}

// convertActionParams converts action parameters
func (a *EventAdapter) convertActionParams(v2Params map[string]interface{}) map[string]string {
	if v2Params == nil {
		return nil
	}
	
	params := make(map[string]string)
	for k, v := range v2Params {
		params[k] = fmt.Sprintf("%v", v)
	}
	return params
}

// GetStats returns adapter statistics
func (a *EventAdapter) GetStats() AdapterStats {
	avgTime := time.Duration(0)
	if a.conversions > 0 {
		avgTime = a.conversionTime / time.Duration(a.conversions)
	}
	
	return AdapterStats{
		TotalConversions:    a.conversions,
		AverageConversionTime: avgTime,
		CacheHitRate:        a.conversionCache.HitRate(),
		CacheSize:           a.conversionCache.Size(),
	}
}

// AdapterStats contains adapter performance statistics
type AdapterStats struct {
	TotalConversions      uint64
	AverageConversionTime time.Duration
	CacheHitRate          float64
	CacheSize             int
}

// ConversionCache caches event conversions to avoid repeated work
type ConversionCache struct {
	cache      map[string]*cacheEntry
	maxSize    int
	ttl        time.Duration
	hits       uint64
	misses     uint64
	mu         sync.RWMutex
}

type cacheEntry struct {
	event     *events_correlation.Event
	timestamp time.Time
}

// NewConversionCache creates a new conversion cache
func NewConversionCache(maxSize int, ttl time.Duration) *ConversionCache {
	cache := &ConversionCache{
		cache:   make(map[string]*cacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
	
	// Start cleanup routine
	go cache.cleanup()
	
	return cache
}

// Get retrieves an event from cache
func (c *ConversionCache) Get(id string) *events_correlation.Event {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if entry, exists := c.cache[id]; exists {
		if time.Since(entry.timestamp) < c.ttl {
			c.hits++
			return entry.event
		}
	}
	
	c.misses++
	return nil
}

// Put stores an event in cache
func (c *ConversionCache) Put(id string, event *events_correlation.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Evict old entries if at capacity
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}
	
	c.cache[id] = &cacheEntry{
		event:     event,
		timestamp: time.Now(),
	}
}

// evictOldest removes the oldest cache entry
func (c *ConversionCache) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	
	for id, entry := range c.cache {
		if oldestID == "" || entry.timestamp.Before(oldestTime) {
			oldestID = id
			oldestTime = entry.timestamp
		}
	}
	
	if oldestID != "" {
		delete(c.cache, oldestID)
	}
}

// cleanup periodically removes expired entries
func (c *ConversionCache) cleanup() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for id, entry := range c.cache {
			if now.Sub(entry.timestamp) > c.ttl {
				delete(c.cache, id)
			}
		}
		c.mu.Unlock()
	}
}

// HitRate returns the cache hit rate
func (c *ConversionCache) HitRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	total := c.hits + c.misses
	if total == 0 {
		return 0
	}
	
	return float64(c.hits) / float64(total)
}

// Size returns the current cache size
func (c *ConversionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	return len(c.cache)
}