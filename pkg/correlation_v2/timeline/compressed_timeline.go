package timeline

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// CompressionLevel defines the level of compression to apply
type CompressionLevel int

const (
	CompressionNone CompressionLevel = iota
	CompressionLow
	CompressionMedium
	CompressionHigh
)

// CompressedTimeline implements a high-performance compressed timeline storage
type CompressedTimeline struct {
	// Configuration
	config TimelineConfig
	
	// Storage layers
	hotStorage  *HotStorage  // Recent events, uncompressed
	warmStorage *WarmStorage // Medium-age events, lightly compressed
	coldStorage *ColdStorage // Old events, heavily compressed
	
	// Indexing
	timeIndex    *TimeIndex
	entityIndex  *EntityIndex
	
	// Metrics
	totalEvents    uint64
	hotEvents      uint64
	warmEvents     uint64
	coldEvents     uint64
	compressionRatio float64
	
	// Synchronization
	mu sync.RWMutex
	
	// Background processing
	compactionTicker *time.Ticker
	cleanupTicker    *time.Ticker
	stopChan         chan struct{}
}

// TimelineConfig configures the compressed timeline
type TimelineConfig struct {
	Capacity         int              `json:"capacity"`
	CompressionLevel CompressionLevel `json:"compression_level"`
	IndexGranularity int              `json:"index_granularity"`
	HotDuration      time.Duration    `json:"hot_duration"`
	WarmDuration     time.Duration    `json:"warm_duration"`
	CompactionInterval time.Duration  `json:"compaction_interval"`
}

// DefaultTimelineConfig returns optimized default configuration
func DefaultTimelineConfig() TimelineConfig {
	return TimelineConfig{
		Capacity:           1000000, // 1M events
		CompressionLevel:   CompressionMedium,
		IndexGranularity:   1000,
		HotDuration:        5 * time.Minute,
		WarmDuration:       30 * time.Minute,
		CompactionInterval: 60 * time.Second,
	}
}

// NewCompressedTimeline creates a new compressed timeline
func NewCompressedTimeline(config TimelineConfig) *CompressedTimeline {
	timeline := &CompressedTimeline{
		config:      config,
		hotStorage:  NewHotStorage(config.Capacity / 4),
		warmStorage: NewWarmStorage(config.Capacity / 2),
		coldStorage: NewColdStorage(config.Capacity / 4),
		timeIndex:   NewTimeIndex(config.IndexGranularity),
		entityIndex: NewEntityIndex(),
		stopChan:    make(chan struct{}),
	}
	
	// Start background processing
	timeline.compactionTicker = time.NewTicker(config.CompactionInterval)
	timeline.cleanupTicker = time.NewTicker(config.CompactionInterval * 2)
	
	go timeline.backgroundProcessor()
	
	return timeline
}

// AddEvent adds an event to the timeline
func (ct *CompressedTimeline) AddEvent(event events_correlation.Event) {
	atomic.AddUint64(&ct.totalEvents, 1)
	
	// Add to hot storage (most recent events)
	ct.hotStorage.Add(event)
	atomic.AddUint64(&ct.hotEvents, 1)
	
	// Update indices
	ct.timeIndex.AddEvent(event)
	ct.entityIndex.AddEvent(event)
}

// GetEventsInWindow retrieves events within a time window
func (ct *CompressedTimeline) GetEventsInWindow(window events_correlation.TimeWindow) []events_correlation.Event {
	var events []events_correlation.Event
	
	// Check hot storage first (fastest access)
	events = append(events, ct.hotStorage.GetEventsInWindow(window)...)
	
	// Check warm storage if needed
	if window.Start.Before(time.Now().Add(-ct.config.HotDuration)) {
		events = append(events, ct.warmStorage.GetEventsInWindow(window)...)
	}
	
	// Check cold storage if needed
	if window.Start.Before(time.Now().Add(-ct.config.WarmDuration)) {
		events = append(events, ct.coldStorage.GetEventsInWindow(window)...)
	}
	
	// Sort by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	
	return events
}

// GetEventsByEntity retrieves events for a specific entity
func (ct *CompressedTimeline) GetEventsByEntity(entityID string, limit int) []events_correlation.Event {
	return ct.entityIndex.GetEvents(entityID, limit)
}

// backgroundProcessor handles compaction and cleanup
func (ct *CompressedTimeline) backgroundProcessor() {
	for {
		select {
		case <-ct.stopChan:
			return
		case <-ct.compactionTicker.C:
			ct.compact()
		case <-ct.cleanupTicker.C:
			ct.cleanup()
		}
	}
}

// compact moves events between storage layers
func (ct *CompressedTimeline) compact() {
	now := time.Now()
	hotThreshold := now.Add(-ct.config.HotDuration)
	warmThreshold := now.Add(-ct.config.WarmDuration)
	
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	// Move events from hot to warm storage
	hotEvents := ct.hotStorage.GetEventsOlderThan(hotThreshold)
	for _, event := range hotEvents {
		ct.warmStorage.Add(event)
		atomic.AddUint64(&ct.warmEvents, 1)
		atomic.AddUint64(&ct.hotEvents, ^uint64(0)) // Decrement
	}
	
	// Move events from warm to cold storage
	warmEvents := ct.warmStorage.GetEventsOlderThan(warmThreshold)
	for _, event := range warmEvents {
		ct.coldStorage.Add(event)
		atomic.AddUint64(&ct.coldEvents, 1)
		atomic.AddUint64(&ct.warmEvents, ^uint64(0)) // Decrement
	}
}

// cleanup removes old events beyond capacity
func (ct *CompressedTimeline) cleanup() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	// Remove oldest events if over capacity
	totalEvents := atomic.LoadUint64(&ct.totalEvents)
	if int(totalEvents) > ct.config.Capacity {
		eventsToRemove := int(totalEvents) - ct.config.Capacity
		ct.coldStorage.RemoveOldest(eventsToRemove)
		atomic.AddUint64(&ct.totalEvents, ^uint64(eventsToRemove-1)) // Subtract
	}
}

// Stats returns timeline statistics
func (ct *CompressedTimeline) Stats() TimelineStats {
	return TimelineStats{
		TotalEvents:      atomic.LoadUint64(&ct.totalEvents),
		HotEvents:        atomic.LoadUint64(&ct.hotEvents),
		WarmEvents:       atomic.LoadUint64(&ct.warmEvents),
		ColdEvents:       atomic.LoadUint64(&ct.coldEvents),
		CompressionRatio: atomic.LoadUint64((*uint64)(unsafe.Pointer(&ct.compressionRatio))),
		MemoryUsage:      ct.getMemoryUsage(),
	}
}

// TimelineStats contains timeline performance metrics
type TimelineStats struct {
	TotalEvents      uint64 `json:"total_events"`
	HotEvents        uint64 `json:"hot_events"`
	WarmEvents       uint64 `json:"warm_events"`
	ColdEvents       uint64 `json:"cold_events"`
	CompressionRatio uint64 `json:"compression_ratio"`
	MemoryUsage      uint64 `json:"memory_usage"`
}

// getMemoryUsage calculates approximate memory usage
func (ct *CompressedTimeline) getMemoryUsage() uint64 {
	// Approximate calculation based on event counts and compression
	hotSize := atomic.LoadUint64(&ct.hotEvents) * 1024 // 1KB per hot event
	warmSize := atomic.LoadUint64(&ct.warmEvents) * 512 // 512B per warm event (compressed)
	coldSize := atomic.LoadUint64(&ct.coldEvents) * 256  // 256B per cold event (highly compressed)
	
	return hotSize + warmSize + coldSize
}

// Reset clears the timeline
func (ct *CompressedTimeline) Reset() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	ct.hotStorage.Reset()
	ct.warmStorage.Reset()
	ct.coldStorage.Reset()
	ct.timeIndex.Reset()
	ct.entityIndex.Reset()
	
	atomic.StoreUint64(&ct.totalEvents, 0)
	atomic.StoreUint64(&ct.hotEvents, 0)
	atomic.StoreUint64(&ct.warmEvents, 0)
	atomic.StoreUint64(&ct.coldEvents, 0)
}

// Shutdown gracefully shuts down the timeline
func (ct *CompressedTimeline) Shutdown() {
	close(ct.stopChan)
	ct.compactionTicker.Stop()
	ct.cleanupTicker.Stop()
}

// HotStorage stores recent events without compression
type HotStorage struct {
	events   []events_correlation.Event
	capacity int
	mu       sync.RWMutex
}

// NewHotStorage creates a new hot storage
func NewHotStorage(capacity int) *HotStorage {
	return &HotStorage{
		events:   make([]events_correlation.Event, 0, capacity),
		capacity: capacity,
	}
}

// Add adds an event to hot storage
func (hs *HotStorage) Add(event events_correlation.Event) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	
	hs.events = append(hs.events, event)
	
	// Remove oldest if over capacity
	if len(hs.events) > hs.capacity {
		copy(hs.events, hs.events[1:])
		hs.events = hs.events[:len(hs.events)-1]
	}
}

// GetEventsInWindow returns events within a time window
func (hs *HotStorage) GetEventsInWindow(window events_correlation.TimeWindow) []events_correlation.Event {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	
	var result []events_correlation.Event
	for _, event := range hs.events {
		if window.Contains(event.Timestamp) {
			result = append(result, event)
		}
	}
	
	return result
}

// GetEventsOlderThan returns events older than the threshold
func (hs *HotStorage) GetEventsOlderThan(threshold time.Time) []events_correlation.Event {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	
	var result []events_correlation.Event
	var remaining []events_correlation.Event
	
	for _, event := range hs.events {
		if event.Timestamp.Before(threshold) {
			result = append(result, event)
		} else {
			remaining = append(remaining, event)
		}
	}
	
	hs.events = remaining
	return result
}

// Reset clears hot storage
func (hs *HotStorage) Reset() {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	
	hs.events = hs.events[:0]
}

// WarmStorage stores medium-age events with light compression
type WarmStorage struct {
	// Simplified implementation - in production would use actual compression
	events   []events_correlation.Event
	capacity int
	mu       sync.RWMutex
}

// NewWarmStorage creates a new warm storage
func NewWarmStorage(capacity int) *WarmStorage {
	return &WarmStorage{
		events:   make([]events_correlation.Event, 0, capacity),
		capacity: capacity,
	}
}

// Add adds an event to warm storage
func (ws *WarmStorage) Add(event events_correlation.Event) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	// TODO: Apply light compression
	ws.events = append(ws.events, event)
	
	if len(ws.events) > ws.capacity {
		copy(ws.events, ws.events[1:])
		ws.events = ws.events[:len(ws.events)-1]
	}
}

// GetEventsInWindow returns events within a time window
func (ws *WarmStorage) GetEventsInWindow(window events_correlation.TimeWindow) []events_correlation.Event {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	
	var result []events_correlation.Event
	for _, event := range ws.events {
		if window.Contains(event.Timestamp) {
			result = append(result, event)
		}
	}
	
	return result
}

// GetEventsOlderThan returns events older than the threshold
func (ws *WarmStorage) GetEventsOlderThan(threshold time.Time) []events_correlation.Event {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	var result []events_correlation.Event
	var remaining []events_correlation.Event
	
	for _, event := range ws.events {
		if event.Timestamp.Before(threshold) {
			result = append(result, event)
		} else {
			remaining = append(remaining, event)
		}
	}
	
	ws.events = remaining
	return result
}

// Reset clears warm storage
func (ws *WarmStorage) Reset() {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	ws.events = ws.events[:0]
}

// ColdStorage stores old events with heavy compression
type ColdStorage struct {
	// Simplified implementation - in production would use heavy compression
	events   []events_correlation.Event
	capacity int
	mu       sync.RWMutex
}

// NewColdStorage creates a new cold storage
func NewColdStorage(capacity int) *ColdStorage {
	return &ColdStorage{
		events:   make([]events_correlation.Event, 0, capacity),
		capacity: capacity,
	}
}

// Add adds an event to cold storage
func (cs *ColdStorage) Add(event events_correlation.Event) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	// TODO: Apply heavy compression
	cs.events = append(cs.events, event)
}

// GetEventsInWindow returns events within a time window
func (cs *ColdStorage) GetEventsInWindow(window events_correlation.TimeWindow) []events_correlation.Event {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	
	var result []events_correlation.Event
	for _, event := range cs.events {
		if window.Contains(event.Timestamp) {
			result = append(result, event)
		}
	}
	
	return result
}

// RemoveOldest removes the oldest events
func (cs *ColdStorage) RemoveOldest(count int) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	if count >= len(cs.events) {
		cs.events = cs.events[:0]
		return
	}
	
	copy(cs.events, cs.events[count:])
	cs.events = cs.events[:len(cs.events)-count]
}

// Reset clears cold storage
func (cs *ColdStorage) Reset() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	cs.events = cs.events[:0]
}

// TimeIndex provides fast time-based lookups
type TimeIndex struct {
	granularity int
	buckets     map[int64][]int // timestamp bucket -> event indices
	mu          sync.RWMutex
}

// NewTimeIndex creates a new time index
func NewTimeIndex(granularity int) *TimeIndex {
	return &TimeIndex{
		granularity: granularity,
		buckets:     make(map[int64][]int),
	}
}

// AddEvent adds an event to the time index
func (ti *TimeIndex) AddEvent(event events_correlation.Event) {
	bucket := event.Timestamp.Unix() / int64(ti.granularity)
	
	ti.mu.Lock()
	defer ti.mu.Unlock()
	
	// TODO: Store actual event indices
	ti.buckets[bucket] = append(ti.buckets[bucket], 0)
}

// Reset clears the time index
func (ti *TimeIndex) Reset() {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	
	ti.buckets = make(map[int64][]int)
}

// EntityIndex provides fast entity-based lookups
type EntityIndex struct {
	entities map[string][]events_correlation.Event
	mu       sync.RWMutex
}

// NewEntityIndex creates a new entity index
func NewEntityIndex() *EntityIndex {
	return &EntityIndex{
		entities: make(map[string][]events_correlation.Event),
	}
}

// AddEvent adds an event to the entity index
func (ei *EntityIndex) AddEvent(event events_correlation.Event) {
	ei.mu.Lock()
	defer ei.mu.Unlock()
	
	entityID := event.Entity.UID
	if entityID == "" {
		entityID = event.Entity.Namespace + "/" + event.Entity.Name
	}
	
	ei.entities[entityID] = append(ei.entities[entityID], event)
}

// GetEvents returns events for an entity
func (ei *EntityIndex) GetEvents(entityID string, limit int) []events_correlation.Event {
	ei.mu.RLock()
	defer ei.mu.RUnlock()
	
	events, exists := ei.entities[entityID]
	if !exists {
		return nil
	}
	
	if limit > 0 && len(events) > limit {
		return events[len(events)-limit:]
	}
	
	return events
}

// Reset clears the entity index
func (ei *EntityIndex) Reset() {
	ei.mu.Lock()
	defer ei.mu.Unlock()
	
	ei.entities = make(map[string][]events_correlation.Event)
}

// CompressEvents compresses a slice of events using gzip
func CompressEvents(events []events_correlation.Event) ([]byte, error) {
	// Simplified compression - in production would use custom binary format
	var buf []byte
	
	for _, event := range events {
		// Convert timestamp to binary
		timestampBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(timestampBytes, uint64(event.Timestamp.UnixNano()))
		buf = append(buf, timestampBytes...)
		
		// Add event type and entity info (simplified)
		buf = append(buf, []byte(event.Type)...)
		buf = append(buf, 0) // Null terminator
	}
	
	// Apply gzip compression
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	defer w.Close()
	
	_, err := w.Write(buf)
	if err != nil {
		return nil, err
	}
	
	err = w.Close()
	return compressed.Bytes(), err
}

// DecompressEvents decompresses events from gzip format
func DecompressEvents(data []byte) ([]events_correlation.Event, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	
	_, err = io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	
	// TODO: Implement actual decompression logic
	var events []events_correlation.Event
	return events, nil
}