package internal

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

// IPAMAnalytics provides advanced analytics for IP allocation/deallocation patterns
type IPAMAnalytics struct {
	config core.Config
	mu     sync.RWMutex
	logger Logger
	events chan<- domain.UnifiedEvent
	stopCh chan struct{}
	wg     sync.WaitGroup

	// IP allocation tracking
	allocations      map[string]*IPAllocation
	pools            map[string]*IPPoolAnalytics
	allocationTrends *AllocationTrends

	// Pattern detection
	patterns    *PatternDetector
	anomalies   []AnomalyRecord
	predictions *PredictionEngine
}

// IPAllocation tracks individual IP allocations
type IPAllocation struct {
	IP               string
	Pool             string
	Subnet           string
	PodName          string
	PodNamespace     string
	NodeName         string
	AllocatedAt      time.Time
	DeallocatedAt    *time.Time
	Duration         time.Duration
	CNIPlugin        string
	AllocationTime   time.Duration // Time taken to allocate
	DeallocationTime time.Duration // Time taken to deallocate
}

// IPPoolAnalytics tracks analytics for an IP pool
type IPPoolAnalytics struct {
	PoolName           string
	CIDR               string
	TotalIPs           int
	AllocatedIPs       int
	AvailableIPs       int
	ReservedIPs        int
	FragmentationScore float64
	AllocationRate     float64 // IPs per minute
	DeallocationRate   float64 // IPs per minute
	ChurnRate          float64 // Combined rate
	PeakUtilization    float64
	PeakTime           time.Time
	Allocations        []PoolAllocationEvent
}

// PoolAllocationEvent tracks allocation events in a pool
type PoolAllocationEvent struct {
	Timestamp   time.Time
	EventType   string // "allocate", "deallocate"
	IP          string
	Utilization float64
}

// AllocationTrends tracks allocation trends over time
type AllocationTrends struct {
	HourlyAllocations  map[int]int        // Hour of day -> allocation count
	DailyAllocations   map[string]int     // Date -> allocation count
	WeeklyPattern      []float64          // Average allocations per day of week
	PeakHours          []int              // Hours with highest allocation
	AllocationVelocity float64            // Rate of change in allocations
	PredictedDemand    map[string]float64 // Future demand predictions
}

// PatternDetector detects patterns in IP allocation
type PatternDetector struct {
	patterns []Pattern
}

// Pattern represents a detected allocation pattern
type Pattern struct {
	Type           string // "burst", "gradual", "cyclic", "leak"
	DetectedAt     time.Time
	Confidence     float64
	Description    string
	Impact         string
	Recommendation string
}

// AnomalyRecord tracks allocation anomalies
type AnomalyRecord struct {
	Timestamp   time.Time
	Type        string // "rapid_allocation", "leak", "fragmentation", "exhaustion"
	Severity    string
	Pool        string
	Description string
	Impact      string
	Resolved    bool
}

// PredictionEngine predicts future IP allocation needs
type PredictionEngine struct {
	predictions []Prediction
}

// Prediction represents a predicted future state
type Prediction struct {
	Timestamp            time.Time
	PredictedFor         time.Time
	Pool                 string
	PredictedUtilization float64
	Confidence           float64
	Recommendation       string
}

// NewIPAMAnalytics creates a new IPAM analytics engine
func NewIPAMAnalytics(config core.Config) (*IPAMAnalytics, error) {
	return &IPAMAnalytics{
		config:      config,
		logger:      &StandardLogger{},
		stopCh:      make(chan struct{}),
		allocations: make(map[string]*IPAllocation),
		pools:       make(map[string]*IPPoolAnalytics),
		allocationTrends: &AllocationTrends{
			HourlyAllocations: make(map[int]int),
			DailyAllocations:  make(map[string]int),
			WeeklyPattern:     make([]float64, 7),
			PredictedDemand:   make(map[string]float64),
		},
		patterns:    &PatternDetector{},
		predictions: &PredictionEngine{},
	}, nil
}

// Start begins IPAM analytics
func (a *IPAMAnalytics) Start(ctx context.Context, events chan<- domain.UnifiedEvent) error {
	a.events = events

	// Start analytics routines
	a.wg.Add(4)
	go a.trackAllocations(ctx)
	go a.analyzePatterns(ctx)
	go a.detectAnomalies(ctx)
	go a.generatePredictions(ctx)

	a.logger.Info("IPAM analytics started", nil)
	return nil
}

// Stop stops IPAM analytics
func (a *IPAMAnalytics) Stop() error {
	close(a.stopCh)
	a.wg.Wait()
	a.logger.Info("IPAM analytics stopped", nil)
	return nil
}

// ProcessIPAMEvent processes an IPAM-related CNI event
func (a *IPAMAnalytics) ProcessIPAMEvent(event core.CNIRawEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch event.Operation {
	case core.CNIOperationAdd:
		if event.AssignedIP != "" && event.Success {
			a.recordAllocation(event)
		}
	case core.CNIOperationDel:
		if event.AssignedIP != "" {
			a.recordDeallocation(event)
		}
	}

	// Update trends
	a.updateTrends(event)
}

// recordAllocation records an IP allocation
func (a *IPAMAnalytics) recordAllocation(event core.CNIRawEvent) {
	allocation := &IPAllocation{
		IP:             event.AssignedIP,
		Pool:           a.detectPool(event.AssignedIP, event.Subnet),
		Subnet:         event.Subnet,
		PodName:        event.PodName,
		PodNamespace:   event.PodNamespace,
		NodeName:       event.NodeName,
		AllocatedAt:    event.Timestamp,
		CNIPlugin:      event.PluginName,
		AllocationTime: event.Duration,
	}

	a.allocations[event.AssignedIP] = allocation

	// Update pool analytics
	poolKey := allocation.Pool
	pool, exists := a.pools[poolKey]
	if !exists {
		pool = a.initializePool(poolKey, event.Subnet)
		a.pools[poolKey] = pool
	}

	pool.AllocatedIPs++
	pool.AvailableIPs = pool.TotalIPs - pool.AllocatedIPs - pool.ReservedIPs

	utilization := float64(pool.AllocatedIPs) / float64(pool.TotalIPs) * 100
	pool.Allocations = append(pool.Allocations, PoolAllocationEvent{
		Timestamp:   event.Timestamp,
		EventType:   "allocate",
		IP:          event.AssignedIP,
		Utilization: utilization,
	})

	// Track peak utilization
	if utilization > pool.PeakUtilization {
		pool.PeakUtilization = utilization
		pool.PeakTime = event.Timestamp
	}

	// Calculate fragmentation
	pool.FragmentationScore = a.calculateFragmentation(pool)
}

// recordDeallocation records an IP deallocation
func (a *IPAMAnalytics) recordDeallocation(event core.CNIRawEvent) {
	allocation, exists := a.allocations[event.AssignedIP]
	if !exists {
		return
	}

	now := event.Timestamp
	allocation.DeallocatedAt = &now
	allocation.Duration = now.Sub(allocation.AllocatedAt)
	allocation.DeallocationTime = event.Duration

	// Update pool analytics
	if pool, exists := a.pools[allocation.Pool]; exists {
		pool.AllocatedIPs--
		pool.AvailableIPs = pool.TotalIPs - pool.AllocatedIPs - pool.ReservedIPs

		utilization := float64(pool.AllocatedIPs) / float64(pool.TotalIPs) * 100
		pool.Allocations = append(pool.Allocations, PoolAllocationEvent{
			Timestamp:   event.Timestamp,
			EventType:   "deallocate",
			IP:          event.AssignedIP,
			Utilization: utilization,
		})
	}
}

// updateTrends updates allocation trends
func (a *IPAMAnalytics) updateTrends(event core.CNIRawEvent) {
	if event.Operation != core.CNIOperationAdd || !event.Success {
		return
	}

	// Update hourly allocations
	hour := event.Timestamp.Hour()
	a.allocationTrends.HourlyAllocations[hour]++

	// Update daily allocations
	date := event.Timestamp.Format("2006-01-02")
	a.allocationTrends.DailyAllocations[date]++

	// Update weekly pattern
	dayOfWeek := int(event.Timestamp.Weekday())
	a.allocationTrends.WeeklyPattern[dayOfWeek]++
}

// trackAllocations continuously tracks allocation metrics
func (a *IPAMAnalytics) trackAllocations(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.calculateAllocationRates()
		}
	}
}

// calculateAllocationRates calculates allocation/deallocation rates
func (a *IPAMAnalytics) calculateAllocationRates() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	window := 5 * time.Minute

	for _, pool := range a.pools {
		allocations := 0
		deallocations := 0

		// Count recent events
		for _, event := range pool.Allocations {
			if now.Sub(event.Timestamp) <= window {
				switch event.EventType {
				case "allocate":
					allocations++
				case "deallocate":
					deallocations++
				}
			}
		}

		// Calculate rates (per minute)
		pool.AllocationRate = float64(allocations) / window.Minutes()
		pool.DeallocationRate = float64(deallocations) / window.Minutes()
		pool.ChurnRate = pool.AllocationRate + pool.DeallocationRate
	}
}

// analyzePatterns analyzes allocation patterns
func (a *IPAMAnalytics) analyzePatterns(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.detectPatterns()
		}
	}
}

// detectPatterns detects allocation patterns
func (a *IPAMAnalytics) detectPatterns() {
	a.mu.Lock()
	defer a.mu.Unlock()

	patterns := []Pattern{}

	// Detect burst pattern
	if burst := a.detectBurstPattern(); burst != nil {
		patterns = append(patterns, *burst)
	}

	// Detect leak pattern
	if leak := a.detectLeakPattern(); leak != nil {
		patterns = append(patterns, *leak)
	}

	// Detect cyclic pattern
	if cyclic := a.detectCyclicPattern(); cyclic != nil {
		patterns = append(patterns, *cyclic)
	}

	a.patterns.patterns = patterns

	// Emit pattern events
	for _, pattern := range patterns {
		a.emitPatternEvent(pattern)
	}
}

// detectBurstPattern detects burst allocation patterns
func (a *IPAMAnalytics) detectBurstPattern() *Pattern {
	// Check for rapid allocation rate increase
	for _, pool := range a.pools {
		if pool.AllocationRate > 10 { // More than 10 IPs per minute
			return &Pattern{
				Type:           "burst",
				DetectedAt:     time.Now(),
				Confidence:     0.8,
				Description:    fmt.Sprintf("Burst allocation detected in pool %s: %.2f IPs/min", pool.PoolName, pool.AllocationRate),
				Impact:         "Rapid IP consumption may lead to pool exhaustion",
				Recommendation: "Consider expanding IP pool or investigating cause of burst",
			}
		}
	}
	return nil
}

// detectLeakPattern detects IP leak patterns
func (a *IPAMAnalytics) detectLeakPattern() *Pattern {
	// Check for allocations without corresponding deallocations
	leakedIPs := 0
	for _, allocation := range a.allocations {
		if allocation.DeallocatedAt == nil && time.Since(allocation.AllocatedAt) > 24*time.Hour {
			leakedIPs++
		}
	}

	if leakedIPs > 10 {
		return &Pattern{
			Type:           "leak",
			DetectedAt:     time.Now(),
			Confidence:     0.9,
			Description:    fmt.Sprintf("IP leak detected: %d IPs allocated >24h without deallocation", leakedIPs),
			Impact:         "IP pool exhaustion over time",
			Recommendation: "Investigate pods not releasing IPs properly",
		}
	}
	return nil
}

// detectCyclicPattern detects cyclic allocation patterns
func (a *IPAMAnalytics) detectCyclicPattern() *Pattern {
	// Analyze hourly allocation patterns
	peakHours := []int{}
	avgAllocations := 0.0

	for hour, count := range a.allocationTrends.HourlyAllocations {
		avgAllocations += float64(count)
		if count > 0 {
			peakHours = append(peakHours, hour)
		}
	}
	avgAllocations /= 24

	// Check for regular patterns
	for hour, count := range a.allocationTrends.HourlyAllocations {
		if float64(count) > avgAllocations*2 {
			a.allocationTrends.PeakHours = append(a.allocationTrends.PeakHours, hour)
		}
	}

	if len(a.allocationTrends.PeakHours) > 0 {
		return &Pattern{
			Type:           "cyclic",
			DetectedAt:     time.Now(),
			Confidence:     0.7,
			Description:    fmt.Sprintf("Cyclic allocation pattern detected with peaks at hours: %v", a.allocationTrends.PeakHours),
			Impact:         "Predictable load patterns",
			Recommendation: "Pre-scale resources before peak hours",
		}
	}
	return nil
}

// detectAnomalies detects allocation anomalies
func (a *IPAMAnalytics) detectAnomalies(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.checkForAnomalies()
		}
	}
}

// checkForAnomalies checks for allocation anomalies
func (a *IPAMAnalytics) checkForAnomalies() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check for pool exhaustion
	for _, pool := range a.pools {
		utilization := float64(pool.AllocatedIPs) / float64(pool.TotalIPs) * 100

		if utilization > 90 {
			anomaly := AnomalyRecord{
				Timestamp:   time.Now(),
				Type:        "exhaustion",
				Severity:    "critical",
				Pool:        pool.PoolName,
				Description: fmt.Sprintf("IP pool near exhaustion: %.1f%% utilized", utilization),
				Impact:      "New pod deployments may fail",
				Resolved:    false,
			}
			a.anomalies = append(a.anomalies, anomaly)
			a.emitAnomalyEvent(anomaly)
		}

		// Check for high fragmentation
		if pool.FragmentationScore > 0.7 {
			anomaly := AnomalyRecord{
				Timestamp:   time.Now(),
				Type:        "fragmentation",
				Severity:    "warning",
				Pool:        pool.PoolName,
				Description: fmt.Sprintf("High IP fragmentation detected: score %.2f", pool.FragmentationScore),
				Impact:      "Inefficient IP utilization",
				Resolved:    false,
			}
			a.anomalies = append(a.anomalies, anomaly)
			a.emitAnomalyEvent(anomaly)
		}
	}
}

// generatePredictions generates future allocation predictions
func (a *IPAMAnalytics) generatePredictions(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.predictFutureAllocations()
		}
	}
}

// predictFutureAllocations predicts future IP allocations
func (a *IPAMAnalytics) predictFutureAllocations() {
	a.mu.Lock()
	defer a.mu.Unlock()

	predictions := []Prediction{}

	for poolName, pool := range a.pools {
		// Simple linear prediction based on allocation rate
		currentUtilization := float64(pool.AllocatedIPs) / float64(pool.TotalIPs) * 100
		predictedUtilization := currentUtilization + (pool.AllocationRate * 60 * 24) // Next 24 hours

		if predictedUtilization > 80 {
			prediction := Prediction{
				Timestamp:            time.Now(),
				PredictedFor:         time.Now().Add(24 * time.Hour),
				Pool:                 poolName,
				PredictedUtilization: predictedUtilization,
				Confidence:           0.7,
				Recommendation:       fmt.Sprintf("Pool %s predicted to reach %.1f%% utilization in 24h", poolName, predictedUtilization),
			}
			predictions = append(predictions, prediction)

			// Store in trends
			a.allocationTrends.PredictedDemand[poolName] = predictedUtilization
		}
	}

	a.predictions.predictions = predictions

	// Emit prediction events
	for _, prediction := range predictions {
		a.emitPredictionEvent(prediction)
	}
}

// Helper methods

func (a *IPAMAnalytics) detectPool(ip, subnet string) string {
	if subnet != "" {
		return subnet
	}
	// Default pool detection logic
	return "default-pool"
}

func (a *IPAMAnalytics) initializePool(poolName, cidr string) *IPPoolAnalytics {
	totalIPs := 0
	if cidr != "" {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			ones, bits := network.Mask.Size()
			totalIPs = 1 << (bits - ones)
			// Subtract network and broadcast addresses
			if totalIPs > 2 {
				totalIPs -= 2
			}
		}
	}

	return &IPPoolAnalytics{
		PoolName:     poolName,
		CIDR:         cidr,
		TotalIPs:     totalIPs,
		AllocatedIPs: 0,
		AvailableIPs: totalIPs,
		ReservedIPs:  0,
		Allocations:  []PoolAllocationEvent{},
	}
}

func (a *IPAMAnalytics) calculateFragmentation(pool *IPPoolAnalytics) float64 {
	// Simple fragmentation score based on allocation pattern
	// In a real implementation, would analyze IP range continuity
	if pool.AllocatedIPs == 0 || pool.TotalIPs == 0 {
		return 0.0
	}

	// Higher churn rate indicates more fragmentation
	fragmentationScore := pool.ChurnRate / 10.0
	if fragmentationScore > 1.0 {
		fragmentationScore = 1.0
	}

	return fragmentationScore
}

// Event emission methods

func (a *IPAMAnalytics) emitPatternEvent(pattern Pattern) {
	if a.events == nil {
		return
	}

	severity := domain.EventSeverityInfo
	if pattern.Type == "leak" || pattern.Type == "burst" {
		severity = domain.EventSeverityWarning
	}

	event := domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      domain.EventType(fmt.Sprintf("cni.ipam.pattern.%s", pattern.Type)),
		Source:    "cni-ipam-analytics",
		Category:  "cni",
		Severity:  severity,
		Message:   pattern.Description,
		Semantic: &domain.SemanticContext{
			Intent:   "ipam-pattern-detection",
			Category: "resource-management",
			Tags:     []string{"ipam", "pattern", pattern.Type},
			Narrative: fmt.Sprintf("%s Impact: %s. Recommendation: %s",
				pattern.Description, pattern.Impact, pattern.Recommendation),
		},
	}

	select {
	case a.events <- event:
	default:
		a.logger.Warn("Event channel full, dropping pattern event", nil)
	}
}

func (a *IPAMAnalytics) emitAnomalyEvent(anomaly AnomalyRecord) {
	if a.events == nil {
		return
	}

	severity := domain.EventSeverityWarning
	if anomaly.Severity == "critical" {
		severity = domain.EventSeverityCritical
	}

	event := domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: anomaly.Timestamp,
		Type:      domain.EventType(fmt.Sprintf("cni.ipam.anomaly.%s", anomaly.Type)),
		Source:    "cni-ipam-analytics",
		Category:  "cni",
		Severity:  severity,
		Message:   anomaly.Description,
		Semantic: &domain.SemanticContext{
			Intent:    "ipam-anomaly-detection",
			Category:  "resource-management",
			Tags:      []string{"ipam", "anomaly", anomaly.Type, anomaly.Pool},
			Narrative: fmt.Sprintf("%s Impact: %s", anomaly.Description, anomaly.Impact),
		},
	}

	select {
	case a.events <- event:
	default:
		a.logger.Warn("Event channel full, dropping anomaly event", nil)
	}
}

func (a *IPAMAnalytics) emitPredictionEvent(prediction Prediction) {
	if a.events == nil {
		return
	}

	event := domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: prediction.Timestamp,
		Type:      domain.EventType("cni.ipam.prediction"),
		Source:    "cni-ipam-analytics",
		Category:  "cni",
		Severity:  domain.EventSeverityInfo,
		Message:   prediction.Recommendation,
		Semantic: &domain.SemanticContext{
			Intent:   "ipam-prediction",
			Category: "resource-management",
			Tags:     []string{"ipam", "prediction", prediction.Pool},
			Narrative: fmt.Sprintf("Prediction for %s: %.1f%% utilization expected by %s (confidence: %.1f%%)",
				prediction.Pool, prediction.PredictedUtilization,
				prediction.PredictedFor.Format("2006-01-02 15:04"),
				prediction.Confidence*100),
		},
	}

	select {
	case a.events <- event:
	default:
		a.logger.Warn("Event channel full, dropping prediction event", nil)
	}
}

// GetAnalytics returns current IPAM analytics
func (a *IPAMAnalytics) GetAnalytics() *IPAMAnalyticsReport {
	a.mu.RLock()
	defer a.mu.RUnlock()

	report := &IPAMAnalyticsReport{
		Timestamp:         time.Now(),
		TotalAllocations:  len(a.allocations),
		ActiveAllocations: 0,
		Pools:             make(map[string]PoolSummary),
		Patterns:          a.patterns.patterns,
		RecentAnomalies:   []AnomalyRecord{},
		Predictions:       a.predictions.predictions,
		Trends:            a.allocationTrends,
	}

	// Count active allocations
	for _, allocation := range a.allocations {
		if allocation.DeallocatedAt == nil {
			report.ActiveAllocations++
		}
	}

	// Summarize pools
	for name, pool := range a.pools {
		report.Pools[name] = PoolSummary{
			Name:               pool.PoolName,
			CIDR:               pool.CIDR,
			Utilization:        float64(pool.AllocatedIPs) / float64(pool.TotalIPs) * 100,
			AllocatedIPs:       pool.AllocatedIPs,
			AvailableIPs:       pool.AvailableIPs,
			FragmentationScore: pool.FragmentationScore,
			AllocationRate:     pool.AllocationRate,
			ChurnRate:          pool.ChurnRate,
		}
	}

	// Get recent anomalies
	cutoff := time.Now().Add(-1 * time.Hour)
	for _, anomaly := range a.anomalies {
		if anomaly.Timestamp.After(cutoff) {
			report.RecentAnomalies = append(report.RecentAnomalies, anomaly)
		}
	}

	return report
}

// Report structures

// IPAMAnalyticsReport provides a comprehensive IPAM analytics report
type IPAMAnalyticsReport struct {
	Timestamp         time.Time
	TotalAllocations  int
	ActiveAllocations int
	Pools             map[string]PoolSummary
	Patterns          []Pattern
	RecentAnomalies   []AnomalyRecord
	Predictions       []Prediction
	Trends            *AllocationTrends
}

// PoolSummary provides a summary of pool statistics
type PoolSummary struct {
	Name               string
	CIDR               string
	Utilization        float64
	AllocatedIPs       int
	AvailableIPs       int
	FragmentationScore float64
	AllocationRate     float64
	ChurnRate          float64
}
