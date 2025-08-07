package analysis

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
	"go.uber.org/zap"
)

// CorrelationData is the minimal interface for correlation input
// This is what we need from correlation package without creating dependency
type CorrelationData struct {
	// Identity
	ID     string `json:"id"`
	Source string `json:"source"` // which correlator

	// What happened
	EventIDs []string `json:"event_ids"` // events involved
	Type     string   `json:"type"`      // k8s_ownership, temporal, etc

	// Quality signals
	Confidence float64  `json:"confidence"` // correlator's confidence
	Evidence   []string `json:"evidence"`   // why correlator thinks this

	// Timing
	TimeWindow time.Duration `json:"time_window"` // how long this took
	Timestamp  time.Time     `json:"timestamp"`   // when detected

	// The story
	Summary     string `json:"summary"`                 // what correlator found
	RootEventID string `json:"root_event_id,omitempty"` // suspected root cause event
}

// Engine is the Smart Brain that analyzes correlations
type Engine struct {
	logger *zap.Logger

	// Pattern detection
	patternMatcher *PatternMatcher

	// Confidence scoring
	scorer *ConfidenceScorer

	// Historical data for pattern matching
	historyStore HistoryStore

	// Configuration
	config Config
}

// Config for the analysis engine
type Config struct {
	// Time window for aggregating correlations
	AggregationWindow time.Duration

	// Minimum confidence threshold
	MinConfidence float64

	// Pattern matching
	EnablePatternDetection bool
	EnablePrediction       bool

	// Scoring weights
	CorrelatorAgreementWeight float64
	EvidenceStrengthWeight    float64
	PatternMatchWeight        float64
	TemporalProximityWeight   float64
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		AggregationWindow:         5 * time.Minute,
		MinConfidence:             0.3,
		EnablePatternDetection:    true,
		EnablePrediction:          true,
		CorrelatorAgreementWeight: 0.3,
		EvidenceStrengthWeight:    0.3,
		PatternMatchWeight:        0.2,
		TemporalProximityWeight:   0.2,
	}
}

// NewEngine creates the Smart Brain
func NewEngine(logger *zap.Logger, config Config) *Engine {
	return &Engine{
		logger:         logger,
		patternMatcher: NewPatternMatcher(logger),
		scorer:         NewConfidenceScorer(config),
		historyStore:   NewMemoryHistoryStore(), // Simple in-memory for now
		config:         config,
	}
}

// Analyze takes correlations and produces actionable intelligence
func (e *Engine) Analyze(ctx context.Context, correlations []CorrelationData) (*AnalysisReport, error) {
	if len(correlations) == 0 {
		return &AnalysisReport{
			ID:        generateID(),
			Timestamp: time.Now(),
			Summary:   "No correlations to analyze",
		}, nil
	}

	startTime := time.Now()

	// Step 1: Aggregate correlations by relationship
	aggregated := e.aggregateCorrelations(correlations)

	// Step 2: Score and rank findings
	findings := e.createFindings(aggregated)

	// Step 3: Detect patterns
	patterns := e.detectPatterns(correlations, findings)

	// Step 4: Generate insights
	insights := e.generateInsights(findings, patterns)

	// Step 5: Create recommendations
	recommendations := e.generateRecommendations(findings, insights)

	// Step 6: Calculate overall confidence
	overallConfidence := e.calculateOverallConfidence(findings)

	// Step 7: Build quality metrics
	quality := e.assessQuality(correlations, findings, patterns)

	return &AnalysisReport{
		ID:                generateID(),
		Timestamp:         time.Now(),
		TimeWindow:        e.config.AggregationWindow,
		Findings:          findings,
		Patterns:          patterns,
		Insights:          insights,
		Recommendations:   recommendations,
		Summary:           e.generateSummary(findings, insights),
		OverallConfidence: overallConfidence,
		Quality:           quality,
		Statistics: AnalysisStats{
			EventsAnalyzed:    e.countUniqueEvents(correlations),
			CorrelationsFound: len(correlations),
			PatternsDetected:  len(patterns),
			ProcessingTime:    time.Since(startTime),
			CorrelatorsUsed:   e.getUniqueCorrelators(correlations),
		},
	}, nil
}

// aggregateCorrelations groups related correlations together
func (e *Engine) aggregateCorrelations(correlations []CorrelationData) map[string][]CorrelationData {
	aggregated := make(map[string][]CorrelationData)

	for _, corr := range correlations {
		// Group by overlapping events or root cause
		key := e.findAggregationKey(corr, aggregated)
		if key == "" {
			// New group
			key = corr.ID
		}
		aggregated[key] = append(aggregated[key], corr)
	}

	return aggregated
}

// findAggregationKey finds if this correlation belongs to an existing group
func (e *Engine) findAggregationKey(corr CorrelationData, existing map[string][]CorrelationData) string {
	for key, group := range existing {
		for _, g := range group {
			// Check for event overlap
			if e.hasEventOverlap(corr.EventIDs, g.EventIDs) {
				return key
			}
			// Check for same root cause
			if corr.RootEventID != "" && corr.RootEventID == g.RootEventID {
				return key
			}
		}
	}
	return ""
}

// hasEventOverlap checks if two event lists share common events
func (e *Engine) hasEventOverlap(events1, events2 []string) bool {
	eventMap := make(map[string]bool)
	for _, e := range events1 {
		eventMap[e] = true
	}
	for _, e := range events2 {
		if eventMap[e] {
			return true
		}
	}
	return false
}

// createFindings converts aggregated correlations into findings
func (e *Engine) createFindings(aggregated map[string][]CorrelationData) []Finding {
	var findings []Finding

	for _, group := range aggregated {
		if len(group) == 0 {
			continue
		}

		finding := Finding{
			ID:             generateID(),
			Type:           e.determineFindingType(group),
			Severity:       e.calculateSeverity(group),
			Confidence:     e.scorer.ScoreGroup(group),
			Title:          e.generateTitle(group),
			Summary:        e.generateFindingSummary(group),
			Evidence:       e.extractEvidence(group),
			FirstSeen:      e.getEarliestTime(group),
			LastSeen:       e.getLatestTime(group),
			EventCount:     e.countUniqueEventsInGroup(group),
			Sources:        e.getSourcesFromGroup(group),
			CorrelationIDs: e.getCorrelationIDs(group),
		}

		// Identify root cause if correlators agree
		if rootCause := e.identifyRootCause(group); rootCause != nil {
			finding.RootCause = rootCause
		}

		// Calculate impacts
		finding.Impacts = e.calculateImpacts(group)

		findings = append(findings, finding)
	}

	// Sort by confidence and severity
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Confidence == findings[j].Confidence {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].Confidence > findings[j].Confidence
	})

	return findings
}

// determineFindingType determines the type based on correlation types
func (e *Engine) determineFindingType(group []CorrelationData) FindingType {
	typeCount := make(map[string]int)
	for _, corr := range group {
		switch {
		case strings.Contains(corr.Type, "performance"):
			typeCount["performance"]++
		case strings.Contains(corr.Type, "config"):
			typeCount["configuration"]++
		case strings.Contains(corr.Type, "security"):
			typeCount["security"]++
		case strings.Contains(corr.Type, "capacity"):
			typeCount["capacity"]++
		default:
			typeCount["incident"]++
		}
	}

	// Return most common type
	maxCount := 0
	result := FindingTypeIncident
	for typ, count := range typeCount {
		if count > maxCount {
			maxCount = count
			switch typ {
			case "performance":
				result = FindingTypePerformance
			case "configuration":
				result = FindingTypeConfiguration
			case "security":
				result = FindingTypeSecurity
			case "capacity":
				result = FindingTypeCapacity
			default:
				result = FindingTypeIncident
			}
		}
	}

	return result
}

// calculateSeverity determines severity based on evidence
func (e *Engine) calculateSeverity(group []CorrelationData) domain.EventSeverity {
	// If any correlation indicates critical, use that
	for _, corr := range group {
		if strings.Contains(strings.ToLower(corr.Summary), "critical") ||
			strings.Contains(strings.ToLower(corr.Summary), "failure") ||
			strings.Contains(strings.ToLower(corr.Summary), "down") {
			return domain.EventSeverity("critical")
		}
	}

	// High severity if multiple correlators agree
	if len(group) >= 3 {
		return domain.EventSeverity("high")
	}

	// Medium if confidence is high
	avgConfidence := 0.0
	for _, corr := range group {
		avgConfidence += corr.Confidence
	}
	avgConfidence /= float64(len(group))

	if avgConfidence > 0.7 {
		return domain.EventSeverity("high")
	} else if avgConfidence > 0.5 {
		return domain.EventSeverity("medium")
	}

	return domain.EventSeverity("low")
}

// generateTitle creates a human-readable title
func (e *Engine) generateTitle(group []CorrelationData) string {
	if len(group) == 0 {
		return "Unknown Issue"
	}

	// Use the highest confidence correlation's summary as base
	best := group[0]
	for _, corr := range group {
		if corr.Confidence > best.Confidence {
			best = corr
		}
	}

	// Clean up and shorten
	title := best.Summary
	if len(title) > 100 {
		title = title[:97] + "..."
	}

	return title
}

// identifyRootCause finds root cause if correlators agree
func (e *Engine) identifyRootCause(group []CorrelationData) *RootCause {
	rootCauses := make(map[string]int)
	evidenceMap := make(map[string][]Evidence)

	for _, corr := range group {
		if corr.RootEventID != "" {
			rootCauses[corr.RootEventID]++
			// Convert string evidence to Evidence type
			for _, ev := range corr.Evidence {
				evidenceMap[corr.RootEventID] = append(evidenceMap[corr.RootEventID], Evidence{
					Type:        EvidenceTypeCorrelated,
					Source:      corr.Source,
					Description: ev,
					Confidence:  corr.Confidence,
					Timestamp:   corr.Timestamp,
				})
			}
		}
	}

	// Find most agreed upon root cause
	var bestRoot string
	maxAgreement := 0
	for root, count := range rootCauses {
		if count > maxAgreement {
			maxAgreement = count
			bestRoot = root
		}
	}

	if bestRoot == "" {
		return nil
	}

	// Calculate confidence based on agreement
	confidence := float64(maxAgreement) / float64(len(group))

	return &RootCause{
		EventID:     bestRoot,
		Type:        "correlation_agreement",
		Description: fmt.Sprintf("Identified by %d correlators", maxAgreement),
		Confidence:  confidence,
		Evidence:    evidenceMap[bestRoot],
	}
}

// detectPatterns looks for known patterns in correlations
func (e *Engine) detectPatterns(correlations []CorrelationData, findings []Finding) []Pattern {
	if !e.config.EnablePatternDetection {
		return nil
	}

	return e.patternMatcher.DetectPatterns(correlations, findings)
}

// generateInsights creates human-readable insights
func (e *Engine) generateInsights(findings []Finding, patterns []Pattern) []Insight {
	var insights []Insight

	// Insight from high-confidence findings
	for _, finding := range findings {
		if finding.Confidence > 0.8 {
			insight := Insight{
				ID:          generateID(),
				Type:        InsightTypeAnomaly,
				Priority:    e.mapSeverityToPriority(finding.Severity),
				Title:       fmt.Sprintf("High confidence issue: %s", finding.Title),
				Description: finding.Summary,
				Explanation: e.explainWhy(finding),
				Evidence:    e.extractInsightEvidence(finding),
				Confidence:  finding.Confidence,
				GeneratedAt: time.Now(),
			}
			insights = append(insights, insight)
		}
	}

	// Insights from patterns
	for _, pattern := range patterns {
		insight := Insight{
			ID:          generateID(),
			Type:        InsightTypeTrend,
			Priority:    e.determinePatternPriority(pattern),
			Title:       fmt.Sprintf("Pattern detected: %s", pattern.Name),
			Description: pattern.Description,
			Explanation: fmt.Sprintf("This pattern has occurred %d times", pattern.Occurrences),
			Evidence:    pattern.Signature,
			Confidence:  pattern.Confidence,
			GeneratedAt: time.Now(),
		}
		insights = append(insights, insight)
	}

	return insights
}

// generateRecommendations creates actionable recommendations
func (e *Engine) generateRecommendations(findings []Finding, insights []Insight) []Recommendation {
	var recommendations []Recommendation

	for _, finding := range findings {
		// Only recommend for high confidence findings
		if finding.Confidence < 0.6 {
			continue
		}

		rec := e.createRecommendation(finding)
		if rec != nil {
			recommendations = append(recommendations, *rec)
		}
	}

	// Sort by priority
	sort.Slice(recommendations, func(i, j int) bool {
		return priorityValue(recommendations[i].Priority) > priorityValue(recommendations[j].Priority)
	})

	return recommendations
}

// createRecommendation generates a recommendation for a finding
func (e *Engine) createRecommendation(finding Finding) *Recommendation {
	switch finding.Type {
	case FindingTypePerformance:
		return e.createPerformanceRecommendation(finding)
	case FindingTypeConfiguration:
		return e.createConfigRecommendation(finding)
	case FindingTypeCapacity:
		return e.createCapacityRecommendation(finding)
	case FindingTypeSecurity:
		return e.createSecurityRecommendation(finding)
	default:
		return e.createGenericRecommendation(finding)
	}
}

// Helper functions

func (e *Engine) generateSummary(findings []Finding, insights []Insight) string {
	if len(findings) == 0 {
		return "No significant issues detected"
	}

	critical := 0
	high := 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		}
	}

	if critical > 0 {
		return fmt.Sprintf("CRITICAL: %d critical issues detected requiring immediate attention", critical)
	}
	if high > 0 {
		return fmt.Sprintf("Found %d high-priority issues that should be addressed", high)
	}

	return fmt.Sprintf("Analysis complete: %d findings, %d insights generated", len(findings), len(insights))
}

func (e *Engine) calculateOverallConfidence(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0
	}

	total := 0.0
	for _, f := range findings {
		total += f.Confidence
	}

	return total / float64(len(findings))
}

func (e *Engine) countUniqueEvents(correlations []CorrelationData) int {
	events := make(map[string]bool)
	for _, corr := range correlations {
		for _, event := range corr.EventIDs {
			events[event] = true
		}
	}
	return len(events)
}

func (e *Engine) getUniqueCorrelators(correlations []CorrelationData) []string {
	sources := make(map[string]bool)
	for _, corr := range correlations {
		sources[corr.Source] = true
	}

	result := make([]string, 0, len(sources))
	for source := range sources {
		result = append(result, source)
	}

	return result
}

func generateID() string {
	return fmt.Sprintf("analysis-%d", time.Now().UnixNano())
}

func priorityValue(p Priority) int {
	switch p {
	case PriorityCritical:
		return 4
	case PriorityHigh:
		return 3
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}

// Stub methods for now - these would be fully implemented

func (e *Engine) generateFindingSummary(group []CorrelationData) string {
	return group[0].Summary
}

func (e *Engine) extractEvidence(group []CorrelationData) []Evidence {
	var evidence []Evidence
	for _, corr := range group {
		for _, ev := range corr.Evidence {
			evidence = append(evidence, Evidence{
				Type:        EvidenceTypeCorrelated,
				Source:      corr.Source,
				Description: ev,
				Confidence:  corr.Confidence,
				Timestamp:   corr.Timestamp,
			})
		}
	}
	return evidence
}

func (e *Engine) calculateImpacts(group []CorrelationData) []Impact {
	// Would analyze events to determine actual impacts
	return []Impact{}
}

func (e *Engine) assessQuality(correlations []CorrelationData, findings []Finding, patterns []Pattern) QualityMetrics {
	return QualityMetrics{
		DataCompleteness:    0.8,
		EvidenceStrength:    0.7,
		CorrelatorAgreement: 0.6,
		PatternClarity:      0.5,
	}
}

func (e *Engine) getEarliestTime(group []CorrelationData) time.Time {
	earliest := group[0].Timestamp
	for _, corr := range group {
		if corr.Timestamp.Before(earliest) {
			earliest = corr.Timestamp
		}
	}
	return earliest
}

func (e *Engine) getLatestTime(group []CorrelationData) time.Time {
	latest := group[0].Timestamp
	for _, corr := range group {
		if corr.Timestamp.After(latest) {
			latest = corr.Timestamp
		}
	}
	return latest
}

func (e *Engine) countUniqueEventsInGroup(group []CorrelationData) int {
	events := make(map[string]bool)
	for _, corr := range group {
		for _, event := range corr.EventIDs {
			events[event] = true
		}
	}
	return len(events)
}

func (e *Engine) getSourcesFromGroup(group []CorrelationData) []string {
	sources := make(map[string]bool)
	for _, corr := range group {
		sources[corr.Source] = true
	}
	result := make([]string, 0, len(sources))
	for source := range sources {
		result = append(result, source)
	}
	return result
}

func (e *Engine) getCorrelationIDs(group []CorrelationData) []string {
	ids := make([]string, len(group))
	for i, corr := range group {
		ids[i] = corr.ID
	}
	return ids
}

func (e *Engine) explainWhy(finding Finding) string {
	return fmt.Sprintf("Based on %d correlations with %.0f%% confidence",
		len(finding.CorrelationIDs), finding.Confidence*100)
}

func (e *Engine) extractInsightEvidence(finding Finding) []string {
	evidence := make([]string, 0, len(finding.Evidence))
	for _, ev := range finding.Evidence {
		evidence = append(evidence, ev.Description)
	}
	return evidence
}

func (e *Engine) mapSeverityToPriority(severity domain.EventSeverity) Priority {
	switch severity {
	case "critical":
		return PriorityCritical
	case "high":
		return PriorityHigh
	case "medium":
		return PriorityMedium
	default:
		return PriorityLow
	}
}

func (e *Engine) determinePatternPriority(pattern Pattern) Priority {
	if pattern.Confidence > 0.8 && pattern.Occurrences > 5 {
		return PriorityHigh
	}
	if pattern.Confidence > 0.6 {
		return PriorityMedium
	}
	return PriorityLow
}

// Recommendation creators

func (e *Engine) createPerformanceRecommendation(finding Finding) *Recommendation {
	return &Recommendation{
		ID:          generateID(),
		Type:        ActionTypeOptimize,
		Priority:    e.mapSeverityToPriority(finding.Severity),
		Title:       "Optimize Performance",
		Description: "Performance degradation detected",
		Rationale:   "Improving performance will reduce latency and improve user experience",
		Impact:      "Reduced response times and improved throughput",
		Steps: []string{
			"Review resource utilization metrics",
			"Identify bottlenecks",
			"Scale resources if needed",
		},
		Confidence: finding.Confidence,
	}
}

func (e *Engine) createConfigRecommendation(finding Finding) *Recommendation {
	return &Recommendation{
		ID:          generateID(),
		Type:        ActionTypeRemediate,
		Priority:    PriorityHigh,
		Title:       "Review Configuration Change",
		Description: "Recent configuration change may have caused issues",
		Rationale:   "Configuration changes are a common source of incidents",
		Impact:      "Restore service stability",
		Steps: []string{
			"Review recent configuration changes",
			"Consider rolling back if issue persists",
			"Validate configuration syntax and values",
		},
		Confidence: finding.Confidence,
	}
}

func (e *Engine) createCapacityRecommendation(finding Finding) *Recommendation {
	return &Recommendation{
		ID:          generateID(),
		Type:        ActionTypeMitigate,
		Priority:    PriorityMedium,
		Title:       "Scale Resources",
		Description: "Capacity limits are being reached",
		Rationale:   "Preventing capacity issues before they cause outages",
		Impact:      "Improved availability and performance",
		Steps: []string{
			"Review current resource utilization",
			"Scale up pods or nodes",
			"Consider autoscaling policies",
		},
		Confidence: finding.Confidence,
	}
}

func (e *Engine) createSecurityRecommendation(finding Finding) *Recommendation {
	return &Recommendation{
		ID:          generateID(),
		Type:        ActionTypeInvestigate,
		Priority:    PriorityCritical,
		Title:       "Security Investigation Required",
		Description: "Potential security issue detected",
		Rationale:   "Security issues require immediate investigation",
		Impact:      "Prevent potential security breach",
		Steps: []string{
			"Review security logs",
			"Check for unauthorized access",
			"Apply security patches if needed",
		},
		Confidence: finding.Confidence,
	}
}

func (e *Engine) createGenericRecommendation(finding Finding) *Recommendation {
	return &Recommendation{
		ID:          generateID(),
		Type:        ActionTypeInvestigate,
		Priority:    e.mapSeverityToPriority(finding.Severity),
		Title:       "Investigate Issue",
		Description: finding.Title,
		Rationale:   "Issue requires investigation to determine root cause",
		Impact:      "Resolve underlying issue",
		Steps: []string{
			"Review correlations and evidence",
			"Check system logs",
			"Monitor for recurrence",
		},
		Confidence: finding.Confidence,
	}
}
