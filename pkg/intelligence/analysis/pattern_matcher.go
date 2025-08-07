package analysis

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// PatternMatcher detects patterns in correlations and findings
type PatternMatcher struct {
	logger *zap.Logger

	// Known patterns
	patterns []PatternDefinition
}

// PatternDefinition defines a pattern to match
type PatternDefinition struct {
	Type        PatternType
	Name        string
	Description string
	Matcher     PatternMatchFunc
}

// PatternMatchFunc checks if correlations match a pattern
type PatternMatchFunc func(correlations []CorrelationData, findings []Finding) (*Pattern, bool)

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher(logger *zap.Logger) *PatternMatcher {
	pm := &PatternMatcher{
		logger: logger,
	}

	// Register known patterns
	pm.registerPatterns()

	return pm
}

// registerPatterns sets up known patterns
func (pm *PatternMatcher) registerPatterns() {
	pm.patterns = []PatternDefinition{
		{
			Type:        PatternTypeCascading,
			Name:        "Cascading Failure",
			Description: "A failure in one component triggers failures in dependent components",
			Matcher:     pm.detectCascadingFailure,
		},
		{
			Type:        PatternTypePeriodic,
			Name:        "Periodic Issue",
			Description: "Issue that occurs at regular intervals",
			Matcher:     pm.detectPeriodicPattern,
		},
		{
			Type:        PatternTypeProgressive,
			Name:        "Progressive Degradation",
			Description: "Performance gradually worsening over time",
			Matcher:     pm.detectProgressiveDegradation,
		},
		{
			Type:        PatternTypeCorrelated,
			Name:        "Correlated Events",
			Description: "Events that consistently occur together",
			Matcher:     pm.detectCorrelatedEvents,
		},
		{
			Type:        PatternTypeSequential,
			Name:        "Sequential Pattern",
			Description: "Events that occur in a specific sequence",
			Matcher:     pm.detectSequentialPattern,
		},
	}
}

// DetectPatterns finds patterns in correlations
func (pm *PatternMatcher) DetectPatterns(correlations []CorrelationData, findings []Finding) []Pattern {
	var patterns []Pattern

	for _, def := range pm.patterns {
		if pattern, matched := def.Matcher(correlations, findings); matched {
			patterns = append(patterns, *pattern)
		}
	}

	return patterns
}

// detectCascadingFailure looks for cascading failures
func (pm *PatternMatcher) detectCascadingFailure(correlations []CorrelationData, findings []Finding) (*Pattern, bool) {
	// Look for multiple failures in quick succession
	failureCount := 0
	var firstFailure, lastFailure time.Time
	signature := []string{}

	for _, corr := range correlations {
		if strings.Contains(strings.ToLower(corr.Summary), "fail") ||
			strings.Contains(strings.ToLower(corr.Summary), "error") ||
			strings.Contains(strings.ToLower(corr.Summary), "crash") {
			failureCount++

			if firstFailure.IsZero() || corr.Timestamp.Before(firstFailure) {
				firstFailure = corr.Timestamp
			}
			if lastFailure.IsZero() || corr.Timestamp.After(lastFailure) {
				lastFailure = corr.Timestamp
			}

			signature = append(signature, fmt.Sprintf("%s: %s", corr.Source, corr.Summary))
		}
	}

	// Need at least 3 failures within 5 minutes
	if failureCount >= 3 && lastFailure.Sub(firstFailure) <= 5*time.Minute {
		return &Pattern{
			ID:          generatePatternID(),
			Type:        PatternTypeCascading,
			Name:        "Cascading Failure",
			Description: fmt.Sprintf("%d failures detected within %v", failureCount, lastFailure.Sub(firstFailure)),
			Confidence:  calculateCascadeConfidence(failureCount, lastFailure.Sub(firstFailure)),
			Occurrences: failureCount,
			FirstSeen:   firstFailure,
			LastSeen:    lastFailure,
			Signature:   signature,
		}, true
	}

	return nil, false
}

// detectPeriodicPattern looks for issues that repeat at intervals
func (pm *PatternMatcher) detectPeriodicPattern(correlations []CorrelationData, findings []Finding) (*Pattern, bool) {
	// Group correlations by type
	typeGroups := make(map[string][]time.Time)

	for _, corr := range correlations {
		typeGroups[corr.Type] = append(typeGroups[corr.Type], corr.Timestamp)
	}

	// Check each type for periodic behavior
	for corrType, timestamps := range typeGroups {
		if len(timestamps) < 3 {
			continue
		}

		// Calculate intervals
		intervals := []time.Duration{}
		for i := 1; i < len(timestamps); i++ {
			intervals = append(intervals, timestamps[i].Sub(timestamps[i-1]))
		}

		// Check if intervals are consistent (within 20% variance)
		if isPeriodicPattern(intervals) {
			avgInterval := averageDuration(intervals)
			return &Pattern{
				ID:          generatePatternID(),
				Type:        PatternTypePeriodic,
				Name:        "Periodic Pattern",
				Description: fmt.Sprintf("%s occurring every %v", corrType, avgInterval),
				Confidence:  0.7,
				Occurrences: len(timestamps),
				FirstSeen:   timestamps[0],
				LastSeen:    timestamps[len(timestamps)-1],
				Signature:   []string{fmt.Sprintf("Interval: %v", avgInterval)},
			}, true
		}
	}

	return nil, false
}

// detectProgressiveDegradation looks for gradually worsening metrics
func (pm *PatternMatcher) detectProgressiveDegradation(correlations []CorrelationData, findings []Finding) (*Pattern, bool) {
	// Look for performance-related correlations with decreasing confidence or increasing severity
	performanceCorrs := []CorrelationData{}

	for _, corr := range correlations {
		if strings.Contains(corr.Type, "performance") ||
			strings.Contains(strings.ToLower(corr.Summary), "slow") ||
			strings.Contains(strings.ToLower(corr.Summary), "latency") ||
			strings.Contains(strings.ToLower(corr.Summary), "memory") {
			performanceCorrs = append(performanceCorrs, corr)
		}
	}

	if len(performanceCorrs) < 3 {
		return nil, false
	}

	// Check if severity is increasing over time
	severityIncreasing := false
	for i := 1; i < len(findings); i++ {
		if findings[i].Severity > findings[i-1].Severity {
			severityIncreasing = true
			break
		}
	}

	if severityIncreasing || len(performanceCorrs) >= 3 {
		return &Pattern{
			ID:          generatePatternID(),
			Type:        PatternTypeProgressive,
			Name:        "Progressive Degradation",
			Description: fmt.Sprintf("Performance degrading over %d observations", len(performanceCorrs)),
			Confidence:  0.6,
			Occurrences: len(performanceCorrs),
			FirstSeen:   performanceCorrs[0].Timestamp,
			LastSeen:    performanceCorrs[len(performanceCorrs)-1].Timestamp,
			Signature:   []string{"Performance metrics worsening"},
		}, true
	}

	return nil, false
}

// detectCorrelatedEvents looks for events that occur together
func (pm *PatternMatcher) detectCorrelatedEvents(correlations []CorrelationData, findings []Finding) (*Pattern, bool) {
	// Find events that appear together frequently
	eventPairs := make(map[string]int)

	for i := 0; i < len(correlations); i++ {
		for j := i + 1; j < len(correlations); j++ {
			// Check if correlations are within 1 minute of each other
			if absDuration(correlations[i].Timestamp.Sub(correlations[j].Timestamp)) <= 1*time.Minute {
				pair := fmt.Sprintf("%s+%s", correlations[i].Type, correlations[j].Type)
				eventPairs[pair]++
			}
		}
	}

	// Find most frequent pair
	maxCount := 0
	var bestPair string
	for pair, count := range eventPairs {
		if count > maxCount {
			maxCount = count
			bestPair = pair
		}
	}

	if maxCount >= 2 {
		parts := strings.Split(bestPair, "+")
		return &Pattern{
			ID:          generatePatternID(),
			Type:        PatternTypeCorrelated,
			Name:        "Correlated Events",
			Description: fmt.Sprintf("%s and %s occur together", parts[0], parts[1]),
			Confidence:  float64(maxCount) / float64(len(correlations)),
			Occurrences: maxCount,
			FirstSeen:   correlations[0].Timestamp,
			LastSeen:    correlations[len(correlations)-1].Timestamp,
			Signature:   []string{bestPair},
		}, true
	}

	return nil, false
}

// detectSequentialPattern looks for specific sequences
func (pm *PatternMatcher) detectSequentialPattern(correlations []CorrelationData, findings []Finding) (*Pattern, bool) {
	// Look for common sequences like: config_change -> restart -> error
	knownSequences := [][]string{
		{"config", "restart", "error"},
		{"deploy", "restart", "fail"},
		{"memory", "oom", "crash"},
		{"network", "timeout", "error"},
	}

	for _, sequence := range knownSequences {
		if matchesSequence(correlations, sequence) {
			return &Pattern{
				ID:          generatePatternID(),
				Type:        PatternTypeSequential,
				Name:        "Sequential Pattern",
				Description: fmt.Sprintf("Sequence detected: %s", strings.Join(sequence, " → ")),
				Confidence:  0.8,
				Occurrences: 1,
				FirstSeen:   correlations[0].Timestamp,
				LastSeen:    correlations[len(correlations)-1].Timestamp,
				Signature:   sequence,
			}, true
		}
	}

	return nil, false
}

// Helper functions

func generatePatternID() string {
	return fmt.Sprintf("pattern-%d", time.Now().UnixNano())
}

func calculateCascadeConfidence(failureCount int, duration time.Duration) float64 {
	// More failures in shorter time = higher confidence
	baseConfidence := 0.5

	// Boost for many failures
	if failureCount > 5 {
		baseConfidence += 0.2
	} else if failureCount > 3 {
		baseConfidence += 0.1
	}

	// Boost for rapid succession
	if duration <= 1*time.Minute {
		baseConfidence += 0.2
	} else if duration <= 3*time.Minute {
		baseConfidence += 0.1
	}

	return baseConfidence
}

func isPeriodicPattern(intervals []time.Duration) bool {
	if len(intervals) < 2 {
		return false
	}

	avg := averageDuration(intervals)

	// Check if all intervals are within 20% of average
	for _, interval := range intervals {
		deviation := absDuration(interval - avg)
		if float64(deviation) > float64(avg)*0.2 {
			return false
		}
	}

	return true
}

func averageDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	total := time.Duration(0)
	for _, d := range durations {
		total += d
	}

	return total / time.Duration(len(durations))
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func matchesSequence(correlations []CorrelationData, sequence []string) bool {
	if len(correlations) < len(sequence) {
		return false
	}

	sequenceIndex := 0
	for _, corr := range correlations {
		if sequenceIndex >= len(sequence) {
			return true
		}

		keyword := sequence[sequenceIndex]
		if strings.Contains(strings.ToLower(corr.Type), keyword) ||
			strings.Contains(strings.ToLower(corr.Summary), keyword) {
			sequenceIndex++
		}
	}

	return sequenceIndex >= len(sequence)
}
