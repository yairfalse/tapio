package analysis

import (
	"math"
	"time"
)

// ConfidenceScorer calculates confidence scores for findings
type ConfidenceScorer struct {
	config Config
}

// NewConfidenceScorer creates a new scorer
func NewConfidenceScorer(config Config) *ConfidenceScorer {
	return &ConfidenceScorer{
		config: config,
	}
}

// ScoreGroup calculates confidence for a group of correlations
func (s *ConfidenceScorer) ScoreGroup(group []CorrelationData) float64 {
	if len(group) == 0 {
		return 0
	}

	// Base confidence from individual correlations
	baseConfidence := s.calculateBaseConfidence(group)

	// Agreement boost - multiple correlators seeing the same thing
	agreementBoost := s.calculateAgreementBoost(group)

	// Evidence strength
	evidenceScore := s.calculateEvidenceScore(group)

	// Temporal proximity - events close in time are more likely related
	temporalScore := s.calculateTemporalScore(group)

	// Weighted combination
	finalScore := (baseConfidence * 0.3) +
		(agreementBoost * s.config.CorrelatorAgreementWeight) +
		(evidenceScore * s.config.EvidenceStrengthWeight) +
		(temporalScore * s.config.TemporalProximityWeight)

	// Apply decay based on age
	finalScore = s.applyTimeDecay(finalScore, group)

	// Ensure between 0 and 1
	return math.Min(1.0, math.Max(0.0, finalScore))
}

// calculateBaseConfidence averages individual correlation confidences
func (s *ConfidenceScorer) calculateBaseConfidence(group []CorrelationData) float64 {
	if len(group) == 0 {
		return 0
	}

	total := 0.0
	for _, corr := range group {
		total += corr.Confidence
	}

	return total / float64(len(group))
}

// calculateAgreementBoost rewards multiple correlators agreeing
func (s *ConfidenceScorer) calculateAgreementBoost(group []CorrelationData) float64 {
	// Count unique sources
	sources := make(map[string]bool)
	for _, corr := range group {
		sources[corr.Source] = true
	}

	uniqueSources := len(sources)

	// No boost for single source
	if uniqueSources <= 1 {
		return 0.5
	}

	// Logarithmic boost for multiple sources
	// 2 sources = 0.69, 3 = 0.79, 4 = 0.86, 5 = 0.90
	return math.Min(1.0, 0.5+math.Log(float64(uniqueSources))/5.0)
}

// calculateEvidenceScore scores based on evidence quality and quantity
func (s *ConfidenceScorer) calculateEvidenceScore(group []CorrelationData) float64 {
	totalEvidence := 0
	highQualityEvidence := 0

	for _, corr := range group {
		evidenceCount := len(corr.Evidence)
		totalEvidence += evidenceCount

		// High confidence correlations have higher quality evidence
		if corr.Confidence > 0.7 {
			highQualityEvidence += evidenceCount
		}
	}

	if totalEvidence == 0 {
		return 0.3 // Low score for no evidence
	}

	// Quality ratio
	qualityRatio := float64(highQualityEvidence) / float64(totalEvidence)

	// Quantity bonus (diminishing returns)
	quantityScore := math.Min(1.0, math.Log(float64(totalEvidence)+1)/10.0)

	// Combine quality and quantity
	return (qualityRatio * 0.7) + (quantityScore * 0.3)
}

// calculateTemporalScore rewards events that are close in time
func (s *ConfidenceScorer) calculateTemporalScore(group []CorrelationData) float64 {
	if len(group) <= 1 {
		return 0.5
	}

	// Find time span of all correlations
	var earliest, latest time.Time
	for i, corr := range group {
		if i == 0 || corr.Timestamp.Before(earliest) {
			earliest = corr.Timestamp
		}
		if i == 0 || corr.Timestamp.After(latest) {
			latest = corr.Timestamp
		}
	}

	timeSpan := latest.Sub(earliest)

	// Events within 1 minute = high score
	// Events within 5 minutes = medium score
	// Events over 30 minutes = low score
	switch {
	case timeSpan <= 1*time.Minute:
		return 1.0
	case timeSpan <= 5*time.Minute:
		return 0.8
	case timeSpan <= 10*time.Minute:
		return 0.6
	case timeSpan <= 30*time.Minute:
		return 0.4
	default:
		return 0.2
	}
}

// applyTimeDecay reduces confidence for older correlations
func (s *ConfidenceScorer) applyTimeDecay(score float64, group []CorrelationData) float64 {
	// Find most recent correlation
	var mostRecent time.Time
	for i, corr := range group {
		if i == 0 || corr.Timestamp.After(mostRecent) {
			mostRecent = corr.Timestamp
		}
	}

	age := time.Since(mostRecent)

	// No decay for fresh correlations
	if age <= 5*time.Minute {
		return score
	}

	// Exponential decay
	// Half-life of 1 hour
	halfLife := 1 * time.Hour
	decayFactor := math.Pow(0.5, float64(age)/float64(halfLife))

	return score * decayFactor
}

// ScoreEvidence scores individual evidence pieces
func (s *ConfidenceScorer) ScoreEvidence(evidence []Evidence) float64 {
	if len(evidence) == 0 {
		return 0
	}

	totalScore := 0.0
	weights := map[EvidenceType]float64{
		EvidenceTypeDirect:     1.0,
		EvidenceTypeCorrelated: 0.7,
		EvidenceTypeInferred:   0.5,
		EvidenceTypeHistorical: 0.3,
	}

	for _, ev := range evidence {
		weight, ok := weights[ev.Type]
		if !ok {
			weight = 0.5
		}
		totalScore += ev.Confidence * weight
	}

	// Average weighted score
	return totalScore / float64(len(evidence))
}

// ScorePattern scores pattern matches
func (s *ConfidenceScorer) ScorePattern(pattern Pattern) float64 {
	// Base score from pattern confidence
	score := pattern.Confidence

	// Boost for frequent patterns
	if pattern.Occurrences > 10 {
		score *= 1.2
	} else if pattern.Occurrences > 5 {
		score *= 1.1
	}

	// Boost for recent patterns
	recency := time.Since(pattern.LastSeen)
	if recency < 1*time.Hour {
		score *= 1.1
	}

	// Cap at 1.0
	return math.Min(1.0, score)
}
