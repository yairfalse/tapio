package aggregator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/intelligence/correlation"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Production Story Generator Implementation

type productionStoryGenerator struct {
	logger    *zap.Logger
	config    *StoryGenerationConfiguration
	tracer    trace.Tracer
	templates map[string]*StoryTemplate
	mu        sync.RWMutex
}

func (sg *productionStoryGenerator) GenerateStory(
	ctx context.Context,
	insight *IntelligenceInsight,
	template *StoryTemplate,
) (*Story, error) {
	ctx, span := sg.tracer.Start(ctx, "story_generator.generate_story")
	defer span.End()

	span.SetAttributes(
		attribute.String("insight.id", insight.ID),
		attribute.String("insight.type", insight.Type),
		attribute.String("template.id", template.ID),
	)

	// Parse templates
	titleTmpl, err := sg.parseTemplate(template.TitleTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse title template: %w", err)
	}

	summaryTmpl, err := sg.parseTemplate(template.SummaryTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse summary template: %w", err)
	}

	mainTmpl, err := sg.parseTemplate(template.MainTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse main template: %w", err)
	}

	// Prepare template data
	data := sg.buildTemplateData(insight)

	// Generate story components
	title, err := sg.executeTemplate(titleTmpl, data)
	if err != nil {
		return nil, fmt.Errorf("failed to execute title template: %w", err)
	}

	summary, err := sg.executeTemplate(summaryTmpl, data)
	if err != nil {
		return nil, fmt.Errorf("failed to execute summary template: %w", err)
	}

	narrative, err := sg.executeTemplate(mainTmpl, data)
	if err != nil {
		return nil, fmt.Errorf("failed to execute main template: %w", err)
	}

	// Build timeline
	timeline := sg.buildTimeline(insight)

	// Extract key points
	keyPoints := sg.extractKeyPoints(insight)

	story := &Story{
		ID:         generateStoryID(),
		TemplateID: template.ID,
		Title:      title,
		Summary:    summary,
		Narrative:  narrative,
		Timeline:   timeline,
		KeyPoints:  keyPoints,
		Audience:   template.Audience,
		Format:     template.Format,
		TechnicalDetails: map[string]interface{}{
			"insight_id":        insight.ID,
			"confidence":        insight.OverallConfidence,
			"correlation_count": len(insight.SourceCorrelations),
		},
	}

	span.SetAttributes(
		attribute.String("story.id", story.ID),
		attribute.Int("story.key_points", len(story.KeyPoints)),
		attribute.Int("story.timeline_events", len(story.Timeline)),
	)

	return story, nil
}

func (sg *productionStoryGenerator) GetAvailableTemplates(
	ctx context.Context,
	domain string,
) ([]*StoryTemplate, error) {
	sg.mu.RLock()
	defer sg.mu.RUnlock()

	templates := make([]*StoryTemplate, 0)
	for _, tmpl := range sg.templates {
		if domain == "" || tmpl.Domain == domain {
			templates = append(templates, tmpl)
		}
	}

	return templates, nil
}

func (sg *productionStoryGenerator) UpdateTemplate(
	ctx context.Context,
	template *StoryTemplate,
) error {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}

	sg.templates[template.ID] = template
	sg.logger.Debug("Updated story template", zap.String("template_id", template.ID))

	return nil
}

func (sg *productionStoryGenerator) FindBestTemplate(
	ctx context.Context,
	insight *IntelligenceInsight,
) (*StoryTemplate, error) {
	templates, err := sg.GetAvailableTemplates(ctx, "")
	if err != nil {
		return nil, err
	}

	// Score templates based on insight compatibility
	bestTemplate := (*StoryTemplate)(nil)
	bestScore := 0.0

	for _, tmpl := range templates {
		score := sg.scoreTemplateMatch(insight, tmpl)
		if score > bestScore {
			bestScore = score
			bestTemplate = tmpl
		}
	}

	if bestTemplate == nil {
		return sg.getDefaultTemplate(), nil
	}

	return bestTemplate, nil
}

func (sg *productionStoryGenerator) parseTemplate(tmplText string) (*template.Template, error) {
	return template.New("story").Parse(tmplText)
}

func (sg *productionStoryGenerator) executeTemplate(tmpl *template.Template, data interface{}) (string, error) {
	var buf strings.Builder
	err := tmpl.Execute(&buf, data)
	return buf.String(), err
}

func (sg *productionStoryGenerator) buildTemplateData(insight *IntelligenceInsight) map[string]interface{} {
	return map[string]interface{}{
		"Insight":         insight,
		"Title":           insight.Title,
		"Summary":         insight.Summary,
		"Confidence":      fmt.Sprintf("%.1f%%", insight.OverallConfidence*100),
		"RootCauses":      insight.RootCauses,
		"Impact":          insight.ImpactScope,
		"Recommendations": insight.Recommendations,
		"Evidence":        insight.Evidence,
		"K8sContext":      insight.K8sContext,
		"Timestamp":       insight.Timestamp.Format("2006-01-02 15:04:05 UTC"),
		"RelatedCount":    len(insight.SourceCorrelations),
	}
}

func (sg *productionStoryGenerator) buildTimeline(insight *IntelligenceInsight) []*StoryTimelineEvent {
	events := make([]*StoryTimelineEvent, 0)

	// Add root causes as timeline events
	for _, rootCause := range insight.RootCauses {
		events = append(events, &StoryTimelineEvent{
			Timestamp:   rootCause.FirstSeen,
			Title:       "Root Cause Identified",
			Description: rootCause.Description,
			Impact:      rootCause.Type,
			StoryPhase:  "incident",
		})
	}

	// Sort by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	return events
}

func (sg *productionStoryGenerator) extractKeyPoints(insight *IntelligenceInsight) []string {
	keyPoints := make([]string, 0)

	// Add high-confidence root causes
	for _, rootCause := range insight.RootCauses {
		if rootCause.Confidence > 0.8 {
			keyPoints = append(keyPoints, fmt.Sprintf("High-confidence root cause: %s", rootCause.Description))
		}
	}

	// Add impact information
	if insight.ImpactScope != nil && len(insight.ImpactScope.AffectedServices) > 0 {
		keyPoints = append(keyPoints, fmt.Sprintf("Services affected: %d", len(insight.ImpactScope.AffectedServices)))
	}

	// Add recommendation count
	if len(insight.Recommendations) > 0 {
		keyPoints = append(keyPoints, fmt.Sprintf("Available recommendations: %d", len(insight.Recommendations)))
	}

	return keyPoints
}

func (sg *productionStoryGenerator) scoreTemplateMatch(insight *IntelligenceInsight, template *StoryTemplate) float64 {
	score := 0.0

	// Match insight type
	for _, insightType := range template.InsightTypes {
		if insightType == insight.Type {
			score += 1.0
			break
		}
	}

	// Match domain from K8s context
	if insight.K8sContext != nil && template.Domain == "k8s" {
		score += 0.5
	}

	return score
}

func (sg *productionStoryGenerator) getDefaultTemplate() *StoryTemplate {
	return &StoryTemplate{
		ID:              "default",
		Name:            "Default Template",
		Domain:          "generic",
		InsightTypes:    []string{"*"},
		Audience:        "technical",
		Format:          "markdown",
		TitleTemplate:   "{{.Title}}",
		SummaryTemplate: "{{.Summary}}",
		MainTemplate:    "## Analysis\n\n{{.Summary}}\n\n**Confidence**: {{.Confidence}}\n\n**Correlations**: {{.RelatedCount}}",
	}
}

// Production Confidence Calculator Implementation

type productionConfidenceCalculator struct {
	logger *zap.Logger
	config *ConfidenceConfiguration
	tracer trace.Tracer
}

func (cc *productionConfidenceCalculator) CalculateInsightConfidence(
	ctx context.Context,
	insight *IntelligenceInsight,
	rules *ConfidenceRules,
) (float64, error) {
	ctx, span := cc.tracer.Start(ctx, "confidence_calculator.calculate_insight_confidence")
	defer span.End()

	span.SetAttributes(
		attribute.String("insight.id", insight.ID),
		attribute.String("insight.type", insight.Type),
	)

	switch cc.config.Algorithm {
	case "weighted_average":
		return cc.calculateWeightedAverage(ctx, insight)
	case "bayesian":
		return cc.calculateBayesian(ctx, insight)
	case "neural_network":
		return cc.calculateNeuralNetwork(ctx, insight)
	default:
		return cc.calculateWeightedAverage(ctx, insight)
	}
}

func (cc *productionConfidenceCalculator) CalculateCorrelationWeight(
	ctx context.Context,
	correlation *correlation.CorrelationResult,
	criteria *WeightingCriteria,
) (float64, error) {
	// Base weight from correlation confidence
	weight := correlation.Confidence

	// Apply correlator-specific weighting
	if correlatorWeight, exists := criteria.CorrelatorWeights[correlation.Type]; exists {
		weight *= correlatorWeight
	}

	// Apply recency weighting
	age := time.Since(correlation.StartTime)
	recencyWeight := cc.calculateRecencyWeight(age, criteria)
	weight *= recencyWeight

	// Apply frequency bonus (if available)
	// This would require historical data in a real implementation

	return math.Min(weight, 1.0), nil
}

func (cc *productionConfidenceCalculator) ValidateThresholds(
	ctx context.Context,
	insight *IntelligenceInsight,
	thresholds *ConfidenceThresholds,
) (*ValidationResult, error) {
	result := &ValidationResult{
		OverallConfidence: insight.OverallConfidence,
		RequiredThreshold: thresholds.MinimumOverallConfidence,
		ThresholdMet:      insight.OverallConfidence >= thresholds.MinimumOverallConfidence,
		ValidationDetails: []*ValidationDetail{},
	}

	// Validate overall confidence
	result.ValidationDetails = append(result.ValidationDetails, &ValidationDetail{
		Component: "overall",
		CheckName: "minimum_confidence",
		Passed:    result.ThresholdMet,
		Value:     insight.OverallConfidence,
		Threshold: thresholds.MinimumOverallConfidence,
		Message:   fmt.Sprintf("Overall confidence %.2f vs threshold %.2f", insight.OverallConfidence, thresholds.MinimumOverallConfidence),
	})

	// Validate evidence count
	evidenceCount := len(insight.Evidence)
	evidencePass := evidenceCount >= thresholds.MinimumEvidenceCount
	result.ValidationDetails = append(result.ValidationDetails, &ValidationDetail{
		Component: "evidence",
		CheckName: "minimum_count",
		Passed:    evidencePass,
		Value:     evidenceCount,
		Threshold: thresholds.MinimumEvidenceCount,
		Message:   fmt.Sprintf("Evidence count %d vs minimum %d", evidenceCount, thresholds.MinimumEvidenceCount),
	})

	// Validate root cause confidence
	for i, rootCause := range insight.RootCauses {
		rcPass := rootCause.Confidence >= thresholds.RootCauseMinConfidence
		result.ValidationDetails = append(result.ValidationDetails, &ValidationDetail{
			Component: fmt.Sprintf("root_cause[%d]", i),
			CheckName: "minimum_confidence",
			Passed:    rcPass,
			Value:     rootCause.Confidence,
			Threshold: thresholds.RootCauseMinConfidence,
			Message:   fmt.Sprintf("Root cause confidence %.2f vs threshold %.2f", rootCause.Confidence, thresholds.RootCauseMinConfidence),
		})

		if !rcPass {
			result.ThresholdMet = false
		}
	}

	result.Passed = result.ThresholdMet

	if !result.Passed {
		result.FailureReasons = []string{"One or more confidence thresholds not met"}
		result.Recommendations = []string{"Review evidence quality", "Consider additional correlations"}
	}

	return result, nil
}

func (cc *productionConfidenceCalculator) CalculateCorrelationConfidence(
	ctx context.Context,
	corr *correlation.CorrelationResult,
	patterns []*LearnedPattern,
) (float64, error) {
	// Base confidence from correlation
	confidence := corr.Confidence

	// Boost confidence if matches known patterns
	for _, pattern := range patterns {
		if cc.matchesPattern(corr, pattern) {
			confidence += pattern.Confidence * 0.2 // 20% boost for pattern match
			break
		}
	}

	// Apply evidence-based adjustments
	if corr.RootCause != nil {
		confidence *= 1.1 // Slight boost for root cause identification
	}

	if corr.Impact != nil && corr.Impact.Severity == domain.SeverityCritical {
		confidence *= 1.05 // Slight boost for critical impacts
	}

	return math.Min(confidence, 1.0), nil
}

func (cc *productionConfidenceCalculator) calculateWeightedAverage(
	ctx context.Context,
	insight *IntelligenceInsight,
) (float64, error) {
	if len(insight.Evidence) == 0 {
		return 0.5, nil // Default confidence with no evidence
	}

	totalWeight := 0.0
	weightedSum := 0.0

	for _, evidence := range insight.Evidence {
		weight := evidence.Weight
		if weight == 0 {
			weight = 1.0 // Default weight
		}

		weightedSum += evidence.Confidence * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0.5, nil
	}

	confidence := weightedSum / totalWeight

	// Apply adjustments
	confidence = cc.applyConfidenceAdjustments(confidence, insight)

	return math.Min(math.Max(confidence, 0.0), 1.0), nil
}

func (cc *productionConfidenceCalculator) calculateBayesian(
	ctx context.Context,
	insight *IntelligenceInsight,
) (float64, error) {
	// Simplified Bayesian calculation
	// In production, this would use proper Bayesian inference

	priorProbability := 0.5 // Base prior

	// Calculate likelihood based on evidence
	likelihood := cc.calculateEvidenceLikelihood(insight.Evidence)

	// Simple Bayesian update
	posterior := (likelihood * priorProbability) /
		((likelihood * priorProbability) + ((1.0 - likelihood) * (1.0 - priorProbability)))

	return posterior, nil
}

func (cc *productionConfidenceCalculator) calculateNeuralNetwork(
	ctx context.Context,
	insight *IntelligenceInsight,
) (float64, error) {
	// Placeholder for neural network-based confidence calculation
	// This would integrate with a trained ML model in production

	// For now, use a feature-based approach
	features := cc.extractInsightFeatures(insight)
	confidence := cc.simpleNeuralNetworkPredict(features)

	return confidence, nil
}

func (cc *productionConfidenceCalculator) calculateRecencyWeight(
	age time.Duration,
	criteria *WeightingCriteria,
) float64 {
	hours := float64(age) / float64(time.Hour)
	halfLifeHours := float64(criteria.RecencyHalfLife) / float64(time.Hour)

	switch criteria.RecencyWeightFunction {
	case "exponential":
		return math.Exp(-0.693 * hours / halfLifeHours) // Half-life decay
	case "linear":
		return math.Max(0, 1.0-hours/halfLifeHours)
	case "logarithmic":
		return 1.0 / (1.0 + math.Log(1.0+hours/halfLifeHours))
	default:
		return math.Exp(-0.693 * hours / halfLifeHours)
	}
}

func (cc *productionConfidenceCalculator) matchesPattern(
	corr *correlation.CorrelationResult,
	pattern *LearnedPattern,
) bool {
	// Check if correlation matches any pattern conditions
	for _, condition := range pattern.Conditions {
		if cc.evaluatePatternCondition(corr, condition) {
			return true
		}
	}
	return false
}

func (cc *productionConfidenceCalculator) evaluatePatternCondition(
	corr *correlation.CorrelationResult,
	condition *PatternCondition,
) bool {
	switch condition.Field {
	case "type":
		return condition.Value == corr.Type
	case "confidence":
		threshold, ok := condition.Value.(float64)
		if !ok {
			return false
		}
		return corr.Confidence >= threshold
	default:
		return false
	}
}

func (cc *productionConfidenceCalculator) applyConfidenceAdjustments(
	confidence float64,
	insight *IntelligenceInsight,
) float64 {
	// Apply diversity bonus
	if len(insight.SourceCorrelations) > 3 {
		confidence += cc.config.DiversityBonus
	}

	// Apply missing data penalty
	if len(insight.Evidence) < 2 {
		confidence -= cc.config.MissingDataPenalty
	}

	return confidence
}

func (cc *productionConfidenceCalculator) calculateEvidenceLikelihood(evidence []*Evidence) float64 {
	if len(evidence) == 0 {
		return 0.1
	}

	// Calculate average evidence confidence
	sum := 0.0
	for _, e := range evidence {
		sum += e.Confidence
	}
	return sum / float64(len(evidence))
}

func (cc *productionConfidenceCalculator) extractInsightFeatures(insight *IntelligenceInsight) []float64 {
	features := make([]float64, 0)

	// Feature 1: Number of evidence items (normalized)
	features = append(features, math.Min(float64(len(insight.Evidence))/10.0, 1.0))

	// Feature 2: Average evidence confidence
	avgEvidenceConf := 0.0
	if len(insight.Evidence) > 0 {
		sum := 0.0
		for _, e := range insight.Evidence {
			sum += e.Confidence
		}
		avgEvidenceConf = sum / float64(len(insight.Evidence))
	}
	features = append(features, avgEvidenceConf)

	// Feature 3: Number of source correlations (normalized)
	features = append(features, math.Min(float64(len(insight.SourceCorrelations))/5.0, 1.0))

	// Feature 4: Has root causes (binary)
	if len(insight.RootCauses) > 0 {
		features = append(features, 1.0)
	} else {
		features = append(features, 0.0)
	}

	return features
}

func (cc *productionConfidenceCalculator) simpleNeuralNetworkPredict(features []float64) float64 {
	// Simple linear combination as a placeholder for neural network
	// In production, this would be a trained model
	weights := []float64{0.3, 0.4, 0.2, 0.1}

	if len(features) != len(weights) {
		return 0.5 // Default
	}

	sum := 0.0
	for i, feature := range features {
		sum += feature * weights[i]
	}

	// Apply sigmoid activation
	return 1.0 / (1.0 + math.Exp(-sum))
}

// Production Pattern Learner Implementation

type productionPatternLearner struct {
	logger   *zap.Logger
	store    Neo4jIntelligenceStore
	config   *PatternLearningConfiguration
	tracer   trace.Tracer
	patterns map[string]*LearnedPattern
	mu       sync.RWMutex
}

func (pl *productionPatternLearner) LearnFromCorrelations(
	ctx context.Context,
	correlations []*correlation.CorrelationResult,
) error {
	ctx, span := pl.tracer.Start(ctx, "pattern_learner.learn_from_correlations")
	defer span.End()

	span.SetAttributes(
		attribute.Int("correlations.count", len(correlations)),
	)

	// Group correlations by similarity
	groups := pl.groupSimilarCorrelations(correlations)

	patternsCreated := 0
	for _, group := range groups {
		if len(group) >= pl.config.MinPatternOccurrences {
			pattern := pl.extractPatternFromGroup(group)
			if pattern.Confidence >= pl.config.MinPatternConfidence {
				if err := pl.storePattern(ctx, pattern); err != nil {
					pl.logger.Warn("Failed to store learned pattern", zap.Error(err))
				} else {
					patternsCreated++
				}
			}
		}
	}

	span.SetAttributes(
		attribute.Int("patterns.created", patternsCreated),
	)

	pl.logger.Debug("Learned patterns from correlations",
		zap.Int("correlation_groups", len(groups)),
		zap.Int("patterns_created", patternsCreated))

	return nil
}

func (pl *productionPatternLearner) UpdateInsightPatterns(
	ctx context.Context,
	insights []*IntelligenceInsight,
	feedback []*InsightFeedback,
) error {
	ctx, span := pl.tracer.Start(ctx, "pattern_learner.update_insight_patterns")
	defer span.End()

	patternsUpdated := 0

	// Apply feedback to update pattern confidence
	for _, fb := range feedback {
		if err := pl.applyFeedbackToPatterns(ctx, fb); err != nil {
			pl.logger.Warn("Failed to apply feedback",
				zap.String("insight_id", fb.InsightID),
				zap.Error(err))
		} else {
			patternsUpdated++
		}
	}

	span.SetAttributes(
		attribute.Int("feedback.count", len(feedback)),
		attribute.Int("patterns.updated", patternsUpdated),
	)

	return nil
}

func (pl *productionPatternLearner) GetLearnedPatterns(
	ctx context.Context,
	domain string,
) ([]*LearnedPattern, error) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	patterns := make([]*LearnedPattern, 0)
	for _, pattern := range pl.patterns {
		if domain == "" || pattern.Domain == domain {
			patterns = append(patterns, pattern)
		}
	}

	return patterns, nil
}

func (pl *productionPatternLearner) ExportPatterns(ctx context.Context) (*PatternExport, error) {
	patterns, err := pl.GetLearnedPatterns(ctx, "")
	if err != nil {
		return nil, err
	}

	return &PatternExport{
		Version:    "1.0",
		Patterns:   patterns,
		ExportedAt: time.Now(),
		ExportedBy: "pattern-learner",
		Metadata:   map[string]interface{}{"pattern_count": len(patterns)},
	}, nil
}

func (pl *productionPatternLearner) LearnFromFeedback(
	ctx context.Context,
	feedback *InsightFeedback,
) (*LearningResult, error) {
	ctx, span := pl.tracer.Start(ctx, "pattern_learner.learn_from_feedback")
	defer span.End()

	result := &LearningResult{
		ConfidenceChanges: []*ConfidenceChange{},
		LearningTime:      time.Now(),
		EffectiveAt:       time.Now(),
	}

	// Update patterns based on feedback
	if err := pl.applyFeedbackToPatterns(ctx, feedback); err != nil {
		return nil, err
	}

	result.PatternsUpdated = 1 // Simplified

	span.SetAttributes(
		attribute.String("feedback.insight_id", feedback.InsightID),
		attribute.Int("result.patterns_updated", result.PatternsUpdated),
	)

	return result, nil
}

func (pl *productionPatternLearner) MatchPatterns(
	ctx context.Context,
	corr *correlation.CorrelationResult,
) ([]*LearnedPattern, error) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	matches := make([]*LearnedPattern, 0)

	for _, pattern := range pl.patterns {
		if pl.correlationMatchesPattern(corr, pattern) {
			matches = append(matches, pattern)
		}
	}

	return matches, nil
}

func (pl *productionPatternLearner) ImportPattern(
	ctx context.Context,
	pattern *LearnedPattern,
) error {
	return pl.storePattern(ctx, pattern)
}

func (pl *productionPatternLearner) groupSimilarCorrelations(
	correlations []*correlation.CorrelationResult,
) [][]*correlation.CorrelationResult {
	// Simple grouping by type - in production, this would be more sophisticated
	groups := make(map[string][]*correlation.CorrelationResult)

	for _, corr := range correlations {
		key := corr.Type
		groups[key] = append(groups[key], corr)
	}

	result := make([][]*correlation.CorrelationResult, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}

	return result
}

func (pl *productionPatternLearner) extractPatternFromGroup(
	group []*correlation.CorrelationResult,
) *LearnedPattern {
	if len(group) == 0 {
		return nil
	}

	representative := group[0]

	return &LearnedPattern{
		ID:           generatePatternID(),
		Name:         fmt.Sprintf("Pattern for %s correlations", representative.Type),
		Type:         "statistical",
		Domain:       "k8s", // Default domain
		DiscoveredAt: time.Now(),
		LastRefined:  time.Now(),
		MatchCount:   len(group),
		SuccessRate:  0.8, // Default success rate
		Confidence:   representative.Confidence,
		Conditions: []*PatternCondition{
			{
				Type:     "type_match",
				Field:    "type",
				Operator: "equals",
				Value:    representative.Type,
				Weight:   1.0,
				Required: true,
			},
		},
		Outcomes: []*PatternOutcome{
			{
				Type:        "correlation",
				Probability: 0.8,
				Confidence:  representative.Confidence,
				ImpactLevel: "medium",
				Description: fmt.Sprintf("Likely %s correlation", representative.Type),
			},
		},
		UsageStats: &PatternUsageStats{
			TotalMatches:  len(group),
			RecentMatches: len(group),
			SuccessRate:   0.8,
			LastUsed:      time.Now(),
		},
	}
}

func (pl *productionPatternLearner) storePattern(
	ctx context.Context,
	pattern *LearnedPattern,
) error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.patterns[pattern.ID] = pattern

	// Also store in Neo4j
	return pl.store.StorePattern(ctx, pattern)
}

func (pl *productionPatternLearner) applyFeedbackToPatterns(
	ctx context.Context,
	feedback *InsightFeedback,
) error {
	// Update pattern confidence based on feedback
	// This is a simplified implementation

	if feedback.Accuracy != nil {
		adjustment := (*feedback.Accuracy - 0.5) * 0.1 // +/- 5% adjustment

		pl.mu.Lock()
		for _, pattern := range pl.patterns {
			pattern.Confidence = math.Max(0.0, math.Min(1.0, pattern.Confidence+adjustment))
		}
		pl.mu.Unlock()
	}

	return nil
}

func (pl *productionPatternLearner) correlationMatchesPattern(
	corr *correlation.CorrelationResult,
	pattern *LearnedPattern,
) bool {
	// Check all conditions
	for _, condition := range pattern.Conditions {
		if !pl.evaluateCondition(corr, condition) {
			return false
		}
	}
	return true
}

func (pl *productionPatternLearner) evaluateCondition(
	corr *correlation.CorrelationResult,
	condition *PatternCondition,
) bool {
	switch condition.Field {
	case "type":
		return condition.Value == corr.Type
	case "confidence":
		threshold, ok := condition.Value.(float64)
		if !ok {
			return false
		}
		switch condition.Operator {
		case "greater_than":
			return corr.Confidence > threshold
		case "less_than":
			return corr.Confidence < threshold
		case "equals":
			return math.Abs(corr.Confidence-threshold) < 0.01
		}
	}
	return false
}

// Utility functions

func generateStoryID() string {
	return fmt.Sprintf("story-%d", time.Now().UnixNano())
}

func generatePatternID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("pattern-%s", hex.EncodeToString(bytes)[:16])
}
