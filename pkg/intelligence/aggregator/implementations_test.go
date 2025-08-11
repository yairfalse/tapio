package aggregator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/intelligence/correlation"
	"go.uber.org/zap"
)

// Mock Neo4j Store for testing
type mockNeo4jIntelligenceStore struct {
	mock.Mock
}

func (m *mockNeo4jIntelligenceStore) StoreInsight(ctx context.Context, insight *IntelligenceInsight) (*StorageResult, error) {
	args := m.Called(ctx, insight)
	return args.Get(0).(*StorageResult), args.Error(1)
}

func (m *mockNeo4jIntelligenceStore) StorePattern(ctx context.Context, pattern *LearnedPattern) error {
	args := m.Called(ctx, pattern)
	return args.Error(0)
}

func (m *mockNeo4jIntelligenceStore) QueryInsights(ctx context.Context, query *InsightQuery) (*InsightQueryResult, error) {
	args := m.Called(ctx, query)
	return args.Get(0).(*InsightQueryResult), args.Error(1)
}

func (m *mockNeo4jIntelligenceStore) GetPatterns(ctx context.Context, domain string) ([]*LearnedPattern, error) {
	args := m.Called(ctx, domain)
	return args.Get(0).([]*LearnedPattern), args.Error(1)
}

func (m *mockNeo4jIntelligenceStore) Health(ctx context.Context) (*HealthStatus, error) {
	args := m.Called(ctx)
	return args.Get(0).(*HealthStatus), args.Error(1)
}

// Test Story Generator

func TestProductionStoryGenerator_GenerateStory(t *testing.T) {
	logger := zap.NewNop()
	config := &StoryGenerationConfiguration{
		EnabledTemplates: []string{"default"},
		MaxStoryLength:   1000,
	}

	sg := &productionStoryGenerator{
		logger:    logger,
		config:    config,
		tracer:    mockTracer{},
		templates: make(map[string]*StoryTemplate),
	}

	// Create test insight
	insight := &IntelligenceInsight{
		ID:                 "test-insight-1",
		Title:              "Memory Exhaustion in Pod",
		Type:               "resource_exhaustion",
		Summary:            "Pod is running out of memory",
		OverallConfidence:  0.85,
		Timestamp:          time.Now(),
		SourceCorrelations: []string{"corr1", "corr2"},
		RootCauses: []*RootCause{
			{
				Type:        "memory_leak",
				Description: "Application memory leak detected",
				Confidence:  0.8,
				FirstSeen:   time.Now().Add(-30 * time.Minute),
			},
		},
		ImpactScope: &ImpactScope{
			AffectedServices: []string{"web-service"},
		},
		Recommendations: []*Recommendation{
			{
				Action:      "restart_pod",
				Description: "Restart the affected pod to clear memory",
				Priority:    "high",
				Confidence:  0.9,
			},
		},
		Evidence: []*Evidence{
			{
				Type:        "metric",
				Description: "Memory usage at 95%",
				Source:      "prometheus",
				Confidence:  0.9,
				Weight:      1.0,
			},
		},
	}

	template := &StoryTemplate{
		ID:              "test-template",
		Name:            "Test Template",
		Domain:          "k8s",
		InsightTypes:    []string{"resource_exhaustion"},
		Audience:        "technical",
		Format:          "markdown",
		TitleTemplate:   "{{.Title}}",
		SummaryTemplate: "{{.Summary}}",
		MainTemplate:    "## Problem\n{{.Summary}}\n\n**Confidence**: {{.Confidence}}",
	}

	story, err := sg.GenerateStory(context.Background(), insight, template)

	require.NoError(t, err)
	assert.NotNil(t, story)
	assert.NotEmpty(t, story.ID)
	assert.Equal(t, template.ID, story.TemplateID)
	assert.Equal(t, insight.Title, story.Title)
	assert.Equal(t, insight.Summary, story.Summary)
	assert.Contains(t, story.Narrative, "Problem")
	assert.Contains(t, story.Narrative, insight.Summary)
	assert.NotEmpty(t, story.Timeline)
	assert.NotEmpty(t, story.KeyPoints)
	assert.Equal(t, template.Audience, story.Audience)
	assert.Equal(t, template.Format, story.Format)
}

func TestProductionStoryGenerator_GetAvailableTemplates(t *testing.T) {
	sg := &productionStoryGenerator{
		templates: map[string]*StoryTemplate{
			"k8s-1": {ID: "k8s-1", Domain: "k8s"},
			"k8s-2": {ID: "k8s-2", Domain: "k8s"},
			"app-1": {ID: "app-1", Domain: "application"},
		},
	}

	// Test with specific domain
	k8sTemplates, err := sg.GetAvailableTemplates(context.Background(), "k8s")
	require.NoError(t, err)
	assert.Len(t, k8sTemplates, 2)

	// Test with empty domain (all templates)
	allTemplates, err := sg.GetAvailableTemplates(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, allTemplates, 3)
}

func TestProductionStoryGenerator_UpdateTemplate(t *testing.T) {
	sg := &productionStoryGenerator{
		logger:    zap.NewNop(),
		templates: make(map[string]*StoryTemplate),
	}

	template := &StoryTemplate{
		ID:     "test-template",
		Name:   "Test Template",
		Domain: "test",
	}

	err := sg.UpdateTemplate(context.Background(), template)
	require.NoError(t, err)

	stored, exists := sg.templates[template.ID]
	assert.True(t, exists)
	assert.Equal(t, template, stored)

	// Test with empty ID
	emptyTemplate := &StoryTemplate{}
	err = sg.UpdateTemplate(context.Background(), emptyTemplate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template ID is required")
}

func TestProductionStoryGenerator_FindBestTemplate(t *testing.T) {
	sg := &productionStoryGenerator{
		templates: map[string]*StoryTemplate{
			"exact-match": {
				ID:           "exact-match",
				Domain:       "k8s",
				InsightTypes: []string{"resource_exhaustion"},
			},
			"partial-match": {
				ID:           "partial-match",
				Domain:       "k8s",
				InsightTypes: []string{"network_issue"},
			},
		},
	}

	insight := &IntelligenceInsight{
		Type: "resource_exhaustion",
		K8sContext: &K8sContext{
			Namespace: "default",
		},
	}

	template, err := sg.FindBestTemplate(context.Background(), insight)
	require.NoError(t, err)
	assert.Equal(t, "exact-match", template.ID)

	// Test with no matches - should return default
	insight.Type = "unknown_type"
	insight.K8sContext = nil
	template, err = sg.FindBestTemplate(context.Background(), insight)
	require.NoError(t, err)
	assert.Equal(t, "default", template.ID)
}

func TestProductionStoryGenerator_BuildTemplateData(t *testing.T) {
	sg := &productionStoryGenerator{}

	insight := &IntelligenceInsight{
		ID:                 "test-insight",
		Title:              "Test Title",
		Summary:            "Test Summary",
		OverallConfidence:  0.85,
		Timestamp:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		SourceCorrelations: []string{"corr1", "corr2"},
	}

	data := sg.buildTemplateData(insight)

	assert.Equal(t, insight, data["Insight"])
	assert.Equal(t, insight.Title, data["Title"])
	assert.Equal(t, insight.Summary, data["Summary"])
	assert.Equal(t, "85.0%", data["Confidence"])
	assert.Equal(t, "2023-01-01 12:00:00 UTC", data["Timestamp"])
	assert.Equal(t, 2, data["RelatedCount"])
}

func TestProductionStoryGenerator_BuildTimeline(t *testing.T) {
	sg := &productionStoryGenerator{}

	firstSeen := time.Now().Add(-30 * time.Minute)
	insight := &IntelligenceInsight{
		RootCauses: []*RootCause{
			{
				Type:        "memory_leak",
				Description: "Memory leak detected",
				FirstSeen:   firstSeen,
			},
			{
				Type:        "cpu_spike",
				Description: "CPU spike observed",
				FirstSeen:   firstSeen.Add(10 * time.Minute),
			},
		},
	}

	timeline := sg.buildTimeline(insight)

	assert.Len(t, timeline, 2)
	// Should be sorted by timestamp
	assert.True(t, timeline[0].Timestamp.Before(timeline[1].Timestamp))
	assert.Equal(t, "Root Cause Identified", timeline[0].Title)
	assert.Equal(t, "Memory leak detected", timeline[0].Description)
}

func TestProductionStoryGenerator_ExtractKeyPoints(t *testing.T) {
	sg := &productionStoryGenerator{}

	insight := &IntelligenceInsight{
		RootCauses: []*RootCause{
			{Description: "High confidence cause", Confidence: 0.9},
			{Description: "Low confidence cause", Confidence: 0.5},
		},
		ImpactScope: &ImpactScope{
			AffectedServices: []string{"service1", "service2", "service3"},
		},
		Recommendations: []*Recommendation{
			{Action: "fix1"}, {Action: "fix2"},
		},
	}

	keyPoints := sg.extractKeyPoints(insight)

	assert.Contains(t, keyPoints, "High-confidence root cause: High confidence cause")
	assert.NotContains(t, keyPoints, "Low confidence cause") // Below 0.8 threshold
	assert.Contains(t, keyPoints, "Services affected: 3")
	assert.Contains(t, keyPoints, "Available recommendations: 2")
}

// Test Confidence Calculator

func TestProductionConfidenceCalculator_CalculateInsightConfidence(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"weighted_average", "weighted_average"},
		{"bayesian", "bayesian"},
		{"neural_network", "neural_network"},
		{"default", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &productionConfidenceCalculator{
				logger: zap.NewNop(),
				config: &ConfidenceConfiguration{
					Algorithm: tt.algorithm,
				},
				tracer: mockTracer{},
			}

			insight := &IntelligenceInsight{
				ID:   "test-insight",
				Type: "test_type",
				Evidence: []*Evidence{
					{Confidence: 0.8, Weight: 1.0},
					{Confidence: 0.6, Weight: 1.0},
				},
			}

			confidence, err := cc.CalculateInsightConfidence(context.Background(), insight, nil)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, confidence, 0.0)
			assert.LessOrEqual(t, confidence, 1.0)
		})
	}
}

func TestProductionConfidenceCalculator_CalculateWeightedAverage(t *testing.T) {
	cc := &productionConfidenceCalculator{
		config: &ConfidenceConfiguration{
			DiversityBonus:     0.1,
			MissingDataPenalty: 0.15,
		},
	}

	tests := []struct {
		name     string
		insight  *IntelligenceInsight
		expected float64
		delta    float64
	}{
		{
			name: "no evidence",
			insight: &IntelligenceInsight{
				Evidence: []*Evidence{},
			},
			expected: 0.5,
			delta:    0.01,
		},
		{
			name: "weighted evidence",
			insight: &IntelligenceInsight{
				Evidence: []*Evidence{
					{Confidence: 0.8, Weight: 2.0},
					{Confidence: 0.6, Weight: 1.0},
				},
				SourceCorrelations: []string{"c1", "c2"},
			},
			expected: 0.733, // (0.8*2 + 0.6*1) / (2+1) = 2.2/3 = 0.733
			delta:    0.05,
		},
		{
			name: "diversity bonus applied",
			insight: &IntelligenceInsight{
				Evidence: []*Evidence{
					{Confidence: 0.7, Weight: 1.0},
				},
				SourceCorrelations: []string{"c1", "c2", "c3", "c4"}, // > 3, triggers diversity bonus
			},
			expected: 0.8, // 0.7 + 0.1 diversity bonus
			delta:    0.05,
		},
		{
			name: "missing data penalty",
			insight: &IntelligenceInsight{
				Evidence: []*Evidence{
					{Confidence: 0.8, Weight: 1.0},
				}, // < 2 evidence items, triggers penalty
			},
			expected: 0.65, // 0.8 - 0.15 penalty
			delta:    0.05,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, err := cc.calculateWeightedAverage(context.Background(), tt.insight)
			require.NoError(t, err)
			assert.InDelta(t, tt.expected, confidence, tt.delta)
		})
	}
}

func TestProductionConfidenceCalculator_CalculateCorrelationWeight(t *testing.T) {
	cc := &productionConfidenceCalculator{}

	correlation := &correlation.CorrelationResult{
		Type:       "dependency",
		Confidence: 0.8,
		StartTime:  time.Now().Add(-1 * time.Hour),
	}

	criteria := &WeightingCriteria{
		CorrelatorWeights: map[string]float64{
			"dependency": 1.2,
		},
		RecencyHalfLife:       2 * time.Hour,
		RecencyWeightFunction: "exponential",
	}

	weight, err := cc.CalculateCorrelationWeight(context.Background(), correlation, criteria)
	require.NoError(t, err)

	// Base weight 0.8 * correlator weight 1.2 * recency weight (should be > 0.5 for 1 hour age with 2 hour half-life)
	expectedMin := 0.8 * 1.2 * 0.5 // Conservative estimate
	assert.GreaterOrEqual(t, weight, expectedMin)
	assert.LessOrEqual(t, weight, 1.0) // Capped at 1.0
}

func TestProductionConfidenceCalculator_ValidateThresholds(t *testing.T) {
	cc := &productionConfidenceCalculator{}

	insight := &IntelligenceInsight{
		ID:                "test-insight",
		OverallConfidence: 0.85,
		Evidence: []*Evidence{
			{Type: "metric", Confidence: 0.8},
			{Type: "log", Confidence: 0.7},
			{Type: "trace", Confidence: 0.9},
		},
		RootCauses: []*RootCause{
			{Type: "memory_leak", Confidence: 0.8},
			{Type: "cpu_spike", Confidence: 0.6}, // Below threshold
		},
	}

	thresholds := &ConfidenceThresholds{
		MinimumOverallConfidence: 0.8,
		MinimumEvidenceCount:     2,
		RootCauseMinConfidence:   0.7,
	}

	result, err := cc.ValidateThresholds(context.Background(), insight, thresholds)
	require.NoError(t, err)
	assert.NotNil(t, result)

	assert.Equal(t, 0.85, result.OverallConfidence)
	assert.Equal(t, 0.8, result.RequiredThreshold)
	assert.False(t, result.ThresholdMet) // Should fail due to low root cause confidence
	assert.False(t, result.Passed)

	// Check validation details
	assert.Len(t, result.ValidationDetails, 4) // Overall + evidence + 2 root causes

	// Find the failing root cause validation
	var failedRootCause *ValidationDetail
	for _, detail := range result.ValidationDetails {
		if strings.Contains(detail.Component, "root_cause[1]") {
			failedRootCause = detail
			break
		}
	}
	require.NotNil(t, failedRootCause)
	assert.False(t, failedRootCause.Passed)
	assert.Equal(t, 0.6, failedRootCause.Value)
	assert.Equal(t, 0.7, failedRootCause.Threshold)

	assert.NotEmpty(t, result.FailureReasons)
	assert.NotEmpty(t, result.Recommendations)
}

func TestProductionConfidenceCalculator_CalculateRecencyWeight(t *testing.T) {
	cc := &productionConfidenceCalculator{}

	criteria := &WeightingCriteria{
		RecencyHalfLife: 2 * time.Hour,
	}

	tests := []struct {
		name        string
		age         time.Duration
		weightFunc  string
		expectedMin float64
		expectedMax float64
	}{
		{
			name:        "exponential_recent",
			age:         1 * time.Hour, // Half of half-life
			weightFunc:  "exponential",
			expectedMin: 0.7,
			expectedMax: 1.0,
		},
		{
			name:        "exponential_old",
			age:         4 * time.Hour, // Double half-life
			weightFunc:  "exponential",
			expectedMin: 0.2,
			expectedMax: 0.3,
		},
		{
			name:        "linear",
			age:         1 * time.Hour,
			weightFunc:  "linear",
			expectedMin: 0.4,
			expectedMax: 0.6,
		},
		{
			name:        "logarithmic",
			age:         1 * time.Hour,
			weightFunc:  "logarithmic",
			expectedMin: 0.4,
			expectedMax: 0.8,
		},
		{
			name:        "default_to_exponential",
			age:         1 * time.Hour,
			weightFunc:  "unknown",
			expectedMin: 0.7,
			expectedMax: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria.RecencyWeightFunction = tt.weightFunc
			weight := cc.calculateRecencyWeight(tt.age, criteria)
			assert.GreaterOrEqual(t, weight, tt.expectedMin)
			assert.LessOrEqual(t, weight, tt.expectedMax)
		})
	}
}

// Test Pattern Learner

func TestProductionPatternLearner_LearnFromCorrelations(t *testing.T) {
	mockStore := &mockNeo4jIntelligenceStore{}
	pl := &productionPatternLearner{
		logger: zap.NewNop(),
		store:  mockStore,
		config: &PatternLearningConfiguration{
			MinPatternOccurrences: 2,
			MinPatternConfidence:  0.6,
		},
		tracer:   mockTracer{},
		patterns: make(map[string]*LearnedPattern),
	}

	correlations := []*correlation.CorrelationResult{
		{Type: "dependency", Confidence: 0.8},
		{Type: "dependency", Confidence: 0.7}, // Same type, forms group
		{Type: "resource", Confidence: 0.9},   // Different type, alone
	}

	// Mock the store to expect pattern storage
	mockStore.On("StorePattern", mock.Anything, mock.AnythingOfType("*aggregator.LearnedPattern")).Return(nil)

	err := pl.LearnFromCorrelations(context.Background(), correlations)
	require.NoError(t, err)

	// Should have created one pattern (dependency group has 2 items >= MinPatternOccurrences)
	assert.Len(t, pl.patterns, 1)

	// Verify the pattern
	var dependencyPattern *LearnedPattern
	for _, pattern := range pl.patterns {
		if pattern.Name == "Pattern for dependency correlations" {
			dependencyPattern = pattern
			break
		}
	}
	require.NotNil(t, dependencyPattern)
	assert.Equal(t, "statistical", dependencyPattern.Type)
	assert.Equal(t, 2, dependencyPattern.MatchCount)
	assert.GreaterOrEqual(t, dependencyPattern.Confidence, 0.6)

	mockStore.AssertExpectations(t)
}

func TestProductionPatternLearner_UpdateInsightPatterns(t *testing.T) {
	pl := &productionPatternLearner{
		logger:   zap.NewNop(),
		tracer:   mockTracer{},
		patterns: make(map[string]*LearnedPattern),
	}

	// Add a pattern to update
	pattern := &LearnedPattern{
		ID:         "test-pattern",
		Confidence: 0.7,
	}
	pl.patterns[pattern.ID] = pattern

	insights := []*IntelligenceInsight{
		{ID: "insight-1"},
	}

	feedback := []*InsightFeedback{
		{
			InsightID: "insight-1",
			Accuracy:  &[]float64{0.8}[0], // Positive feedback
		},
	}

	err := pl.UpdateInsightPatterns(context.Background(), insights, feedback)
	require.NoError(t, err)

	// Pattern confidence should be adjusted upward
	assert.Greater(t, pl.patterns[pattern.ID].Confidence, 0.7)
}

func TestProductionPatternLearner_GetLearnedPatterns(t *testing.T) {
	pl := &productionPatternLearner{
		patterns: map[string]*LearnedPattern{
			"k8s-1": {ID: "k8s-1", Domain: "k8s"},
			"k8s-2": {ID: "k8s-2", Domain: "k8s"},
			"app-1": {ID: "app-1", Domain: "application"},
		},
	}

	// Test with specific domain
	k8sPatterns, err := pl.GetLearnedPatterns(context.Background(), "k8s")
	require.NoError(t, err)
	assert.Len(t, k8sPatterns, 2)

	// Test with empty domain (all patterns)
	allPatterns, err := pl.GetLearnedPatterns(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, allPatterns, 3)
}

func TestProductionPatternLearner_ExportPatterns(t *testing.T) {
	pl := &productionPatternLearner{
		patterns: map[string]*LearnedPattern{
			"pattern-1": {ID: "pattern-1", Name: "Test Pattern"},
		},
	}

	export, err := pl.ExportPatterns(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, export)
	assert.Equal(t, "1.0", export.Version)
	assert.Len(t, export.Patterns, 1)
	assert.Equal(t, "pattern-learner", export.ExportedBy)
	assert.WithinDuration(t, time.Now(), export.ExportedAt, 5*time.Second)
}

func TestProductionPatternLearner_LearnFromFeedback(t *testing.T) {
	pl := &productionPatternLearner{
		logger:   zap.NewNop(),
		tracer:   mockTracer{},
		patterns: make(map[string]*LearnedPattern),
	}

	feedback := &InsightFeedback{
		InsightID: "test-insight",
		Accuracy:  &[]float64{0.9}[0], // Very positive feedback
	}

	result, err := pl.LearnFromFeedback(context.Background(), feedback)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, result.PatternsUpdated)
	assert.WithinDuration(t, time.Now(), result.LearningTime, 5*time.Second)
	assert.WithinDuration(t, time.Now(), result.EffectiveAt, 5*time.Second)
}

func TestProductionPatternLearner_MatchPatterns(t *testing.T) {
	pl := &productionPatternLearner{
		patterns: map[string]*LearnedPattern{
			"dependency-pattern": {
				ID: "dependency-pattern",
				Conditions: []*PatternCondition{
					{
						Field:    "type",
						Operator: "equals",
						Value:    "dependency",
						Required: true,
					},
				},
			},
		},
	}

	// Test matching correlation
	matchingCorr := &correlation.CorrelationResult{
		Type:       "dependency",
		Confidence: 0.8,
	}

	matches, err := pl.MatchPatterns(context.Background(), matchingCorr)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "dependency-pattern", matches[0].ID)

	// Test non-matching correlation
	nonMatchingCorr := &correlation.CorrelationResult{
		Type:       "resource",
		Confidence: 0.8,
	}

	matches, err = pl.MatchPatterns(context.Background(), nonMatchingCorr)
	require.NoError(t, err)
	assert.Len(t, matches, 0)
}

func TestProductionPatternLearner_ImportPattern(t *testing.T) {
	mockStore := &mockNeo4jIntelligenceStore{}
	pl := &productionPatternLearner{
		store:    mockStore,
		patterns: make(map[string]*LearnedPattern),
	}

	pattern := &LearnedPattern{
		ID:   "imported-pattern",
		Name: "Imported Pattern",
	}

	mockStore.On("StorePattern", mock.Anything, pattern).Return(nil)

	err := pl.ImportPattern(context.Background(), pattern)
	require.NoError(t, err)

	// Pattern should be stored in memory
	stored, exists := pl.patterns[pattern.ID]
	assert.True(t, exists)
	assert.Equal(t, pattern, stored)

	mockStore.AssertExpectations(t)
}

func TestProductionPatternLearner_GroupSimilarCorrelations(t *testing.T) {
	pl := &productionPatternLearner{}

	correlations := []*correlation.CorrelationResult{
		{Type: "dependency"},
		{Type: "dependency"},
		{Type: "resource"},
		{Type: "network"},
		{Type: "network"},
		{Type: "network"},
	}

	groups := pl.groupSimilarCorrelations(correlations)

	assert.Len(t, groups, 3) // dependency, resource, network

	// Find the network group (should be largest)
	var networkGroup []*correlation.CorrelationResult
	for _, group := range groups {
		if len(group) == 3 {
			networkGroup = group
			break
		}
	}
	require.NotNil(t, networkGroup)

	for _, corr := range networkGroup {
		assert.Equal(t, "network", corr.Type)
	}
}

func TestProductionPatternLearner_EvaluateCondition(t *testing.T) {
	pl := &productionPatternLearner{}

	corr := &correlation.CorrelationResult{
		Type:       "dependency",
		Confidence: 0.8,
	}

	tests := []struct {
		name      string
		condition *PatternCondition
		expected  bool
	}{
		{
			name: "type_match",
			condition: &PatternCondition{
				Field: "type",
				Value: "dependency",
			},
			expected: true,
		},
		{
			name: "type_no_match",
			condition: &PatternCondition{
				Field: "type",
				Value: "resource",
			},
			expected: false,
		},
		{
			name: "confidence_greater_than",
			condition: &PatternCondition{
				Field:    "confidence",
				Operator: "greater_than",
				Value:    0.7,
			},
			expected: true,
		},
		{
			name: "confidence_less_than",
			condition: &PatternCondition{
				Field:    "confidence",
				Operator: "less_than",
				Value:    0.9,
			},
			expected: true,
		},
		{
			name: "confidence_equals",
			condition: &PatternCondition{
				Field:    "confidence",
				Operator: "equals",
				Value:    0.8,
			},
			expected: true,
		},
		{
			name: "unknown_field",
			condition: &PatternCondition{
				Field: "unknown",
				Value: "anything",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pl.evaluateCondition(corr, tt.condition)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test Utility Functions

func TestGenerateStoryID(t *testing.T) {
	id1 := generateStoryID()
	id2 := generateStoryID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Contains(t, id1, "story-")
}

func TestGeneratePatternID(t *testing.T) {
	id1 := generatePatternID()
	id2 := generatePatternID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Contains(t, id1, "pattern-")
	assert.Len(t, strings.Split(id1, "-")[1], 16) // Should be 16 hex chars
}

// Helper mock tracer for testing
type mockTracer struct{}

func (m mockTracer) Start(ctx context.Context, spanName string, opts ...interface{}) (context.Context, mockSpan) {
	return ctx, mockSpan{}
}

type mockSpan struct{}

func (m mockSpan) End(options ...interface{})                     {}
func (m mockSpan) AddEvent(name string, options ...interface{})   {}
func (m mockSpan) IsRecording() bool                              { return false }
func (m mockSpan) RecordError(err error, options ...interface{})  {}
func (m mockSpan) SpanContext() interface{}                       { return nil }
func (m mockSpan) SetStatus(code interface{}, description string) {}
func (m mockSpan) SetName(name string)                            {}
func (m mockSpan) SetAttributes(kv ...interface{})                {}
func (m mockSpan) TracerProvider() interface{}                    { return nil }
