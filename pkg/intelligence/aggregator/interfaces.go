package aggregator

import (
	"context"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/intelligence/correlation"
)

// IntelligenceAggregator processes multiple correlation results into validated insights
type IntelligenceAggregator interface {
	// Core processing methods
	AggregateCorrelations(ctx context.Context, correlations []*correlation.CorrelationResult) ([]*IntelligenceInsight, error)
	ProcessBatch(ctx context.Context, batch *CorrelationBatch) (*BatchProcessingResult, error)
	ProcessStream(ctx context.Context, stream <-chan *correlation.CorrelationResult) <-chan *IntelligenceInsight

	// Configuration and tuning
	SetConfiguration(ctx context.Context, config *AggregatorConfiguration) error
	GetConfiguration(ctx context.Context) (*AggregatorConfiguration, error)
	ValidateConfiguration(ctx context.Context, config *AggregatorConfiguration) (*ConfigValidationResult, error)
	ReloadConfiguration(ctx context.Context) error

	// Historical data and learning
	GetInsightHistory(ctx context.Context, query *InsightQuery) (*InsightHistoryResult, error)
	LearnFromFeedback(ctx context.Context, feedback *InsightFeedback) (*LearningResult, error)
	ExportPatterns(ctx context.Context, domain string) (*PatternExport, error)
	ImportPatterns(ctx context.Context, patterns *PatternImport) (*ImportResult, error)

	// Health and monitoring
	GetHealth(ctx context.Context) (*AggregatorHealth, error)
	GetMetrics(ctx context.Context) (*AggregatorMetrics, error)
	GetPerformanceStats(ctx context.Context, window time.Duration) (*PerformanceStats, error)

	// Lifecycle management
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// StoryGenerator creates human-readable narratives from technical correlations
type StoryGenerator interface {
	// GenerateStory creates a compelling narrative from insight data
	GenerateStory(ctx context.Context, insight *IntelligenceInsight, template *StoryTemplate) (*Story, error)

	// GetAvailableTemplates returns all configured story templates
	GetAvailableTemplates(ctx context.Context, domain string) ([]*StoryTemplate, error)

	// UpdateTemplate dynamically updates story templates
	UpdateTemplate(ctx context.Context, template *StoryTemplate) error

	// FindBestTemplate finds the best template for an insight
	FindBestTemplate(ctx context.Context, insight *IntelligenceInsight) (*StoryTemplate, error)
}

// ConfidenceCalculator computes confidence scores using configurable algorithms
type ConfidenceCalculator interface {
	// CalculateInsightConfidence computes overall confidence for an insight
	CalculateInsightConfidence(ctx context.Context, insight *IntelligenceInsight, rules *ConfidenceRules) (float64, error)

	// CalculateCorrelationWeight determines how much each correlation contributes
	CalculateCorrelationWeight(ctx context.Context, correlation *correlation.CorrelationResult, criteria *WeightingCriteria) (float64, error)

	// ValidateThresholds checks if insight meets configured confidence thresholds
	ValidateThresholds(ctx context.Context, insight *IntelligenceInsight, thresholds *ConfidenceThresholds) (*ValidationResult, error)

	// CalculateCorrelationConfidence calculates confidence for correlation with patterns
	CalculateCorrelationConfidence(ctx context.Context, corr *correlation.CorrelationResult, patterns []*LearnedPattern) (float64, error)
}

// PatternLearner adapts intelligence patterns over time
type PatternLearner interface {
	// LearnFromCorrelations updates patterns based on new correlation data
	LearnFromCorrelations(ctx context.Context, correlations []*correlation.CorrelationResult) error

	// UpdateInsightPatterns refines insight generation patterns
	UpdateInsightPatterns(ctx context.Context, insights []*IntelligenceInsight, feedback []*InsightFeedback) error

	// GetLearnedPatterns returns currently learned patterns
	GetLearnedPatterns(ctx context.Context, domain string) ([]*LearnedPattern, error)

	// ExportPatterns exports patterns for backup or transfer
	ExportPatterns(ctx context.Context) (*PatternExport, error)

	// LearnFromFeedback learns from specific feedback
	LearnFromFeedback(ctx context.Context, feedback *InsightFeedback) (*LearningResult, error)

	// MatchPatterns matches correlation against learned patterns
	MatchPatterns(ctx context.Context, corr *correlation.CorrelationResult) ([]*LearnedPattern, error)

	// ImportPattern imports a single pattern
	ImportPattern(ctx context.Context, pattern *LearnedPattern) error
}

// RulesEngine manages configurable intelligence rules
type RulesEngine interface {
	// EvaluateRules applies configured rules to determine insight validity
	EvaluateRules(ctx context.Context, insight *IntelligenceInsight, ruleset *IntelligenceRuleset) (*RuleEvaluationResult, error)

	// UpdateRules dynamically updates rule configuration
	UpdateRules(ctx context.Context, rules []*IntelligenceRule) error

	// GetActiveRules returns currently active rules for a domain
	GetActiveRules(ctx context.Context, domain string) ([]*IntelligenceRule, error)

	// ValidateInsight validates insight against rules
	ValidateInsight(ctx context.Context, insight *IntelligenceInsight) (*RuleValidationResult, error)

	// ProcessRules processes rules on insight
	ProcessRules(ctx context.Context, insight *IntelligenceInsight) (*RuleProcessingResult, error)

	// UpdateRule updates a single rule
	UpdateRule(ctx context.Context, rule *Rule) error

	// ImportRule imports a rule
	ImportRule(ctx context.Context, rule *Rule) error
}

// PluginIntegrator handles integration with observability platforms
type PluginIntegrator interface {
	// Plugin management
	RegisterPlugin(ctx context.Context, plugin *ObservabilityPlugin) error
	UnregisterPlugin(ctx context.Context, pluginID string) error
	GetRegisteredPlugins(ctx context.Context) ([]*ObservabilityPlugin, error)

	// Insight delivery
	SendInsight(ctx context.Context, insight *IntelligenceInsight, targets []string) (*DeliveryResult, error)
	SendBatchInsights(ctx context.Context, insights []*IntelligenceInsight, targets []string) (*BatchDeliveryResult, error)

	// Format and capability discovery
	GetSupportedFormats(ctx context.Context, pluginID string) ([]string, error)
	GetPluginCapabilities(ctx context.Context, pluginID string) (*PluginCapabilities, error)

	// Health and monitoring
	TestPlugin(ctx context.Context, pluginID string) (*PluginTestResult, error)
	GetPluginHealth(ctx context.Context) (map[string]*PluginHealth, error)
}

// Neo4jIntelligenceStore manages intelligence data in Neo4j
type Neo4jIntelligenceStore interface {
	// Insight storage and retrieval
	StoreInsight(ctx context.Context, insight *IntelligenceInsight) (*StorageResult, error)
	GetInsight(ctx context.Context, insightID string) (*IntelligenceInsight, error)
	QueryInsights(ctx context.Context, query *InsightQuery) (*InsightQueryResult, error)
	DeleteInsight(ctx context.Context, insightID string) error

	// Pattern management
	StorePattern(ctx context.Context, pattern *LearnedPattern) error
	QueryPatterns(ctx context.Context, query *PatternQuery) ([]*StoredPattern, error)
	UpdatePatternConfidence(ctx context.Context, patternID string, adjustment float64, reason string) error
	DeletePattern(ctx context.Context, patternID string) error

	// Configuration storage
	StoreConfiguration(ctx context.Context, config *StoredConfiguration) error
	GetConfiguration(ctx context.Context, configID string) (*StoredConfiguration, error)
	ListConfigurations(ctx context.Context, domain string) ([]*StoredConfiguration, error)

	// Historical context and analytics
	GetHistoricalContext(ctx context.Context, query *ContextQuery) (*HistoricalContext, error)
	GetInsightTrends(ctx context.Context, query *TrendQuery) (*TrendAnalysis, error)
	GetPatternUsageStats(ctx context.Context, patternID string, window time.Duration) (*PatternUsageStats, error)

	// Relationship analysis
	AnalyzeInsightRelationships(ctx context.Context, insightID string, depth int) (*RelationshipGraph, error)
	FindSimilarInsights(ctx context.Context, insight *IntelligenceInsight, threshold float64) ([]*IntelligenceInsight, error)

	// Maintenance and cleanup
	CleanupOldInsights(ctx context.Context, retentionPolicy *RetentionPolicy) (*CleanupResult, error)
	OptimizeStorage(ctx context.Context) (*OptimizationResult, error)

	// Transaction support
	BeginTransaction(ctx context.Context) (IntelligenceTransaction, error)

	// Health and monitoring
	GetStorageHealth(ctx context.Context) (*StorageHealth, error)
	GetStorageMetrics(ctx context.Context) (*StorageMetrics, error)
}

// IntelligenceInsight represents the output of intelligence aggregation
type IntelligenceInsight struct {
	// Core identification
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "root_cause", "impact_analysis", "predictive", "anomaly"
	Title     string    `json:"title"`
	Timestamp time.Time `json:"timestamp"`

	// Intelligence data
	Summary          string            `json:"summary"`
	DetailedAnalysis string            `json:"detailed_analysis"`
	RootCauses       []*RootCause      `json:"root_causes"`
	ImpactScope      *ImpactScope      `json:"impact_scope"`
	Recommendations  []*Recommendation `json:"recommendations"`

	// Evidence and confidence
	Evidence          []*Evidence        `json:"evidence"`
	OverallConfidence float64            `json:"overall_confidence"`
	ComponentScores   map[string]float64 `json:"component_scores"`

	// Source correlations
	SourceCorrelations []*CorrelationReference `json:"source_correlations"`
	DominantPattern    *PatternReference       `json:"dominant_pattern,omitempty"`

	// Context and relationships
	K8sContext      *domain.K8sContext `json:"k8s_context,omitempty"`
	BusinessContext *BusinessContext   `json:"business_context,omitempty"`
	RelatedInsights []string           `json:"related_insights"`

	// Storytelling
	Story *Story `json:"story,omitempty"`

	// Metadata
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	ExternalReferences []*ExternalReference   `json:"external_references,omitempty"`
}

// AggregatorConfiguration holds all configurable parameters
type AggregatorConfiguration struct {
	// Core processing settings
	Processing      *ProcessingConfiguration      `json:"processing"`
	Confidence      *ConfidenceConfiguration      `json:"confidence"`
	StoryGeneration *StoryGenerationConfiguration `json:"story_generation"`

	// Intelligence rules
	Rules             []*IntelligenceRule   `json:"rules"`
	Thresholds        *ConfidenceThresholds `json:"thresholds"`
	WeightingCriteria *WeightingCriteria    `json:"weighting_criteria"`

	// Pattern learning settings
	PatternLearning *PatternLearningConfiguration `json:"pattern_learning"`

	// Plugin configuration
	Plugins map[string]*PluginConfiguration `json:"plugins"`

	// Neo4j storage settings
	Storage *StorageConfiguration `json:"storage"`

	// Domain-specific configurations
	DomainConfigs map[string]*DomainConfiguration `json:"domain_configs"`
}

// ProcessingConfiguration controls core processing behavior
type ProcessingConfiguration struct {
	// Buffer and batch settings
	MaxCorrelationsPerBatch  int           `json:"max_correlations_per_batch"`
	BatchProcessingTimeout   time.Duration `json:"batch_processing_timeout"`
	InsightGenerationTimeout time.Duration `json:"insight_generation_timeout"`

	// Quality control
	RequireMinimumEvidence   bool          `json:"require_minimum_evidence"`
	MinimumEvidenceCount     int           `json:"minimum_evidence_count"`
	EnableDuplicateDetection bool          `json:"enable_duplicate_detection"`
	DuplicateTimeWindow      time.Duration `json:"duplicate_time_window"`

	// Performance settings
	MaxConcurrentProcessing int           `json:"max_concurrent_processing"`
	MemoryLimitMB           int           `json:"memory_limit_mb"`
	EnableCaching           bool          `json:"enable_caching"`
	CacheRetentionTime      time.Duration `json:"cache_retention_time"`
}

// ConfidenceConfiguration defines confidence calculation parameters
type ConfidenceConfiguration struct {
	// Confidence algorithm selection
	Algorithm string `json:"algorithm"` // "weighted_average", "bayesian", "neural_network"

	// Weighting factors for different evidence types
	CorrelationWeights    map[string]float64 `json:"correlation_weights"`
	PatternMatchWeights   map[string]float64 `json:"pattern_match_weights"`
	HistoricalDataWeights map[string]float64 `json:"historical_data_weights"`

	// Adjustment factors
	RecencyFactor   float64 `json:"recency_factor"`
	FrequencyFactor float64 `json:"frequency_factor"`
	DiversityBonus  float64 `json:"diversity_bonus"`

	// Penalties for uncertainty
	MissingDataPenalty         float64 `json:"missing_data_penalty"`
	ConflictingEvidencePenalty float64 `json:"conflicting_evidence_penalty"`

	// Dynamic adjustment settings
	EnableLearningAdjustment bool    `json:"enable_learning_adjustment"`
	LearningRate             float64 `json:"learning_rate"`
}

// InsightQuery defines parameters for querying historical insights
type InsightQuery struct {
	// Time range
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	// Filtering criteria
	Types           []string `json:"types,omitempty"`
	MinConfidence   *float64 `json:"min_confidence,omitempty"`
	K8sNamespace    string   `json:"k8s_namespace,omitempty"`
	K8sResourceType string   `json:"k8s_resource_type,omitempty"`

	// Result constraints
	Limit          int    `json:"limit,omitempty"`
	Offset         int    `json:"offset,omitempty"`
	OrderBy        string `json:"order_by,omitempty"`        // "timestamp", "confidence", "relevance"
	OrderDirection string `json:"order_direction,omitempty"` // "asc", "desc"

	// Enhanced filtering
	MaxConfidence      *float64          `json:"max_confidence,omitempty"`
	K8sCluster         string            `json:"k8s_cluster,omitempty"`
	Severity           []string          `json:"severity,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	SearchText         string            `json:"search_text,omitempty"`
	RootCauseTypes     []string          `json:"root_cause_types,omitempty"`
	HasRecommendations bool              `json:"has_recommendations,omitempty"`
	IncludeMetadata    bool              `json:"include_metadata,omitempty"`
	IncludeEvidence    bool              `json:"include_evidence,omitempty"`
	GroupBy            string            `json:"group_by,omitempty"`
}

// Additional interface definitions for complete system

// CircuitBreaker provides fault tolerance for external dependencies
type CircuitBreaker interface {
	Execute(ctx context.Context, operation func(ctx context.Context) (interface{}, error)) (interface{}, error)
	GetState() CircuitBreakerState
	GetMetrics() *CircuitBreakerMetrics
	Reset() error
}

// WorkerPool manages concurrent processing
type WorkerPool interface {
	Submit(ctx context.Context, task Task) error
	SubmitBatch(ctx context.Context, tasks []Task) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	GetStats() *WorkerPoolStats
	Resize(newSize int) error
}

// CacheManager handles intelligent caching
type CacheManager interface {
	Get(ctx context.Context, key string) (interface{}, bool)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	GetStats() *CacheStats
}

// RateLimiter controls processing rates
type RateLimiter interface {
	Allow() bool
	AllowN(n int) bool
	Wait(ctx context.Context) error
	WaitN(ctx context.Context, n int) error
	GetRate() float64
	SetRate(rate float64) error
}

// IntelligenceTransaction provides transactional intelligence operations
type IntelligenceTransaction interface {
	StoreInsight(ctx context.Context, insight *IntelligenceInsight) error
	UpdatePattern(ctx context.Context, pattern *LearnedPattern) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}
