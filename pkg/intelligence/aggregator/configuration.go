package aggregator

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Configuration manager types and implementations

// StoryGenerationConfiguration controls story generation behavior
type StoryGenerationConfiguration struct {
	// Template management
	DefaultTemplateDirectory  string        `json:"default_template_directory"`
	CustomTemplateDirectories []string      `json:"custom_template_directories"`
	TemplateRefreshInterval   time.Duration `json:"template_refresh_interval"`

	// Generation settings
	MaxStoryLength         int    `json:"max_story_length"`
	EnableTechnicalDetails bool   `json:"enable_technical_details"`
	DefaultAudience        string `json:"default_audience"`
	DefaultFormat          string `json:"default_format"`

	// Language and style
	ToneConfiguration *ToneConfiguration `json:"tone_configuration"`

	// Performance
	GenerationTimeout     time.Duration `json:"generation_timeout"`
	ConcurrentGenerations int           `json:"concurrent_generations"`
	EnableCaching         bool          `json:"enable_caching"`
	CacheRetentionTime    time.Duration `json:"cache_retention_time"`
}

// PatternLearningConfiguration controls pattern learning behavior
type PatternLearningConfiguration struct {
	// Learning algorithms
	EnabledAlgorithms []string `json:"enabled_algorithms"` // "statistical", "neural", "rule_based"

	// Pattern discovery
	MinPatternOccurrences int           `json:"min_pattern_occurrences"`
	MinPatternConfidence  float64       `json:"min_pattern_confidence"`
	MaxPatternsPerDomain  int           `json:"max_patterns_per_domain"`
	PatternExpirationTime time.Duration `json:"pattern_expiration_time"`

	// Learning rates
	BaselineLearningRate float64 `json:"baseline_learning_rate"`
	AdaptiveLearningRate bool    `json:"adaptive_learning_rate"`
	FeedbackLearningRate float64 `json:"feedback_learning_rate"`

	// Validation settings
	RequireValidation    bool    `json:"require_validation"`
	ValidationThreshold  float64 `json:"validation_threshold"`
	CrossValidationFolds int     `json:"cross_validation_folds"`

	// Performance settings
	LearningScheduleInterval time.Duration `json:"learning_schedule_interval"`
	MaxLearningMemoryMB      int           `json:"max_learning_memory_mb"`
	EnableBackgroundLearning bool          `json:"enable_background_learning"`
}

// PluginConfiguration defines plugin-specific settings
type PluginConfiguration struct {
	// Basic configuration
	Name     string `json:"name"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`

	// Connection settings
	EndpointURL string `json:"endpoint_url,omitempty"`
	APIKey      string `json:"api_key,omitempty"`
	AuthMethod  string `json:"auth_method,omitempty"` // "api_key", "oauth", "token"

	// Format configuration
	OutputFormat string            `json:"output_format"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
	FieldMapping map[string]string `json:"field_mapping,omitempty"`

	// Delivery settings
	DeliveryMethod  string             `json:"delivery_method"` // "push", "pull", "webhook"
	DeliveryTimeout time.Duration      `json:"delivery_timeout"`
	RetryPolicy     *RetryPolicyConfig `json:"retry_policy,omitempty"`

	// Filtering
	InsightFilters []*InsightFilter `json:"insight_filters,omitempty"`

	// Custom configuration
	CustomConfig map[string]interface{} `json:"custom_config,omitempty"`
}

// StorageConfiguration controls Neo4j and storage behavior
type StorageConfiguration struct {
	// Neo4j connection
	Neo4jURI      string `json:"neo4j_uri"`
	Neo4jUsername string `json:"neo4j_username"`
	Neo4jPassword string `json:"neo4j_password"`
	Neo4jDatabase string `json:"neo4j_database"`

	// Connection pool settings
	MaxConnections    int           `json:"max_connections"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	IdleTimeout       time.Duration `json:"idle_timeout"`

	// Storage policies
	InsightRetention  time.Duration `json:"insight_retention"`
	PatternRetention  time.Duration `json:"pattern_retention"`
	FeedbackRetention time.Duration `json:"feedback_retention"`

	// Indexing strategy
	IndexConfiguration *IndexConfiguration `json:"index_configuration"`

	// Backup settings
	BackupConfiguration *BackupConfiguration `json:"backup_configuration,omitempty"`

	// Performance tuning
	BatchSize        int           `json:"batch_size"`
	WriteTimeout     time.Duration `json:"write_timeout"`
	QueryTimeout     time.Duration `json:"query_timeout"`
	EnableQueryCache bool          `json:"enable_query_cache"`
	CacheSize        int           `json:"cache_size"`
}

// DomainConfiguration allows domain-specific customization
type DomainConfiguration struct {
	// Basic domain settings
	Domain      string `json:"domain"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`

	// Domain-specific thresholds
	ConfidenceThresholds *ConfidenceThresholds `json:"confidence_thresholds"`
	WeightingCriteria    *WeightingCriteria    `json:"weighting_criteria"`

	// Rules and patterns
	DomainRules       []*IntelligenceRule `json:"domain_rules"`
	PreloadedPatterns []*LearnedPattern   `json:"preloaded_patterns"`

	// Story generation
	StoryTemplates       []*StoryTemplate `json:"story_templates"`
	DefaultStoryTemplate string           `json:"default_story_template"`

	// Integration settings
	PluginOverrides map[string]*PluginConfiguration `json:"plugin_overrides,omitempty"`

	// Learning settings
	LearningOverrides *PatternLearningConfiguration `json:"learning_overrides,omitempty"`
}

// Supporting configuration types

// ToneConfiguration defines story generation tone and style
type ToneConfiguration struct {
	TechnicalTone   string            `json:"technical_tone"` // "formal", "casual", "detailed"
	BusinessTone    string            `json:"business_tone"`  // "executive", "operational", "analytical"
	UrgencyTone     map[string]string `json:"urgency_tone"`   // Maps severity to tone
	CustomToneRules []string          `json:"custom_tone_rules"`
	LanguageLocale  string            `json:"language_locale"`
}

// RetryPolicyConfig defines retry behavior for plugin integrations
type RetryPolicyConfig struct {
	MaxRetries        int           `json:"max_retries"`
	InitialDelay      time.Duration `json:"initial_delay"`
	BackoffMultiplier float64       `json:"backoff_multiplier"`
	MaxDelay          time.Duration `json:"max_delay"`
	RetryableErrors   []string      `json:"retryable_errors"`
}

// InsightFilter defines filtering rules for plugin delivery
type InsightFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "equals", "contains", "greater", "less"
	Value    interface{} `json:"value"`
	Include  bool        `json:"include"` // true=include, false=exclude
}

// IndexConfiguration defines Neo4j indexing strategy
type IndexConfiguration struct {
	// Core indexes
	CreateNodeIndexes         bool `json:"create_node_indexes"`
	CreateRelationshipIndexes bool `json:"create_relationship_indexes"`

	// Custom indexes
	CustomNodeIndexes []string `json:"custom_node_indexes"`
	CustomRelIndexes  []string `json:"custom_rel_indexes"`

	// Index maintenance
	RebuildInterval   time.Duration `json:"rebuild_interval"`
	OptimizeOnStartup bool          `json:"optimize_on_startup"`
}

// BackupConfiguration defines backup strategy
type BackupConfiguration struct {
	Enabled         bool          `json:"enabled"`
	BackupInterval  time.Duration `json:"backup_interval"`
	RetentionPeriod time.Duration `json:"retention_period"`
	BackupLocation  string        `json:"backup_location"`
	BackupFormat    string        `json:"backup_format"`
	EncryptionKey   string        `json:"encryption_key,omitempty"`
}

// Configuration loading and validation

// LoadConfiguration loads configuration from multiple sources with precedence:
// 1. Environment variables (highest)
// 2. Configuration file
// 3. Default values (lowest)
func LoadConfiguration(configPath string) (*AggregatorConfiguration, error) {
	// Start with default configuration
	config := DefaultConfiguration()

	// Load from file if provided
	if configPath != "" {
		fileConfig, err := loadConfigFromFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
		config = mergeConfigurations(config, fileConfig)
	}

	// Override with environment variables
	envConfig := loadConfigFromEnv()
	config = mergeConfigurations(config, envConfig)

	// Validate the final configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// DefaultConfiguration returns a fully configured default configuration
func DefaultConfiguration() *AggregatorConfiguration {
	return &AggregatorConfiguration{
		Processing: &ProcessingConfiguration{
			MaxCorrelationsPerBatch:  100,
			BatchProcessingTimeout:   30 * time.Second,
			InsightGenerationTimeout: 60 * time.Second,
			RequireMinimumEvidence:   true,
			MinimumEvidenceCount:     3,
			EnableDuplicateDetection: true,
			DuplicateTimeWindow:      30 * time.Minute,
			MaxConcurrentProcessing:  10,
			MemoryLimitMB:            1024,
			EnableCaching:            true,
			CacheRetentionTime:       24 * time.Hour,
		},

		Confidence: &ConfidenceConfiguration{
			Algorithm: "weighted_average",
			CorrelationWeights: map[string]float64{
				"temporal":   0.8,
				"dependency": 0.9,
				"ownership":  0.7,
				"config":     0.6,
				"servicemap": 0.8,
			},
			PatternMatchWeights: map[string]float64{
				"exact":       1.0,
				"partial":     0.7,
				"statistical": 0.5,
			},
			HistoricalDataWeights: map[string]float64{
				"recent": 1.0,
				"medium": 0.8,
				"old":    0.6,
			},
			RecencyFactor:              0.1,
			FrequencyFactor:            0.2,
			DiversityBonus:             0.1,
			MissingDataPenalty:         0.2,
			ConflictingEvidencePenalty: 0.3,
			EnableLearningAdjustment:   true,
			LearningRate:               0.01,
		},

		StoryGeneration: &StoryGenerationConfiguration{
			DefaultTemplateDirectory:  "/etc/tapio/templates",
			CustomTemplateDirectories: []string{"/opt/tapio/custom-templates"},
			TemplateRefreshInterval:   1 * time.Hour,
			MaxStoryLength:            10000,
			EnableTechnicalDetails:    true,
			DefaultAudience:           "technical",
			DefaultFormat:             "markdown",
			ToneConfiguration: &ToneConfiguration{
				TechnicalTone: "detailed",
				BusinessTone:  "operational",
				UrgencyTone: map[string]string{
					"critical": "urgent",
					"high":     "serious",
					"medium":   "concerned",
					"low":      "informational",
				},
				LanguageLocale: "en-US",
			},
			GenerationTimeout:     30 * time.Second,
			ConcurrentGenerations: 5,
			EnableCaching:         true,
			CacheRetentionTime:    6 * time.Hour,
		},

		Rules: getDefaultRules(),

		Thresholds: &ConfidenceThresholds{
			MinimumOverallConfidence:    0.7,
			MinimumPublishConfidence:    0.8,
			MinimumActionConfidence:     0.9,
			RootCauseMinConfidence:      0.75,
			RecommendationMinConfidence: 0.8,
			PatternMatchMinConfidence:   0.6,
			MinimumEvidenceCount:        3,
			MinimumEvidenceWeight:       0.5,
			RequiredEvidenceTypes:       []string{"event", "correlation"},
			DomainThresholds: map[string]float64{
				"k8s":            0.7,
				"infrastructure": 0.75,
				"application":    0.8,
			},
			SeverityThresholds: map[string]float64{
				"critical": 0.9,
				"high":     0.8,
				"medium":   0.7,
				"low":      0.6,
			},
		},

		WeightingCriteria: &WeightingCriteria{
			CorrelatorWeights: map[string]float64{
				"temporal":   0.8,
				"dependency": 0.9,
				"ownership":  0.7,
				"config":     0.6,
				"servicemap": 0.8,
				"sequence":   0.75,
			},
			EvidenceTypeWeights: map[string]float64{
				"event":       1.0,
				"metric":      0.9,
				"log":         0.8,
				"pattern":     0.85,
				"correlation": 0.95,
			},
			RecencyWeightFunction:   "exponential",
			RecencyHalfLife:         24 * time.Hour,
			FrequencyWeightCap:      2.0,
			FrequencyWeightFunction: "logarithmic",
			SourceReputationWeights: map[string]float64{
				"kubernetes": 1.0,
				"prometheus": 0.95,
				"logs":       0.85,
				"custom":     0.8,
			},
			DataQualityWeights: map[string]float64{
				"complete":  1.0,
				"partial":   0.8,
				"estimated": 0.6,
			},
		},

		PatternLearning: &PatternLearningConfiguration{
			EnabledAlgorithms:        []string{"statistical", "rule_based"},
			MinPatternOccurrences:    5,
			MinPatternConfidence:     0.7,
			MaxPatternsPerDomain:     1000,
			PatternExpirationTime:    30 * 24 * time.Hour, // 30 days
			BaselineLearningRate:     0.01,
			AdaptiveLearningRate:     true,
			FeedbackLearningRate:     0.05,
			RequireValidation:        true,
			ValidationThreshold:      0.8,
			CrossValidationFolds:     5,
			LearningScheduleInterval: 6 * time.Hour,
			MaxLearningMemoryMB:      512,
			EnableBackgroundLearning: true,
		},

		Plugins: getDefaultPluginConfigurations(),

		Storage: &StorageConfiguration{
			Neo4jURI:          getEnvString("NEO4J_URI", "bolt://localhost:7687"),
			Neo4jUsername:     getEnvString("NEO4J_USERNAME", "neo4j"),
			Neo4jPassword:     getEnvString("NEO4J_PASSWORD", "password"),
			Neo4jDatabase:     getEnvString("NEO4J_DATABASE", "neo4j"),
			MaxConnections:    10,
			ConnectionTimeout: 30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			InsightRetention:  90 * 24 * time.Hour,  // 90 days
			PatternRetention:  180 * 24 * time.Hour, // 180 days
			FeedbackRetention: 365 * 24 * time.Hour, // 1 year
			IndexConfiguration: &IndexConfiguration{
				CreateNodeIndexes:         true,
				CreateRelationshipIndexes: true,
				CustomNodeIndexes:         []string{},
				CustomRelIndexes:          []string{},
				RebuildInterval:           7 * 24 * time.Hour, // weekly
				OptimizeOnStartup:         true,
			},
			BatchSize:        1000,
			WriteTimeout:     30 * time.Second,
			QueryTimeout:     60 * time.Second,
			EnableQueryCache: true,
			CacheSize:        10000,
		},

		DomainConfigs: getDefaultDomainConfigurations(),
	}
}

// loadConfigFromFile loads configuration from a JSON file
func loadConfigFromFile(path string) (*AggregatorConfiguration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config AggregatorConfiguration
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// loadConfigFromEnv loads configuration overrides from environment variables
func loadConfigFromEnv() *AggregatorConfiguration {
	config := &AggregatorConfiguration{}

	// Processing configuration
	if val := os.Getenv("AGGREGATOR_MAX_CORRELATIONS_PER_BATCH"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			if config.Processing == nil {
				config.Processing = &ProcessingConfiguration{}
			}
			config.Processing.MaxCorrelationsPerBatch = intVal
		}
	}

	if val := os.Getenv("AGGREGATOR_BATCH_PROCESSING_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			if config.Processing == nil {
				config.Processing = &ProcessingConfiguration{}
			}
			config.Processing.BatchProcessingTimeout = duration
		}
	}

	// Confidence configuration
	if val := os.Getenv("AGGREGATOR_CONFIDENCE_ALGORITHM"); val != "" {
		if config.Confidence == nil {
			config.Confidence = &ConfidenceConfiguration{}
		}
		config.Confidence.Algorithm = val
	}

	if val := os.Getenv("AGGREGATOR_MIN_OVERALL_CONFIDENCE"); val != "" {
		if floatVal, err := strconv.ParseFloat(val, 64); err == nil {
			if config.Thresholds == nil {
				config.Thresholds = &ConfidenceThresholds{}
			}
			config.Thresholds.MinimumOverallConfidence = floatVal
		}
	}

	// Storage configuration
	if val := os.Getenv("NEO4J_URI"); val != "" {
		if config.Storage == nil {
			config.Storage = &StorageConfiguration{}
		}
		config.Storage.Neo4jURI = val
	}

	if val := os.Getenv("NEO4J_USERNAME"); val != "" {
		if config.Storage == nil {
			config.Storage = &StorageConfiguration{}
		}
		config.Storage.Neo4jUsername = val
	}

	if val := os.Getenv("NEO4J_PASSWORD"); val != "" {
		if config.Storage == nil {
			config.Storage = &StorageConfiguration{}
		}
		config.Storage.Neo4jPassword = val
	}

	return config
}

// mergeConfigurations merges two configurations, with the override taking precedence
func mergeConfigurations(base, override *AggregatorConfiguration) *AggregatorConfiguration {
	result := *base

	if override.Processing != nil {
		if result.Processing == nil {
			result.Processing = &ProcessingConfiguration{}
		}
		mergeProcessingConfig(result.Processing, override.Processing)
	}

	if override.Confidence != nil {
		if result.Confidence == nil {
			result.Confidence = &ConfidenceConfiguration{}
		}
		mergeConfidenceConfig(result.Confidence, override.Confidence)
	}

	if override.StoryGeneration != nil {
		if result.StoryGeneration == nil {
			result.StoryGeneration = &StoryGenerationConfiguration{}
		}
		mergeStoryGenerationConfig(result.StoryGeneration, override.StoryGeneration)
	}

	if override.Rules != nil {
		result.Rules = override.Rules
	}

	if override.Thresholds != nil {
		result.Thresholds = override.Thresholds
	}

	if override.WeightingCriteria != nil {
		result.WeightingCriteria = override.WeightingCriteria
	}

	if override.PatternLearning != nil {
		result.PatternLearning = override.PatternLearning
	}

	if override.Plugins != nil {
		if result.Plugins == nil {
			result.Plugins = make(map[string]*PluginConfiguration)
		}
		for k, v := range override.Plugins {
			result.Plugins[k] = v
		}
	}

	if override.Storage != nil {
		result.Storage = override.Storage
	}

	if override.DomainConfigs != nil {
		if result.DomainConfigs == nil {
			result.DomainConfigs = make(map[string]*DomainConfiguration)
		}
		for k, v := range override.DomainConfigs {
			result.DomainConfigs[k] = v
		}
	}

	return &result
}

// Helper functions for merging configurations

func mergeProcessingConfig(base, override *ProcessingConfiguration) {
	if override.MaxCorrelationsPerBatch > 0 {
		base.MaxCorrelationsPerBatch = override.MaxCorrelationsPerBatch
	}
	if override.BatchProcessingTimeout > 0 {
		base.BatchProcessingTimeout = override.BatchProcessingTimeout
	}
	if override.InsightGenerationTimeout > 0 {
		base.InsightGenerationTimeout = override.InsightGenerationTimeout
	}
	// Continue for all fields...
}

func mergeConfidenceConfig(base, override *ConfidenceConfiguration) {
	if override.Algorithm != "" {
		base.Algorithm = override.Algorithm
	}
	if override.CorrelationWeights != nil {
		if base.CorrelationWeights == nil {
			base.CorrelationWeights = make(map[string]float64)
		}
		for k, v := range override.CorrelationWeights {
			base.CorrelationWeights[k] = v
		}
	}
	// Continue for all fields...
}

func mergeStoryGenerationConfig(base, override *StoryGenerationConfiguration) {
	if override.DefaultTemplateDirectory != "" {
		base.DefaultTemplateDirectory = override.DefaultTemplateDirectory
	}
	if override.CustomTemplateDirectories != nil {
		base.CustomTemplateDirectories = override.CustomTemplateDirectories
	}
	if override.TemplateRefreshInterval > 0 {
		base.TemplateRefreshInterval = override.TemplateRefreshInterval
	}
	// Continue for all fields...
}

// Configuration validation
func (c *AggregatorConfiguration) Validate() error {
	if err := c.validateProcessing(); err != nil {
		return fmt.Errorf("processing configuration validation failed: %w", err)
	}

	if err := c.validateConfidence(); err != nil {
		return fmt.Errorf("confidence configuration validation failed: %w", err)
	}

	if err := c.validateStorage(); err != nil {
		return fmt.Errorf("storage configuration validation failed: %w", err)
	}

	if err := c.validateThresholds(); err != nil {
		return fmt.Errorf("thresholds validation failed: %w", err)
	}

	return nil
}

func (c *AggregatorConfiguration) validateProcessing() error {
	if c.Processing == nil {
		return fmt.Errorf("processing configuration is required")
	}

	if c.Processing.MaxCorrelationsPerBatch <= 0 {
		return fmt.Errorf("max correlations per batch must be positive")
	}

	if c.Processing.BatchProcessingTimeout <= 0 {
		return fmt.Errorf("batch processing timeout must be positive")
	}

	if c.Processing.MaxConcurrentProcessing <= 0 {
		return fmt.Errorf("max concurrent processing must be positive")
	}

	return nil
}

func (c *AggregatorConfiguration) validateConfidence() error {
	if c.Confidence == nil {
		return fmt.Errorf("confidence configuration is required")
	}

	validAlgorithms := map[string]bool{
		"weighted_average": true,
		"bayesian":         true,
		"neural_network":   true,
	}

	if !validAlgorithms[c.Confidence.Algorithm] {
		return fmt.Errorf("invalid confidence algorithm: %s", c.Confidence.Algorithm)
	}

	return nil
}

func (c *AggregatorConfiguration) validateStorage() error {
	if c.Storage == nil {
		return fmt.Errorf("storage configuration is required")
	}

	if c.Storage.Neo4jURI == "" {
		return fmt.Errorf("neo4j URI is required")
	}

	if c.Storage.MaxConnections <= 0 {
		return fmt.Errorf("max connections must be positive")
	}

	return nil
}

func (c *AggregatorConfiguration) validateThresholds() error {
	if c.Thresholds == nil {
		return fmt.Errorf("confidence thresholds are required")
	}

	if c.Thresholds.MinimumOverallConfidence < 0 || c.Thresholds.MinimumOverallConfidence > 1 {
		return fmt.Errorf("minimum overall confidence must be between 0 and 1")
	}

	return nil
}

// Helper functions for defaults

func getDefaultRules() []*IntelligenceRule {
	return []*IntelligenceRule{
		{
			ID:          "high-confidence-root-cause",
			Name:        "High Confidence Root Cause Rule",
			Description: "Requires high confidence for root cause identification",
			Domain:      "k8s",
			Type:        "threshold",
			Conditions: []*RuleCondition{
				{
					Field:    "root_cause.confidence",
					Operator: "greater_than",
					Value:    0.8,
					Weight:   1.0,
				},
			},
			LogicalOperator: "AND",
			Actions: []*RuleAction{
				{
					Type: "approve_insight",
					Parameters: map[string]interface{}{
						"category": "root_cause_analysis",
					},
				},
			},
			Enabled:   true,
			Priority:  1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Version:   "1.0",
		},
	}
}

func getDefaultPluginConfigurations() map[string]*PluginConfiguration {
	return map[string]*PluginConfiguration{
		"honeycomb": {
			Name:            "Honeycomb Integration",
			Type:            "observability_platform",
			Enabled:         false,
			Priority:        1,
			OutputFormat:    "json",
			DeliveryMethod:  "webhook",
			DeliveryTimeout: 30 * time.Second,
			RetryPolicy: &RetryPolicyConfig{
				MaxRetries:        3,
				InitialDelay:      1 * time.Second,
				BackoffMultiplier: 2.0,
				MaxDelay:          30 * time.Second,
				RetryableErrors:   []string{"timeout", "server_error"},
			},
		},
		"datadog": {
			Name:            "Datadog Integration",
			Type:            "observability_platform",
			Enabled:         false,
			Priority:        2,
			OutputFormat:    "datadog_event",
			DeliveryMethod:  "api",
			DeliveryTimeout: 30 * time.Second,
		},
	}
}

func getDefaultDomainConfigurations() map[string]*DomainConfiguration {
	return map[string]*DomainConfiguration{
		"k8s": {
			Domain:      "k8s",
			DisplayName: "Kubernetes",
			Description: "Kubernetes infrastructure intelligence",
			ConfidenceThresholds: &ConfidenceThresholds{
				MinimumOverallConfidence: 0.75,
				MinimumPublishConfidence: 0.8,
				MinimumActionConfidence:  0.9,
			},
		},
		"infrastructure": {
			Domain:      "infrastructure",
			DisplayName: "Infrastructure",
			Description: "Infrastructure-level intelligence",
			ConfidenceThresholds: &ConfidenceThresholds{
				MinimumOverallConfidence: 0.8,
				MinimumPublishConfidence: 0.85,
				MinimumActionConfidence:  0.95,
			},
		},
	}
}

// Helper functions for environment variable parsing
func getEnvString(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}
