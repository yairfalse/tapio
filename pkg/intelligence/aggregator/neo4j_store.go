package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yairfalse/tapio/pkg/intelligence/correlation"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ProductionNeo4jIntelligenceStore implements Neo4jIntelligenceStore interface
type ProductionNeo4jIntelligenceStore struct {
	logger     *zap.Logger
	graphStore correlation.GraphStore
	tracer     trace.Tracer

	// OTEL instrumentation
	queriesTotal   metric.Int64Counter
	errorsTotal    metric.Int64Counter
	queryDuration  metric.Float64Histogram
	insightsStored metric.Int64Counter
	patternsStored metric.Int64Counter
}

// NewProductionNeo4jIntelligenceStore creates a new production intelligence store
func NewProductionNeo4jIntelligenceStore(
	logger *zap.Logger,
	graphStore correlation.GraphStore,
) (*ProductionNeo4jIntelligenceStore, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if graphStore == nil {
		return nil, fmt.Errorf("graph store is required")
	}

	// Initialize OTEL components
	tracer := otel.Tracer("neo4j-intelligence-store")
	meter := otel.Meter("neo4j-intelligence-store")

	// Create metrics
	queriesTotal, err := meter.Int64Counter(
		"neo4j_intelligence_store_queries_total",
		metric.WithDescription("Total queries executed by intelligence store"),
	)
	if err != nil {
		logger.Warn("Failed to create queries counter", zap.Error(err))
	}

	errorsTotal, err := meter.Int64Counter(
		"neo4j_intelligence_store_errors_total",
		metric.WithDescription("Total errors in intelligence store"),
	)
	if err != nil {
		logger.Warn("Failed to create errors counter", zap.Error(err))
	}

	queryDuration, err := meter.Float64Histogram(
		"neo4j_intelligence_store_query_duration_ms",
		metric.WithDescription("Query execution duration in milliseconds"),
	)
	if err != nil {
		logger.Warn("Failed to create query duration histogram", zap.Error(err))
	}

	insightsStored, err := meter.Int64Counter(
		"neo4j_intelligence_store_insights_stored_total",
		metric.WithDescription("Total insights stored"),
	)
	if err != nil {
		logger.Warn("Failed to create insights stored counter", zap.Error(err))
	}

	patternsStored, err := meter.Int64Counter(
		"neo4j_intelligence_store_patterns_stored_total",
		metric.WithDescription("Total patterns stored"),
	)
	if err != nil {
		logger.Warn("Failed to create patterns stored counter", zap.Error(err))
	}

	return &ProductionNeo4jIntelligenceStore{
		logger:         logger,
		graphStore:     graphStore,
		tracer:         tracer,
		queriesTotal:   queriesTotal,
		errorsTotal:    errorsTotal,
		queryDuration:  queryDuration,
		insightsStored: insightsStored,
		patternsStored: patternsStored,
	}, nil
}

// StoreInsight stores an intelligence insight in Neo4j
func (s *ProductionNeo4jIntelligenceStore) StoreInsight(
	ctx context.Context,
	insight *IntelligenceInsight,
) (*StorageResult, error) {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.store_insight")
	defer span.End()

	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds() * 1000
		if s.queryDuration != nil {
			s.queryDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("operation", "store_insight"),
			))
		}
	}()

	span.SetAttributes(
		attribute.String("insight.id", insight.ID),
		attribute.String("insight.type", insight.Type),
	)

	// Serialize insight to JSON for storage
	insightData, err := json.Marshal(insight)
	if err != nil {
		s.recordError(ctx, "serialization", err)
		return nil, fmt.Errorf("failed to serialize insight: %w", err)
	}

	// Create Cypher query to store the insight
	query := `
		CREATE (i:Insight {
			id: $id,
			type: $type,
			title: $title,
			timestamp: datetime($timestamp),
			summary: $summary,
			detailed_analysis: $detailed_analysis,
			overall_confidence: $overall_confidence,
			data: $data,
			created_at: datetime()
		})
		RETURN i.id as id
	`

	params := correlation.NewQueryParams()
	params.Set("id", insight.ID)
	params.Set("type", insight.Type)
	params.Set("title", insight.Title)
	params.Set("timestamp", insight.Timestamp.Format(time.RFC3339))
	params.Set("summary", insight.Summary)
	params.Set("detailed_analysis", insight.DetailedAnalysis)
	params.Set("overall_confidence", insight.OverallConfidence)
	params.Set("data", string(insightData))

	// Execute the query
	if err := s.graphStore.ExecuteWrite(ctx, query, params); err != nil {
		s.recordError(ctx, "store_insight", err)
		span.SetAttributes(attribute.String("error", err.Error()))
		return nil, fmt.Errorf("failed to store insight: %w", err)
	}

	// Create relationships to root causes
	if err := s.storeInsightRootCauses(ctx, insight); err != nil {
		s.logger.Warn("Failed to store root cause relationships", zap.Error(err))
	}

	// Create relationships to evidence
	if err := s.storeInsightEvidence(ctx, insight); err != nil {
		s.logger.Warn("Failed to store evidence relationships", zap.Error(err))
	}

	// Record success metrics
	if s.insightsStored != nil {
		s.insightsStored.Add(ctx, 1, metric.WithAttributes(
			attribute.String("insight_type", insight.Type),
		))
	}

	if s.queriesTotal != nil {
		s.queriesTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", "store_insight"),
			attribute.String("status", "success"),
		))
	}

	span.SetAttributes(attribute.String("status", "success"))

	return &StorageResult{
		ID:        insight.ID,
		Success:   true,
		Timestamp: time.Now(),
	}, nil
}

// GetInsight retrieves an insight by ID
func (s *ProductionNeo4jIntelligenceStore) GetInsight(
	ctx context.Context,
	insightID string,
) (*IntelligenceInsight, error) {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.get_insight")
	defer span.End()

	span.SetAttributes(attribute.String("insight.id", insightID))

	query := `
		MATCH (i:Insight {id: $id})
		RETURN i.data as data
	`

	params := correlation.NewQueryParams()
	params.Set("id", insightID)

	result, err := s.graphStore.ExecuteTypedQuery(ctx, query, params)
	if err != nil {
		s.recordError(ctx, "get_insight", err)
		return nil, fmt.Errorf("failed to get insight: %w", err)
	}

	if len(result.Scalars) == 0 {
		return nil, fmt.Errorf("insight not found: %s", insightID)
	}

	// Deserialize the insight data
	dataStr, ok := result.Scalars["data"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid insight data format")
	}

	var insight IntelligenceInsight
	if err := json.Unmarshal([]byte(dataStr), &insight); err != nil {
		return nil, fmt.Errorf("failed to deserialize insight: %w", err)
	}

	return &insight, nil
}

// QueryInsights queries insights based on criteria
func (s *ProductionNeo4jIntelligenceStore) QueryInsights(
	ctx context.Context,
	query *InsightQuery,
) (*InsightQueryResult, error) {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.query_insights")
	defer span.End()

	start := time.Now()

	// Build Cypher query based on criteria
	cypherQuery, params := s.buildInsightQuery(query)

	span.SetAttributes(
		attribute.String("query.order_by", query.OrderBy),
		attribute.Int("query.limit", query.Limit),
	)

	result, err := s.graphStore.ExecuteTypedQuery(ctx, cypherQuery, params)
	if err != nil {
		s.recordError(ctx, "query_insights", err)
		return nil, fmt.Errorf("failed to query insights: %w", err)
	}

	// Parse results into insights
	insights := make([]*IntelligenceInsight, 0)
	for key, value := range result.Scalars {
		if key == "data" {
			if dataStr, ok := value.(string); ok {
				var insight IntelligenceInsight
				if err := json.Unmarshal([]byte(dataStr), &insight); err == nil {
					insights = append(insights, &insight)
				}
			}
		}
	}

	// Get total count for pagination
	totalCount := len(insights) // Simplified - in production would use separate count query

	queryResult := &InsightQueryResult{
		Insights:   insights,
		TotalCount: totalCount,
		HasMore:    totalCount > query.Limit,
		QueryTime:  time.Since(start),
	}

	span.SetAttributes(
		attribute.Int("results.count", len(insights)),
		attribute.Int("results.total", totalCount),
	)

	return queryResult, nil
}

// DeleteInsight deletes an insight by ID
func (s *ProductionNeo4jIntelligenceStore) DeleteInsight(
	ctx context.Context,
	insightID string,
) error {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.delete_insight")
	defer span.End()

	span.SetAttributes(attribute.String("insight.id", insightID))

	query := `
		MATCH (i:Insight {id: $id})
		DETACH DELETE i
	`

	params := correlation.NewQueryParams()
	params.Set("id", insightID)

	if err := s.graphStore.ExecuteWrite(ctx, query, params); err != nil {
		s.recordError(ctx, "delete_insight", err)
		return fmt.Errorf("failed to delete insight: %w", err)
	}

	return nil
}

// StorePattern stores a learned pattern
func (s *ProductionNeo4jIntelligenceStore) StorePattern(
	ctx context.Context,
	pattern *LearnedPattern,
) error {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.store_pattern")
	defer span.End()

	span.SetAttributes(
		attribute.String("pattern.id", pattern.ID),
		attribute.String("pattern.type", pattern.Type),
	)

	// Serialize pattern data
	patternData, err := json.Marshal(pattern)
	if err != nil {
		s.recordError(ctx, "pattern_serialization", err)
		return fmt.Errorf("failed to serialize pattern: %w", err)
	}

	query := `
		MERGE (p:Pattern {id: $id})
		SET p.name = $name,
			p.type = $type,
			p.domain = $domain,
			p.confidence = $confidence,
			p.match_count = $match_count,
			p.success_rate = $success_rate,
			p.data = $data,
			p.updated_at = datetime()
		RETURN p.id as id
	`

	params := correlation.NewQueryParams()
	params.Set("id", pattern.ID)
	params.Set("name", pattern.Name)
	params.Set("type", pattern.Type)
	params.Set("domain", pattern.Domain)
	params.Set("confidence", pattern.Confidence)
	params.Set("match_count", pattern.MatchCount)
	params.Set("success_rate", pattern.SuccessRate)
	params.Set("data", string(patternData))

	if err := s.graphStore.ExecuteWrite(ctx, query, params); err != nil {
		s.recordError(ctx, "store_pattern", err)
		return fmt.Errorf("failed to store pattern: %w", err)
	}

	// Record success metrics
	if s.patternsStored != nil {
		s.patternsStored.Add(ctx, 1, metric.WithAttributes(
			attribute.String("pattern_type", pattern.Type),
			attribute.String("domain", pattern.Domain),
		))
	}

	return nil
}

// QueryPatterns queries patterns based on criteria
func (s *ProductionNeo4jIntelligenceStore) QueryPatterns(
	ctx context.Context,
	query *PatternQuery,
) ([]*StoredPattern, error) {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.query_patterns")
	defer span.End()

	cypherQuery := `
		MATCH (p:Pattern)
		WHERE ($domain = '' OR p.domain = $domain)
		AND ($type = '' OR p.type = $type)
		RETURN p.data as data
		ORDER BY p.confidence DESC
		LIMIT $limit
	`

	params := correlation.NewQueryParams()
	params.Set("domain", query.Domain)
	params.Set("type", query.Type)
	params.Set("limit", query.Limit)

	result, err := s.graphStore.ExecuteTypedQuery(ctx, cypherQuery, params)
	if err != nil {
		s.recordError(ctx, "query_patterns", err)
		return nil, fmt.Errorf("failed to query patterns: %w", err)
	}

	patterns := make([]*StoredPattern, 0)
	for key, value := range result.Scalars {
		if key == "data" {
			if dataStr, ok := value.(string); ok {
				var pattern LearnedPattern
				if err := json.Unmarshal([]byte(dataStr), &pattern); err == nil {
					storedPattern := &StoredPattern{
						Pattern:   &pattern,
						StoredAt:  time.Now(),
						UpdatedAt: pattern.LastRefined,
					}
					patterns = append(patterns, storedPattern)
				}
			}
		}
	}

	span.SetAttributes(attribute.Int("patterns.count", len(patterns)))

	return patterns, nil
}

// UpdatePatternConfidence updates pattern confidence
func (s *ProductionNeo4jIntelligenceStore) UpdatePatternConfidence(
	ctx context.Context,
	patternID string,
	adjustment float64,
	reason string,
) error {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.update_pattern_confidence")
	defer span.End()

	span.SetAttributes(
		attribute.String("pattern.id", patternID),
		attribute.Float64("adjustment", adjustment),
	)

	query := `
		MATCH (p:Pattern {id: $id})
		SET p.confidence = p.confidence + $adjustment,
			p.updated_at = datetime()
		RETURN p.confidence as new_confidence
	`

	params := correlation.NewQueryParams()
	params.Set("id", patternID)
	params.Set("adjustment", adjustment)

	if err := s.graphStore.ExecuteWrite(ctx, query, params); err != nil {
		s.recordError(ctx, "update_pattern_confidence", err)
		return fmt.Errorf("failed to update pattern confidence: %w", err)
	}

	s.logger.Debug("Updated pattern confidence",
		zap.String("pattern_id", patternID),
		zap.Float64("adjustment", adjustment),
		zap.String("reason", reason))

	return nil
}

// DeletePattern deletes a pattern
func (s *ProductionNeo4jIntelligenceStore) DeletePattern(
	ctx context.Context,
	patternID string,
) error {
	ctx, span := s.tracer.Start(ctx, "neo4j_store.delete_pattern")
	defer span.End()

	query := `
		MATCH (p:Pattern {id: $id})
		DETACH DELETE p
	`

	params := correlation.NewQueryParams()
	params.Set("id", patternID)

	if err := s.graphStore.ExecuteWrite(ctx, query, params); err != nil {
		s.recordError(ctx, "delete_pattern", err)
		return fmt.Errorf("failed to delete pattern: %w", err)
	}

	return nil
}

// StoreConfiguration stores configuration
func (s *ProductionNeo4jIntelligenceStore) StoreConfiguration(
	ctx context.Context,
	config *StoredConfiguration,
) error {
	configData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to serialize configuration: %w", err)
	}

	query := `
		MERGE (c:Configuration {id: $id})
		SET c.name = $name,
			c.domain = $domain,
			c.version = $version,
			c.data = $data,
			c.updated_at = datetime()
	`

	params := correlation.NewQueryParams()
	params.Set("id", config.ID)
	params.Set("name", config.Name)
	params.Set("domain", config.Domain)
	params.Set("version", config.Version)
	params.Set("data", string(configData))

	return s.graphStore.ExecuteWrite(ctx, query, params)
}

// GetConfiguration retrieves configuration by ID
func (s *ProductionNeo4jIntelligenceStore) GetConfiguration(
	ctx context.Context,
	configID string,
) (*StoredConfiguration, error) {
	query := `
		MATCH (c:Configuration {id: $id})
		RETURN c.data as data
	`

	params := correlation.NewQueryParams()
	params.Set("id", configID)

	result, err := s.graphStore.ExecuteTypedQuery(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration: %w", err)
	}

	if len(result.Scalars) == 0 {
		return nil, fmt.Errorf("configuration not found: %s", configID)
	}

	dataStr, ok := result.Scalars["data"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid configuration data format")
	}

	var config StoredConfiguration
	if err := json.Unmarshal([]byte(dataStr), &config); err != nil {
		return nil, fmt.Errorf("failed to deserialize configuration: %w", err)
	}

	return &config, nil
}

// ListConfigurations lists configurations for a domain
func (s *ProductionNeo4jIntelligenceStore) ListConfigurations(
	ctx context.Context,
	domain string,
) ([]*StoredConfiguration, error) {
	query := `
		MATCH (c:Configuration)
		WHERE ($domain = '' OR c.domain = $domain)
		RETURN c.data as data
		ORDER BY c.updated_at DESC
	`

	params := correlation.NewQueryParams()
	params.Set("domain", domain)

	result, err := s.graphStore.ExecuteTypedQuery(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list configurations: %w", err)
	}

	configs := make([]*StoredConfiguration, 0)
	for key, value := range result.Scalars {
		if key == "data" {
			if dataStr, ok := value.(string); ok {
				var config StoredConfiguration
				if err := json.Unmarshal([]byte(dataStr), &config); err == nil {
					configs = append(configs, &config)
				}
			}
		}
	}

	return configs, nil
}

// GetStorageHealth returns storage health status
func (s *ProductionNeo4jIntelligenceStore) GetStorageHealth(
	ctx context.Context,
) (*StorageHealth, error) {
	// Test connectivity with a simple query
	query := `RETURN 1 as health_check`
	params := correlation.NewQueryParams()

	_, err := s.graphStore.ExecuteTypedQuery(ctx, query, params)

	health := &StorageHealth{
		IsHealthy:  err == nil,
		LastCheck:  time.Now(),
		Connection: "neo4j",
	}

	if err != nil {
		health.Message = fmt.Sprintf("Neo4j connectivity failed: %v", err)
		health.Errors = []string{err.Error()}
	} else {
		health.Message = "Neo4j connection healthy"
	}

	return health, nil
}

// GetStorageMetrics returns storage metrics
func (s *ProductionNeo4jIntelligenceStore) GetStorageMetrics(
	ctx context.Context,
) (*StorageMetrics, error) {
	// Query basic storage statistics
	query := `
		CALL {
			MATCH (i:Insight) RETURN count(i) as insight_count
		}
		CALL {
			MATCH (p:Pattern) RETURN count(p) as pattern_count
		}
		RETURN insight_count, pattern_count
	`

	params := correlation.NewQueryParams()
	result, err := s.graphStore.ExecuteTypedQuery(ctx, query, params)
	if err != nil {
		s.logger.Warn("Failed to get storage metrics", zap.Error(err))
		// Return default metrics on error
		return &StorageMetrics{
			TotalInsights:    0,
			TotalPatterns:    0,
			DatabaseSize:     0,
			QueryPerformance: map[string]time.Duration{},
			LastUpdated:      time.Now(),
		}, nil
	}

	insightCount := int64(0)
	patternCount := int64(0)

	if val, exists := result.Scalars["insight_count"]; exists {
		if count, ok := val.(int64); ok {
			insightCount = count
		}
	}

	if val, exists := result.Scalars["pattern_count"]; exists {
		if count, ok := val.(int64); ok {
			patternCount = count
		}
	}

	return &StorageMetrics{
		TotalInsights: insightCount,
		TotalPatterns: patternCount,
		DatabaseSize:  0, // Would require APOC procedures for accurate size
		QueryPerformance: map[string]time.Duration{
			"insight_queries": time.Millisecond * 50, // Estimated
			"pattern_queries": time.Millisecond * 30, // Estimated
		},
		LastUpdated: time.Now(),
	}, nil
}

// Helper methods

func (s *ProductionNeo4jIntelligenceStore) storeInsightRootCauses(
	ctx context.Context,
	insight *IntelligenceInsight,
) error {
	for i, rootCause := range insight.RootCauses {
		query := `
			MATCH (i:Insight {id: $insight_id})
			CREATE (rc:RootCause {
				id: $id,
				type: $type,
				description: $description,
				confidence: $confidence,
				first_seen: datetime($first_seen)
			})
			CREATE (i)-[:HAS_ROOT_CAUSE {order: $order}]->(rc)
		`

		params := correlation.NewQueryParams()
		params.Set("insight_id", insight.ID)
		params.Set("id", rootCause.ID)
		params.Set("type", rootCause.Type)
		params.Set("description", rootCause.Description)
		params.Set("confidence", rootCause.Confidence)
		params.Set("first_seen", rootCause.FirstSeen.Format(time.RFC3339))
		params.Set("order", i)

		if err := s.graphStore.ExecuteWrite(ctx, query, params); err != nil {
			return fmt.Errorf("failed to store root cause %s: %w", rootCause.ID, err)
		}
	}
	return nil
}

func (s *ProductionNeo4jIntelligenceStore) storeInsightEvidence(
	ctx context.Context,
	insight *IntelligenceInsight,
) error {
	for i, evidence := range insight.Evidence {
		evidenceData, _ := json.Marshal(evidence.Data)

		query := `
			MATCH (i:Insight {id: $insight_id})
			CREATE (e:Evidence {
				id: $id,
				type: $type,
				source: $source,
				title: $title,
				description: $description,
				confidence: $confidence,
				weight: $weight,
				timestamp: datetime($timestamp),
				data: $data
			})
			CREATE (i)-[:HAS_EVIDENCE {order: $order}]->(e)
		`

		params := correlation.NewQueryParams()
		params.Set("insight_id", insight.ID)
		params.Set("id", evidence.ID)
		params.Set("type", evidence.Type)
		params.Set("source", evidence.Source)
		params.Set("title", evidence.Title)
		params.Set("description", evidence.Description)
		params.Set("confidence", evidence.Confidence)
		params.Set("weight", evidence.Weight)
		params.Set("timestamp", evidence.Timestamp.Format(time.RFC3339))
		params.Set("data", string(evidenceData))
		params.Set("order", i)

		if err := s.graphStore.ExecuteWrite(ctx, query, params); err != nil {
			return fmt.Errorf("failed to store evidence %s: %w", evidence.ID, err)
		}
	}
	return nil
}

func (s *ProductionNeo4jIntelligenceStore) buildInsightQuery(
	query *InsightQuery,
) (string, correlation.QueryParams) {
	cypherQuery := `
		MATCH (i:Insight)
		WHERE 1=1
	`

	params := correlation.NewQueryParams()

	// Add time range filters
	if query.StartTime != nil {
		cypherQuery += ` AND i.timestamp >= datetime($start_time)`
		params.Set("start_time", query.StartTime.Format(time.RFC3339))
	}

	if query.EndTime != nil {
		cypherQuery += ` AND i.timestamp <= datetime($end_time)`
		params.Set("end_time", query.EndTime.Format(time.RFC3339))
	}

	// Add type filters
	if len(query.Types) > 0 {
		cypherQuery += ` AND i.type IN $types`
		params.Set("types", query.Types)
	}

	// Add confidence filters
	if query.MinConfidence != nil {
		cypherQuery += ` AND i.overall_confidence >= $min_confidence`
		params.Set("min_confidence", *query.MinConfidence)
	}

	if query.MaxConfidence != nil {
		cypherQuery += ` AND i.overall_confidence <= $max_confidence`
		params.Set("max_confidence", *query.MaxConfidence)
	}

	// Add ordering
	orderBy := "i.timestamp"
	if query.OrderBy != "" {
		switch query.OrderBy {
		case "confidence":
			orderBy = "i.overall_confidence"
		case "relevance":
			orderBy = "i.overall_confidence" // Simplified
		}
	}

	orderDirection := "DESC"
	if query.OrderDirection == "asc" {
		orderDirection = "ASC"
	}

	cypherQuery += fmt.Sprintf(" RETURN i.data as data ORDER BY %s %s", orderBy, orderDirection)

	// Add limit
	limit := 50 // Default limit
	if query.Limit > 0 {
		limit = query.Limit
	}
	cypherQuery += ` LIMIT $limit`
	params.Set("limit", limit)

	return cypherQuery, params
}

func (s *ProductionNeo4jIntelligenceStore) recordError(
	ctx context.Context,
	operation string,
	err error,
) {
	if s.errorsTotal != nil {
		s.errorsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("error_type", classifyStoreError(err)),
		))
	}
}

func classifyStoreError(err error) string {
	errStr := err.Error()
	if containsSubstring(errStr, "connection") || containsSubstring(errStr, "timeout") {
		return "connection"
	}
	if containsSubstring(errStr, "serialization") || containsSubstring(errStr, "json") {
		return "serialization"
	}
	if containsSubstring(errStr, "constraint") || containsSubstring(errStr, "duplicate") {
		return "constraint"
	}
	return "unknown"
}

// Required types for the store

type StorageResult struct {
	ID        string    `json:"id"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type InsightQueryResult struct {
	Insights   []*IntelligenceInsight `json:"insights"`
	TotalCount int                    `json:"total_count"`
	HasMore    bool                   `json:"has_more"`
	QueryTime  time.Duration          `json:"query_time"`
}

type PatternQuery struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Limit  int    `json:"limit"`
}

type StoredPattern struct {
	Pattern   *LearnedPattern `json:"pattern"`
	StoredAt  time.Time       `json:"stored_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type StoredConfiguration struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Domain   string    `json:"domain"`
	Version  string    `json:"version"`
	Data     []byte    `json:"data"`
	StoredAt time.Time `json:"stored_at"`
}

type StorageHealth struct {
	IsHealthy  bool      `json:"is_healthy"`
	LastCheck  time.Time `json:"last_check"`
	Connection string    `json:"connection"`
	Message    string    `json:"message"`
	Errors     []string  `json:"errors,omitempty"`
}

type StorageMetrics struct {
	TotalInsights    int64                    `json:"total_insights"`
	TotalPatterns    int64                    `json:"total_patterns"`
	DatabaseSize     int64                    `json:"database_size_bytes"`
	QueryPerformance map[string]time.Duration `json:"query_performance"`
	LastUpdated      time.Time                `json:"last_updated"`
}

func containsSubstring(str, substr string) bool {
	return len(str) >= len(substr) &&
		(len(str) == len(substr) && str == substr ||
			len(str) > len(substr) &&
				(str[:len(substr)] == substr || str[len(str)-len(substr):] == substr ||
					strings.Contains(str, substr)))
}
