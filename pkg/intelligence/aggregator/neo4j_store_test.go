package aggregator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Mock Neo4j Driver and Session for testing
type mockNeo4jDriver struct {
	mock.Mock
}

type mockNeo4jSession struct {
	mock.Mock
}

type mockNeo4jResult struct {
	mock.Mock
}

type mockNeo4jRecord struct {
	mock.Mock
}

func (m *mockNeo4jDriver) NewSession(mode interface{}, bookmarks ...string) interface{} {
	args := m.Called(mode, bookmarks)
	return args.Get(0)
}

func (m *mockNeo4jDriver) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockNeo4jSession) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockNeo4jSession) Run(cypher string, params map[string]interface{}) (interface{}, error) {
	args := m.Called(cypher, params)
	return args.Get(0), args.Error(1)
}

func (m *mockNeo4jSession) WriteTransaction(work interface{}) (interface{}, error) {
	args := m.Called(work)
	return args.Get(0), args.Error(1)
}

func (m *mockNeo4jSession) ReadTransaction(work interface{}) (interface{}, error) {
	args := m.Called(work)
	return args.Get(0), args.Error(1)
}

func (m *mockNeo4jResult) Next() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockNeo4jResult) Record() interface{} {
	args := m.Called()
	return args.Get(0)
}

func (m *mockNeo4jResult) Err() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockNeo4jResult) Consume() (interface{}, error) {
	args := m.Called()
	return args.Get(0), args.Error(1)
}

func (m *mockNeo4jRecord) Get(key string) (interface{}, bool) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1)
}

func (m *mockNeo4jRecord) GetByIndex(index int) interface{} {
	args := m.Called(index)
	return args.Get(0)
}

// Test Neo4j Store

func TestProductionNeo4jIntelligenceStore_StoreInsight(t *testing.T) {
	logger := zap.NewNop()
	config := &Neo4jIntelligenceStoreConfiguration{
		URI:            "bolt://localhost:7687",
		Username:       "neo4j",
		Password:       "password",
		Database:       "intelligence",
		MaxConnections: 10,
		ConnTimeout:    30 * time.Second,
		WriteTimeout:   10 * time.Second,
		ReadTimeout:    10 * time.Second,
	}

	mockDriver := &mockNeo4jDriver{}
	mockSession := &mockNeo4jSession{}

	store := &ProductionNeo4jIntelligenceStore{
		logger: logger,
		config: config,
		tracer: mockTracer{},
		driver: mockDriver,
	}

	ctx := context.Background()
	insight := &IntelligenceInsight{
		ID:                "test-insight-1",
		Title:             "Test Insight",
		Type:              "memory_exhaustion",
		Summary:           "Memory usage is high",
		OverallConfidence: 0.85,
		Timestamp:         time.Now(),
		RootCauses: []*RootCause{
			{
				ID:          "root-cause-1",
				Type:        "memory_leak",
				Description: "Application memory leak",
				Confidence:  0.8,
			},
		},
		Evidence: []*Evidence{
			{
				ID:          "evidence-1",
				Type:        "metric",
				Description: "Memory usage at 95%",
				Confidence:  0.9,
				Weight:      1.0,
			},
		},
		Recommendations: []*Recommendation{
			{
				ID:          "recommendation-1",
				Action:      "restart_pod",
				Description: "Restart the affected pod",
				Priority:    "high",
				Confidence:  0.9,
			},
		},
	}

	// Mock successful transaction
	mockDriver.On("NewSession", mock.Anything, mock.Anything).Return(mockSession)
	mockSession.On("Close").Return(nil)
	mockSession.On("WriteTransaction", mock.Anything).Return(map[string]interface{}{
		"insight_id": insight.ID,
		"created_at": insight.Timestamp,
	}, nil)

	result, err := store.StoreInsight(ctx, insight)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, insight.ID, result.ID)
	assert.NotEmpty(t, result.StoredAt)

	mockDriver.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestProductionNeo4jIntelligenceStore_StoreInsight_Error(t *testing.T) {
	logger := zap.NewNop()
	config := &Neo4jIntelligenceStoreConfiguration{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "password",
		Database: "intelligence",
	}

	mockDriver := &mockNeo4jDriver{}
	mockSession := &mockNeo4jSession{}

	store := &ProductionNeo4jIntelligenceStore{
		logger: logger,
		config: config,
		tracer: mockTracer{},
		driver: mockDriver,
	}

	ctx := context.Background()
	insight := &IntelligenceInsight{
		ID:    "test-insight-1",
		Title: "Test Insight",
		Type:  "memory_exhaustion",
	}

	// Mock failed transaction
	mockDriver.On("NewSession", mock.Anything, mock.Anything).Return(mockSession)
	mockSession.On("Close").Return(nil)
	mockSession.On("WriteTransaction", mock.Anything).Return(nil, errors.New("database error"))

	result, err := store.StoreInsight(ctx, insight)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to store insight")

	mockDriver.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestProductionNeo4jIntelligenceStore_StorePattern(t *testing.T) {
	logger := zap.NewNop()
	config := &Neo4jIntelligenceStoreConfiguration{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "password",
	}

	mockDriver := &mockNeo4jDriver{}
	mockSession := &mockNeo4jSession{}

	store := &ProductionNeo4jIntelligenceStore{
		logger: logger,
		config: config,
		tracer: mockTracer{},
		driver: mockDriver,
	}

	ctx := context.Background()
	pattern := &LearnedPattern{
		ID:           "test-pattern-1",
		Name:         "Test Pattern",
		Type:         "statistical",
		Domain:       "k8s",
		DiscoveredAt: time.Now(),
		MatchCount:   5,
		Confidence:   0.8,
		Conditions: []*PatternCondition{
			{
				Type:     "type_match",
				Field:    "type",
				Operator: "equals",
				Value:    "dependency",
			},
		},
	}

	// Mock successful transaction
	mockDriver.On("NewSession", mock.Anything, mock.Anything).Return(mockSession)
	mockSession.On("Close").Return(nil)
	mockSession.On("WriteTransaction", mock.Anything).Return(nil, nil)

	err := store.StorePattern(ctx, pattern)
	require.NoError(t, err)

	mockDriver.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestProductionNeo4jIntelligenceStore_QueryInsights(t *testing.T) {
	logger := zap.NewNop()
	config := &Neo4jIntelligenceStoreConfiguration{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "password",
	}

	mockDriver := &mockNeo4jDriver{}
	mockSession := &mockNeo4jSession{}
	mockResult := &mockNeo4jResult{}
	mockRecord := &mockNeo4jRecord{}

	store := &ProductionNeo4jIntelligenceStore{
		logger: logger,
		config: config,
		tracer: mockTracer{},
		driver: mockDriver,
	}

	ctx := context.Background()
	query := &InsightQuery{
		TimeRange: &TimeRange{
			From: time.Now().Add(-24 * time.Hour),
			To:   time.Now(),
		},
		Types:             []string{"memory_exhaustion"},
		MinConfidence:     0.7,
		Limit:             10,
		Offset:            0,
		IncludeEvidence:   true,
		IncludeRootCauses: true,
	}

	// Mock the query execution
	mockDriver.On("NewSession", mock.Anything, mock.Anything).Return(mockSession)
	mockSession.On("Close").Return(nil)
	mockSession.On("ReadTransaction", mock.Anything).Return(mockResult, nil)

	// Mock result iteration
	mockResult.On("Next").Return(true).Once()  // First record
	mockResult.On("Next").Return(false).Once() // End of results
	mockResult.On("Err").Return(nil)

	// Mock record data
	mockRecord.On("Get", "i").Return(map[string]interface{}{
		"id":                 "insight-1",
		"title":              "Test Insight",
		"type":               "memory_exhaustion",
		"summary":            "Memory usage high",
		"overall_confidence": 0.85,
		"timestamp":          time.Now().Unix(),
	}, true)

	mockRecord.On("Get", "evidence").Return([]interface{}{
		map[string]interface{}{
			"id":          "evidence-1",
			"type":        "metric",
			"description": "Memory at 95%",
			"confidence":  0.9,
		},
	}, true)

	mockRecord.On("Get", "root_causes").Return([]interface{}{
		map[string]interface{}{
			"id":          "root-cause-1",
			"type":        "memory_leak",
			"description": "Memory leak detected",
			"confidence":  0.8,
		},
	}, true)

	mockResult.On("Record").Return(mockRecord)

	result, err := store.QueryInsights(ctx, query)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Insights, 1)
	assert.Equal(t, "insight-1", result.Insights[0].ID)
	assert.Equal(t, "Test Insight", result.Insights[0].Title)
	assert.Equal(t, "memory_exhaustion", result.Insights[0].Type)

	mockDriver.AssertExpectations(t)
	mockSession.AssertExpectations(t)
	mockResult.AssertExpectations(t)
	mockRecord.AssertExpectations(t)
}

func TestProductionNeo4jIntelligenceStore_GetPatterns(t *testing.T) {
	logger := zap.NewNop()
	config := &Neo4jIntelligenceStoreConfiguration{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "password",
	}

	mockDriver := &mockNeo4jDriver{}
	mockSession := &mockNeo4jSession{}
	mockResult := &mockNeo4jResult{}
	mockRecord := &mockNeo4jRecord{}

	store := &ProductionNeo4jIntelligenceStore{
		logger: logger,
		config: config,
		tracer: mockTracer{},
		driver: mockDriver,
	}

	ctx := context.Background()
	domain := "k8s"

	// Mock the query execution
	mockDriver.On("NewSession", mock.Anything, mock.Anything).Return(mockSession)
	mockSession.On("Close").Return(nil)
	mockSession.On("ReadTransaction", mock.Anything).Return(mockResult, nil)

	// Mock result iteration
	mockResult.On("Next").Return(true).Once()  // First pattern
	mockResult.On("Next").Return(false).Once() // End of results
	mockResult.On("Err").Return(nil)

	// Mock pattern data
	mockRecord.On("Get", "p").Return(map[string]interface{}{
		"id":            "pattern-1",
		"name":          "Test Pattern",
		"type":          "statistical",
		"domain":        "k8s",
		"discovered_at": time.Now().Unix(),
		"match_count":   5,
		"confidence":    0.8,
	}, true)

	mockResult.On("Record").Return(mockRecord)

	patterns, err := store.GetPatterns(ctx, domain)
	require.NoError(t, err)
	assert.Len(t, patterns, 1)
	assert.Equal(t, "pattern-1", patterns[0].ID)
	assert.Equal(t, "Test Pattern", patterns[0].Name)
	assert.Equal(t, "k8s", patterns[0].Domain)

	mockDriver.AssertExpectations(t)
	mockSession.AssertExpectations(t)
	mockResult.AssertExpectations(t)
	mockRecord.AssertExpectations(t)
}

func TestProductionNeo4jIntelligenceStore_Health(t *testing.T) {
	logger := zap.NewNop()
	config := &Neo4jIntelligenceStoreConfiguration{
		URI:              "bolt://localhost:7687",
		Username:         "neo4j",
		Password:         "password",
		HealthcheckQuery: "RETURN 1 as health",
	}

	tests := []struct {
		name           string
		mockError      error
		expectedStatus HealthStatusType
	}{
		{
			name:           "healthy",
			mockError:      nil,
			expectedStatus: HealthStatusHealthy,
		},
		{
			name:           "unhealthy",
			mockError:      errors.New("connection failed"),
			expectedStatus: HealthStatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDriver := &mockNeo4jDriver{}
			mockSession := &mockNeo4jSession{}

			store := &ProductionNeo4jIntelligenceStore{
				logger: logger,
				config: config,
				tracer: mockTracer{},
				driver: mockDriver,
			}

			ctx := context.Background()

			// Mock the health check
			mockDriver.On("NewSession", mock.Anything, mock.Anything).Return(mockSession)
			mockSession.On("Close").Return(nil)

			if tt.mockError != nil {
				mockSession.On("Run", config.HealthcheckQuery, mock.Anything).Return(nil, tt.mockError)
			} else {
				mockResult := &mockNeo4jResult{}
				mockSession.On("Run", config.HealthcheckQuery, mock.Anything).Return(mockResult, nil)
				mockResult.On("Consume").Return(nil, nil)
			}

			status, err := store.Health(ctx)
			require.NoError(t, err)
			assert.NotNil(t, status)
			assert.Equal(t, tt.expectedStatus, status.Status)

			if tt.mockError != nil {
				assert.Contains(t, status.Message, "health check failed")
			} else {
				assert.Equal(t, "Neo4j store is healthy", status.Message)
			}

			mockDriver.AssertExpectations(t)
			mockSession.AssertExpectations(t)
		})
	}
}

func TestProductionNeo4jIntelligenceStore_BuildInsightNode(t *testing.T) {
	store := &ProductionNeo4jIntelligenceStore{}

	insight := &IntelligenceInsight{
		ID:                "test-insight",
		Title:             "Test Title",
		Type:              "memory_exhaustion",
		Summary:           "Test summary",
		OverallConfidence: 0.85,
		Timestamp:         time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	node := store.buildInsightNode(insight)
	assert.Equal(t, insight.ID, node["id"])
	assert.Equal(t, insight.Title, node["title"])
	assert.Equal(t, insight.Type, node["type"])
	assert.Equal(t, insight.Summary, node["summary"])
	assert.Equal(t, insight.OverallConfidence, node["overall_confidence"])
	assert.Equal(t, insight.Timestamp.Unix(), node["timestamp"])
	assert.Equal(t, "Insight", node["created_at"].(time.Time).Format("2006-01-02")) // Should be today
}

func TestProductionNeo4jIntelligenceStore_BuildPatternNode(t *testing.T) {
	store := &ProductionNeo4jIntelligenceStore{}

	pattern := &LearnedPattern{
		ID:           "test-pattern",
		Name:         "Test Pattern",
		Type:         "statistical",
		Domain:       "k8s",
		DiscoveredAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		MatchCount:   5,
		Confidence:   0.8,
	}

	node := store.buildPatternNode(pattern)
	assert.Equal(t, pattern.ID, node["id"])
	assert.Equal(t, pattern.Name, node["name"])
	assert.Equal(t, pattern.Type, node["type"])
	assert.Equal(t, pattern.Domain, node["domain"])
	assert.Equal(t, pattern.DiscoveredAt.Unix(), node["discovered_at"])
	assert.Equal(t, pattern.MatchCount, node["match_count"])
	assert.Equal(t, pattern.Confidence, node["confidence"])
}

func TestProductionNeo4jIntelligenceStore_BuildTimeRangeFilter(t *testing.T) {
	store := &ProductionNeo4jIntelligenceStore{}

	tests := []struct {
		name      string
		timeRange *TimeRange
		expected  string
	}{
		{
			name:      "nil_time_range",
			timeRange: nil,
			expected:  "",
		},
		{
			name: "with_time_range",
			timeRange: &TimeRange{
				From: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				To:   time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
			},
			expected: "AND i.timestamp >= $from_time AND i.timestamp <= $to_time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.buildTimeRangeFilter(tt.timeRange)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProductionNeo4jIntelligenceStore_BuildTypeFilter(t *testing.T) {
	store := &ProductionNeo4jIntelligenceStore{}

	tests := []struct {
		name     string
		types    []string
		expected string
	}{
		{
			name:     "empty_types",
			types:    []string{},
			expected: "",
		},
		{
			name:     "single_type",
			types:    []string{"memory_exhaustion"},
			expected: "AND i.type IN $types",
		},
		{
			name:     "multiple_types",
			types:    []string{"memory_exhaustion", "cpu_spike"},
			expected: "AND i.type IN $types",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.buildTypeFilter(tt.types)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProductionNeo4jIntelligenceStore_ConvertToInsight(t *testing.T) {
	store := &ProductionNeo4jIntelligenceStore{}

	data := map[string]interface{}{
		"id":                 "insight-1",
		"title":              "Test Insight",
		"type":               "memory_exhaustion",
		"summary":            "Memory usage high",
		"overall_confidence": 0.85,
		"timestamp":          int64(1672574400), // 2023-01-01 12:00:00 UTC
	}

	insight := store.convertToInsight(data)
	assert.Equal(t, "insight-1", insight.ID)
	assert.Equal(t, "Test Insight", insight.Title)
	assert.Equal(t, "memory_exhaustion", insight.Type)
	assert.Equal(t, "Memory usage high", insight.Summary)
	assert.Equal(t, 0.85, insight.OverallConfidence)
	assert.Equal(t, int64(1672574400), insight.Timestamp.Unix())
}

func TestProductionNeo4jIntelligenceStore_ConvertToPattern(t *testing.T) {
	store := &ProductionNeo4jIntelligenceStore{}

	data := map[string]interface{}{
		"id":            "pattern-1",
		"name":          "Test Pattern",
		"type":          "statistical",
		"domain":        "k8s",
		"discovered_at": int64(1672574400), // 2023-01-01 12:00:00 UTC
		"match_count":   5,
		"confidence":    0.8,
	}

	pattern := store.convertToPattern(data)
	assert.Equal(t, "pattern-1", pattern.ID)
	assert.Equal(t, "Test Pattern", pattern.Name)
	assert.Equal(t, "statistical", pattern.Type)
	assert.Equal(t, "k8s", pattern.Domain)
	assert.Equal(t, int64(1672574400), pattern.DiscoveredAt.Unix())
	assert.Equal(t, 5, pattern.MatchCount)
	assert.Equal(t, 0.8, pattern.Confidence)
}
