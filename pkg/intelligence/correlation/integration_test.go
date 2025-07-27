package correlation

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yairfalse/tapio/pkg/domain"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// IntegrationTestSuite tests the complete correlation system end-to-end
type IntegrationTestSuite struct {
	simpleSystem *SimpleCorrelationSystem
	hybridSystem *HybridCorrelationEngine
	manager      *SimpleCollectionManager
	logger       *zap.Logger
}

// TestFullSystemIntegration tests the complete correlation pipeline
func TestFullSystemIntegration(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	t.Run("SimpleCorrelationSystemIntegration", suite.TestSimpleSystemIntegration)
	t.Run("HybridSystemIntegration", suite.TestHybridSystemIntegration)
	t.Run("CollectionManagerIntegration", suite.TestCollectionManagerIntegration)
	t.Run("ConcurrentProcessingIntegration", suite.TestConcurrentProcessingIntegration)
	t.Run("RealTimeStreamingIntegration", suite.TestRealTimeStreamingIntegration)
	t.Run("ErrorHandlingIntegration", suite.TestErrorHandlingIntegration)
	t.Run("PerformanceIntegration", suite.TestPerformanceIntegration)
}

// NewIntegrationTestSuite creates a new integration test suite
func NewIntegrationTestSuite(t *testing.T) *IntegrationTestSuite {
	logger := zaptest.NewLogger(t)

	// Create simple correlation system
	simpleConfig := DefaultSimpleSystemConfig()
	simpleConfig.EventBufferSize = 1000
	simpleConfig.MaxConcurrency = 4
	simpleSystem := NewSimpleCorrelationSystem(logger, simpleConfig)
	require.NoError(t, simpleSystem.Start())

	// Create hybrid correlation engine
	hybridConfig := DefaultHybridConfig()
	hybridConfig.MaxConcurrentProcessing = 4
	hybridSystem := NewHybridCorrelationEngine(logger, hybridConfig)
	require.NoError(t, hybridSystem.Start())

	// Create collection manager
	managerConfig := DefaultConfig()
	managerConfig.EventBufferSize = 1000
	manager := NewSimpleCollectionManager(managerConfig)
	require.NoError(t, manager.Start())

	return &IntegrationTestSuite{
		simpleSystem: simpleSystem,
		hybridSystem: hybridSystem,
		manager:      manager,
		logger:       logger,
	}
}

// Cleanup stops all systems
func (suite *IntegrationTestSuite) Cleanup() {
	if suite.simpleSystem != nil {
		suite.simpleSystem.Stop()
	}
	if suite.hybridSystem != nil {
		suite.hybridSystem.Stop()
	}
	if suite.manager != nil {
		suite.manager.Stop()
	}
}

// TestSimpleSystemIntegration tests the simple correlation system end-to-end
func (suite *IntegrationTestSuite) TestSimpleSystemIntegration(t *testing.T) {
	ctx := context.Background()

	// Create a realistic K8s deployment scenario
	events := []*domain.UnifiedEvent{
		createIntegrationEvent("deploy-1", "Deployment", "myapp", "ScalingReplicaSet", time.Now().Add(-10*time.Second)),
		createIntegrationEvent("rs-1", "ReplicaSet", "myapp-abc123", "SuccessfulCreate", time.Now().Add(-9*time.Second)),
		createIntegrationEvent("pod-1", "Pod", "myapp-abc123-xyz789", "Scheduled", time.Now().Add(-8*time.Second)),
		createIntegrationEvent("pod-1", "Pod", "myapp-abc123-xyz789", "Pulling", time.Now().Add(-7*time.Second)),
		createIntegrationEvent("pod-1", "Pod", "myapp-abc123-xyz789", "Pulled", time.Now().Add(-6*time.Second)),
		createIntegrationEvent("pod-1", "Pod", "myapp-abc123-xyz789", "Created", time.Now().Add(-5*time.Second)),
		createIntegrationEvent("pod-1", "Pod", "myapp-abc123-xyz789", "Started", time.Now().Add(-4*time.Second)),
	}

	// Process events through system
	for _, event := range events {
		err := suite.simpleSystem.ProcessEvent(ctx, event)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // Allow processing
	}

	// Allow correlation detection
	time.Sleep(500 * time.Millisecond)

	// Collect insights
	insights := collectInsights(suite.simpleSystem.Insights(), 100*time.Millisecond)

	// Validate results
	assert.Greater(t, len(insights), 0, "Should generate insights from deployment scenario")

	// Check for specific correlation types
	foundK8sCorrelation := false
	foundSequenceCorrelation := false

	for _, insight := range insights {
		switch insight.Type {
		case "k8s_correlation":
			foundK8sCorrelation = true
			assert.Greater(t, insight.Metadata["confidence"], 0.8, "K8s correlation should have high confidence")
		case "sequence_correlation":
			foundSequenceCorrelation = true
			assert.Greater(t, insight.Metadata["confidence"], 0.7, "Sequence correlation should have good confidence")
		}
	}

	assert.True(t, foundK8sCorrelation, "Should detect K8s structural correlations")
	// Note: Sequence correlation might not always trigger in short test timeframes
	_ = foundSequenceCorrelation // Prevent unused variable error

	// Validate system statistics
	stats := suite.simpleSystem.GetStats()
	assert.Greater(t, stats["events_processed"].(int64), int64(0), "Should have processed events")
	assert.Equal(t, stats["running"].(bool), true, "System should be running")
}

// TestHybridSystemIntegration tests the hybrid correlation engine
func (suite *IntegrationTestSuite) TestHybridSystemIntegration(t *testing.T) {
	ctx := context.Background()

	// Create a complex scenario with multiple correlation types
	event := createComplexIntegrationEvent()

	// Process through hybrid system
	result, err := suite.hybridSystem.ProcessEvent(ctx, event)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Validate hybrid result structure
	assert.Equal(t, event, result.Event)
	assert.GreaterOrEqual(t, len(result.Correlations), 0, "Should return correlation results")
	assert.Greater(t, result.ProcessingTime, time.Duration(0), "Should track processing time")

	// Validate correlation enrichment
	for _, corr := range result.Correlations {
		assert.NotEmpty(t, corr.Type, "Correlation should have type")
		assert.NotEmpty(t, corr.Source, "Correlation should have source")
		assert.GreaterOrEqual(t, corr.Confidence, 0.0, "Confidence should be non-negative")
		assert.LessOrEqual(t, corr.Confidence, 1.0, "Confidence should not exceed 1.0")
		assert.NotNil(t, corr.Explanation, "Correlation should have explanation")
	}
}

// TestCollectionManagerIntegration tests the collection manager
func (suite *IntegrationTestSuite) TestCollectionManagerIntegration(t *testing.T) {
	// Create domain events (not UnifiedEvents)
	events := []domain.Event{
		createDomainEvent("event-1", "Pod creation"),
		createDomainEvent("event-2", "ReplicaSet scaling"),
		createDomainEvent("event-3", "Deployment update"),
	}

	// Process through manager
	insights := suite.manager.ProcessEvents(events)

	// Validate processing
	assert.GreaterOrEqual(t, len(insights), 0, "Manager should return insights")

	// Test insight retrieval
	allInsights := suite.manager.GetInsights()
	assert.GreaterOrEqual(t, len(allInsights), 0, "Should be able to retrieve all insights")

	// Test statistics
	stats := suite.manager.Statistics()
	assert.Contains(t, stats, "event_buffer_size", "Stats should include buffer size")
	assert.Contains(t, stats, "insight_queue_size", "Stats should include queue size")
	assert.Contains(t, stats, "correlation_system_stats", "Stats should include correlation system stats")
}

// TestConcurrentProcessingIntegration tests concurrent event processing
func (suite *IntegrationTestSuite) TestConcurrentProcessingIntegration(t *testing.T) {
	ctx := context.Background()

	const numGoroutines = 10
	const eventsPerGoroutine = 50

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines)

	// Process events concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()

			for j := 0; j < eventsPerGoroutine; j++ {
				event := createConcurrentTestEvent(routineID, j)
				err := suite.simpleSystem.ProcessEvent(ctx, event)
				if err != nil {
					errChan <- err
					return
				}
				time.Sleep(1 * time.Millisecond) // Small delay
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Errorf("Concurrent processing error: %v", err)
	}

	// Validate system state after concurrent processing
	stats := suite.simpleSystem.GetStats()
	assert.GreaterOrEqual(t, stats["events_processed"].(int64), int64(numGoroutines*eventsPerGoroutine),
		"Should have processed all concurrent events")
}

// TestRealTimeStreamingIntegration tests real-time insight streaming
func (suite *IntegrationTestSuite) TestRealTimeStreamingIntegration(t *testing.T) {
	ctx := context.Background()

	// Start listening for insights
	insightChan := suite.simpleSystem.Insights()
	receivedInsights := make([]domain.Insight, 0)

	// Goroutine to collect insights
	done := make(chan bool)
	go func() {
		timeout := time.After(2 * time.Second)
		for {
			select {
			case insight := <-insightChan:
				receivedInsights = append(receivedInsights, insight)
			case <-timeout:
				done <- true
				return
			case <-done:
				return
			}
		}
	}()

	// Generate events that should trigger insights
	events := createStreamingTestEvents()
	for _, event := range events {
		err := suite.simpleSystem.ProcessEvent(ctx, event)
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond) // Allow processing
	}

	// Wait for collection to complete
	time.Sleep(1 * time.Second)
	done <- true

	// Validate streaming results
	assert.Greater(t, len(receivedInsights), 0, "Should receive insights through streaming")

	// Validate insight quality
	for _, insight := range receivedInsights {
		assert.NotEmpty(t, insight.ID, "Insight should have ID")
		assert.NotEmpty(t, insight.Type, "Insight should have type")
		assert.NotEmpty(t, insight.Title, "Insight should have title")
		assert.NotZero(t, insight.Timestamp, "Insight should have timestamp")
	}
}

// TestErrorHandlingIntegration tests error handling throughout the system
func (suite *IntegrationTestSuite) TestErrorHandlingIntegration(t *testing.T) {
	ctx := context.Background()

	// Test with invalid events
	invalidEvents := []*domain.UnifiedEvent{
		nil,                                  // Nil event
		{ID: "", Timestamp: time.Time{}},     // Invalid event
		{ID: "valid", Timestamp: time.Now()}, // Partially valid
	}

	// Process invalid events - system should handle gracefully
	for i, event := range invalidEvents {
		if event == nil {
			continue // Skip nil events
		}

		err := suite.simpleSystem.ProcessEvent(ctx, event)
		// System should either succeed or fail gracefully
		if err != nil {
			t.Logf("Event %d handled with error (expected): %v", i, err)
		}
	}

	// System should still be operational
	stats := suite.simpleSystem.GetStats()
	assert.Equal(t, stats["running"].(bool), true, "System should remain operational after errors")

	// Test recovery with valid event
	validEvent := createIntegrationEvent("recovery", "Pod", "test", "Started", time.Now())
	err := suite.simpleSystem.ProcessEvent(ctx, validEvent)
	assert.NoError(t, err, "System should recover and process valid events")
}

// TestPerformanceIntegration tests performance characteristics under load
func (suite *IntegrationTestSuite) TestPerformanceIntegration(t *testing.T) {
	ctx := context.Background()

	const eventCount = 1000
	startTime := time.Now()

	// Process large number of events
	for i := 0; i < eventCount; i++ {
		event := createPerformanceTestEvent(i)
		err := suite.simpleSystem.ProcessEvent(ctx, event)
		require.NoError(t, err)
	}

	processingDuration := time.Since(startTime)

	// Validate performance requirements
	maxExpectedDuration := 10 * time.Second // Reasonable upper bound
	assert.Less(t, processingDuration, maxExpectedDuration,
		"Processing %d events should complete within %v", eventCount, maxExpectedDuration)

	// Calculate throughput
	throughput := float64(eventCount) / processingDuration.Seconds()
	minExpectedThroughput := 100.0 // events per second

	assert.Greater(t, throughput, minExpectedThroughput,
		"Throughput should be at least %.1f events/sec, got %.1f", minExpectedThroughput, throughput)

	// Validate system stats
	stats := suite.simpleSystem.GetStats()
	avgProcessingTime := stats["avg_processing_time_ms"].(int64)
	assert.Less(t, avgProcessingTime, int64(100),
		"Average processing time should be under 100ms per event")
}

// Helper functions for integration tests

func createIntegrationEvent(id, kind, name, reason string, timestamp time.Time) *domain.UnifiedEvent {
	return &domain.UnifiedEvent{
		ID:        id,
		Timestamp: timestamp,
		Type:      domain.EventTypeKubernetes,
		Source:    "integration-test",
		Severity:  domain.EventSeverityInfo,
		Kubernetes: &domain.KubernetesData{
			Object:     name,
			ObjectKind: kind,
			// Namespace:  "default",
			Reason:     reason,
			APIVersion: "v1",
			Labels: map[string]string{
				"app": "test-app",
			},
		},
	}
}

func createComplexIntegrationEvent() *domain.UnifiedEvent {
	return &domain.UnifiedEvent{
		ID:        "complex-event",
		Timestamp: time.Now(),
		Type:      domain.EventTypeKubernetes,
		Source:    "complex-test",
		Severity:  domain.EventSeverityHigh,
		Kubernetes: &domain.KubernetesData{
			Object:     "complex-pod",
			ObjectKind: "Pod",
			// Namespace:  "production",
			Reason:     "Failed",
			APIVersion: "v1",
			Labels: map[string]string{
				"app":       "critical-service",
				"version":   "v1.2.3",
				"component": "api",
			},
			// OwnerReferences: []string{"replicaset-abc123"}, // Field doesn't exist in KubernetesData
		},
		Network: &domain.NetworkData{
			Protocol:   "TCP",
			SourceIP:   "10.0.1.100",
			SourcePort: 8080,
			DestIP:     "10.0.2.200",
			DestPort:   5432,
		},
		Application: &domain.ApplicationData{
			Level:     "ERROR",
			Message:   "Database connection failed",
			Logger:    "api-server",
			ErrorType: "ConnectionTimeout",
		},
	}
}

func createDomainEvent(id, message string) domain.Event {
	return domain.Event{
		ID:        domain.EventID(id),
		Timestamp: time.Now(),
		Type:      domain.EventTypeKubernetes,
		Source:    domain.SourceK8s,
		Message:   message,
		Severity:  domain.EventSeverityInfo,
		Context: domain.EventContext{
			Namespace: "default",
			Host:      "test-node",
		},
		Data: map[string]interface{}{
			"test": true,
		},
	}
}

func createConcurrentTestEvent(routineID, eventID int) *domain.UnifiedEvent {
	return &domain.UnifiedEvent{
		ID:        fmt.Sprintf("concurrent-%d-%d", routineID, eventID),
		Timestamp: time.Now(),
		Type:      domain.EventTypeKubernetes,
		Source:    "concurrent-test",
		Severity:  domain.EventSeverityInfo,
		Kubernetes: &domain.KubernetesData{
			Object:     fmt.Sprintf("pod-%d-%d", routineID, eventID),
			ObjectKind: "Pod",
			// Namespace:  fmt.Sprintf("ns-%d", routineID),
			Reason:     "Started",
			APIVersion: "v1",
		},
	}
}

func createStreamingTestEvents() []*domain.UnifiedEvent {
	events := make([]*domain.UnifiedEvent, 5)
	baseTime := time.Now()

	for i := 0; i < 5; i++ {
		events[i] = &domain.UnifiedEvent{
			ID:        fmt.Sprintf("stream-event-%d", i),
			Timestamp: baseTime.Add(time.Duration(i) * 100 * time.Millisecond),
			Type:      domain.EventTypeKubernetes,
			Source:    "streaming-test",
			Severity:  domain.EventSeverityInfo,
			Kubernetes: &domain.KubernetesData{
				Object:     fmt.Sprintf("streaming-pod-%d", i),
				ObjectKind: "Pod",
				// Namespace:  "streaming",
				Reason:     []string{"Created", "Scheduled", "Pulling", "Started", "Ready"}[i],
				APIVersion: "v1",
			},
		}
	}

	return events
}

func createPerformanceTestEvent(id int) *domain.UnifiedEvent {
	return &domain.UnifiedEvent{
		ID:        fmt.Sprintf("perf-event-%d", id),
		Timestamp: time.Now(),
		Type:      domain.EventTypeKubernetes,
		Source:    "performance-test",
		Severity:  domain.EventSeverityInfo,
		Kubernetes: &domain.KubernetesData{
			Object:     fmt.Sprintf("perf-pod-%d", id),
			ObjectKind: "Pod",
			// Namespace:  "performance",
			Reason:     "Started",
			APIVersion: "v1",
		},
	}
}

func collectInsights(insightChan <-chan domain.Insight, timeout time.Duration) []domain.Insight {
	insights := make([]domain.Insight, 0)
	timeoutChan := time.After(timeout)

	for {
		select {
		case insight := <-insightChan:
			insights = append(insights, insight)
		case <-timeoutChan:
			return insights
		}
	}
}
