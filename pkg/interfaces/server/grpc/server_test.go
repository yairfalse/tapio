package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yairfalse/tapio/pkg/dataflow"
	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/integrations/collector-manager"
	"github.com/yairfalse/tapio/pkg/intelligence/correlation"
	pb "github.com/yairfalse/tapio/proto/gen/tapio/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// TestUnifiedServer tests the unified gRPC and REST server
func TestUnifiedServer(t *testing.T) {
	// Create logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	// Create test configuration
	config := DefaultUnifiedServerConfig()
	config.GRPCAddress = ":0" // Use random port
	config.HTTPAddress = ":0" // Use random port
	config.EnableAuth = false // Disable auth for testing

	// Create unified server
	server, err := NewUnifiedServer(config, logger)
	require.NoError(t, err)

	// Create mock dependencies
	collectorMgr := manager.NewCollectorManager()
	dataFlow := &dataflow.TapioDataFlow{}
	correlationEngine := correlation.NewSemanticCorrelationEngine()

	// Set dependencies
	server.SetDependencies(collectorMgr, dataFlow, correlationEngine)

	// Start server
	ctx := context.Background()
	err = server.Start(ctx)
	require.NoError(t, err)
	defer server.Stop(context.Background())

	// Get actual addresses
	grpcAddr := server.grpcListener.Addr().String()
	httpAddr := server.httpListener.Addr().String()

	// Test gRPC endpoints
	t.Run("gRPC", func(t *testing.T) {
		testGRPCEndpoints(t, grpcAddr)
	})

	// Test REST endpoints
	t.Run("REST", func(t *testing.T) {
		testRESTEndpoints(t, httpAddr)
	})

	// Test health checks
	t.Run("HealthChecks", func(t *testing.T) {
		testHealthChecks(t, grpcAddr, httpAddr)
	})
}

func testGRPCEndpoints(t *testing.T, grpcAddr string) {
	// Create gRPC connection
	conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	t.Run("TapioService", func(t *testing.T) {
		client := pb.NewTapioServiceClient(conn)
		
		// Test GetStatus
		resp, err := client.GetStatus(context.Background(), &pb.GetStatusRequest{})
		require.NoError(t, err)
		assert.Equal(t, pb.SystemStatus_SYSTEM_STATUS_HEALTHY, resp.Status)
		assert.NotEmpty(t, resp.Version)
		assert.Greater(t, resp.Uptime, int64(0))
		
		// Test GetConfiguration
		configResp, err := client.GetConfiguration(context.Background(), &pb.GetConfigurationRequest{})
		require.NoError(t, err)
		assert.NotEmpty(t, configResp.Environment)
		assert.NotEmpty(t, configResp.Features)
	})

	t.Run("EventService", func(t *testing.T) {
		client := pb.NewEventServiceClient(conn)
		
		// Test SubmitEvent
		event := &pb.Event{
			Id:        "test_event_001",
			Type:      pb.EventType_EVENT_TYPE_NETWORK,
			Severity:  pb.EventSeverity_EVENT_SEVERITY_INFO,
			Timestamp: timestamppb(),
			Message:   "Test event from integration test",
		}
		
		submitResp, err := client.SubmitEvent(context.Background(), &pb.SubmitEventRequest{
			Event: event,
		})
		require.NoError(t, err)
		assert.Equal(t, "test_event_001", submitResp.EventId)
		assert.Equal(t, "accepted", submitResp.Status)
		
		// Test QueryEvents
		queryResp, err := client.QueryEvents(context.Background(), &pb.QueryEventsRequest{
			Filter: &pb.Filter{
				Limit: 10,
			},
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, queryResp.TotalCount, int64(1))
	})

	t.Run("CollectorService", func(t *testing.T) {
		client := pb.NewCollectorServiceClient(conn)
		
		// Test ListCollectors
		resp, err := client.ListCollectors(context.Background(), &pb.ListCollectorsRequest{})
		require.NoError(t, err)
		assert.NotNil(t, resp.Collectors)
		
		// Test GetCollectorHealth
		healthResp, err := client.GetCollectorHealth(context.Background(), &pb.GetCollectorHealthRequest{
			CollectorName: "systemd",
		})
		require.NoError(t, err)
		assert.Equal(t, "systemd", healthResp.CollectorName)
		assert.Equal(t, pb.CollectorStatus_COLLECTOR_STATUS_RUNNING, healthResp.Status)
	})

	t.Run("CorrelationService", func(t *testing.T) {
		client := pb.NewCorrelationServiceClient(conn)
		
		// Test AnalyzeEvents
		events := []*pb.Event{
			{
				Id:        "corr_test_001",
				Type:      pb.EventType_EVENT_TYPE_NETWORK,
				Timestamp: timestamppb(),
				Message:   "Network event for correlation",
			},
			{
				Id:        "corr_test_002",
				Type:      pb.EventType_EVENT_TYPE_KUBERNETES,
				Timestamp: timestamppb(),
				Message:   "Kubernetes event for correlation",
			},
		}
		
		analyzeResp, err := client.AnalyzeEvents(context.Background(), &pb.AnalyzeEventsRequest{
			Events:       events,
			AnalysisType: pb.AnalysisType_ANALYSIS_TYPE_SEMANTIC,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, analyzeResp.AnalysisId)
		assert.Equal(t, pb.AnalysisStatus_ANALYSIS_STATUS_COMPLETED, analyzeResp.Status)
		
		// Test GetCorrelations
		corrResp, err := client.GetCorrelations(context.Background(), &pb.GetCorrelationsRequest{
			Limit: 10,
		})
		require.NoError(t, err)
		assert.NotNil(t, corrResp.Correlations)
	})

	t.Run("ObservabilityService", func(t *testing.T) {
		client := pb.NewObservabilityServiceClient(conn)
		
		// Test GetMetrics
		resp, err := client.GetMetrics(context.Background(), &pb.GetMetricsRequest{})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Metrics)
		assert.Greater(t, resp.TotalCount, int32(0))
	})
}

func testRESTEndpoints(t *testing.T, httpAddr string) {
	baseURL := fmt.Sprintf("http://%s/api/v1", httpAddr)

	t.Run("EventSubmission", func(t *testing.T) {
		// Submit single event
		event := EventIngestRequest{
			ID:        "rest_test_001",
			Type:      "network",
			Severity:  "info",
			Timestamp: time.Now(),
			Message:   "REST API test event",
			Service:   "test-service",
			Data: map[string]interface{}{
				"test": true,
			},
		}
		
		body, _ := json.Marshal(event)
		resp, err := http.Post(baseURL+"/events", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusAccepted, resp.StatusCode)
		
		var result EventIngestResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, "rest_test_001", result.EventID)
		assert.Equal(t, "accepted", result.Status)
	})

	t.Run("BulkEventSubmission", func(t *testing.T) {
		// Submit bulk events
		events := []EventIngestRequest{
			{
				ID:        "bulk_001",
				Type:      "kubernetes",
				Severity:  "warning",
				Timestamp: time.Now(),
				Message:   "Bulk event 1",
			},
			{
				ID:        "bulk_002",
				Type:      "system",
				Severity:  "error",
				Timestamp: time.Now(),
				Message:   "Bulk event 2",
			},
		}
		
		body, _ := json.Marshal(events)
		resp, err := http.Post(baseURL+"/events/bulk", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusAccepted, resp.StatusCode)
		
		var result BulkIngestResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, 2, result.Total)
		assert.Equal(t, 2, result.Success)
		assert.Equal(t, 0, result.Failed)
	})

	t.Run("EventSearch", func(t *testing.T) {
		// Search events
		searchReq := EventSearchRequest{
			Query: "type:network",
			TimeRange: TimeRange{
				Start: time.Now().Add(-1 * time.Hour),
				End:   time.Now(),
			},
			Limit: 10,
		}
		
		body, _ := json.Marshal(searchReq)
		resp, err := http.Post(baseURL+"/events/search", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var result EventSearchResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, "type:network", result.Query)
		assert.NotNil(t, result.Events)
		assert.NotNil(t, result.Facets)
	})

	t.Run("CollectorStatus", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/collectors/status")
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var result CollectorStatusResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.NotEmpty(t, result.Collectors)
		assert.Greater(t, result.EventsPerSecond, float64(0))
	})

	t.Run("AnalyticsSummary", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/analytics/summary")
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var result AnalyticsSummaryResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.NotNil(t, result.EventStatistics)
		assert.NotNil(t, result.CorrelationStatistics)
	})

	t.Run("SystemInfo", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/system/info")
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var result SystemInfoResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, "1.0.0", result.Version)
		assert.NotEmpty(t, result.Platform)
		assert.NotEmpty(t, result.Features)
		assert.NotNil(t, result.Limits)
	})
}

func testHealthChecks(t *testing.T, grpcAddr, httpAddr string) {
	t.Run("gRPC Health", func(t *testing.T) {
		conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()
		
		client := grpc_health_v1.NewHealthClient(conn)
		resp, err := client.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("REST Health", func(t *testing.T) {
		// Basic health
		resp, err := http.Get(fmt.Sprintf("http://%s/health", httpAddr))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var health map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&health)
		require.NoError(t, err)
		assert.Equal(t, "healthy", health["status"])
		
		// Readiness check
		resp, err = http.Get(fmt.Sprintf("http://%s/health/ready", httpAddr))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		// Liveness check
		resp, err = http.Get(fmt.Sprintf("http://%s/health/live", httpAddr))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		// Detailed health
		resp, err = http.Get(fmt.Sprintf("http://%s/api/v1/system/health/detailed", httpAddr))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var detailed DetailedHealthResponse
		err = json.NewDecoder(resp.Body).Decode(&detailed)
		require.NoError(t, err)
		assert.Equal(t, "healthy", detailed.Status)
		assert.NotEmpty(t, detailed.Components)
		assert.NotEmpty(t, detailed.Checks)
	})
}

// TestEventStreaming tests real-time event streaming
func TestEventStreaming(t *testing.T) {
	// Create and start server
	logger, _ := zap.NewDevelopment()
	config := DefaultUnifiedServerConfig()
	config.GRPCAddress = ":0"
	config.HTTPAddress = ":0"
	
	server, err := NewUnifiedServer(config, logger)
	require.NoError(t, err)
	
	err = server.Start(context.Background())
	require.NoError(t, err)
	defer server.Stop(context.Background())
	
	httpAddr := server.httpListener.Addr().String()
	
	t.Run("SSE Streaming", func(t *testing.T) {
		// Create SSE request
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/api/v1/events/stream", httpAddr), nil)
		require.NoError(t, err)
		req.Header.Set("Accept", "text/event-stream")
		
		// Create client with timeout
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
		
		// Read first event (should be connected event)
		buf := make([]byte, 1024)
		n, err := resp.Body.Read(buf)
		require.NoError(t, err)
		assert.Contains(t, string(buf[:n]), "event: connected")
	})
}

// TestConcurrentRequests tests server under concurrent load
func TestConcurrentRequests(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultUnifiedServerConfig()
	config.GRPCAddress = ":0"
	config.HTTPAddress = ":0"
	config.MaxRequestsPerSec = 1000
	
	server, err := NewUnifiedServer(config, logger)
	require.NoError(t, err)
	
	err = server.Start(context.Background())
	require.NoError(t, err)
	defer server.Stop(context.Background())
	
	httpAddr := server.httpListener.Addr().String()
	baseURL := fmt.Sprintf("http://%s/api/v1", httpAddr)
	
	// Run concurrent requests
	concurrency := 10
	requestsPerWorker := 100
	
	type result struct {
		success int
		failed  int
	}
	
	results := make(chan result, concurrency)
	
	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			r := result{}
			
			for j := 0; j < requestsPerWorker; j++ {
				event := EventIngestRequest{
					ID:        fmt.Sprintf("concurrent_%d_%d", workerID, j),
					Type:      "test",
					Severity:  "info",
					Timestamp: time.Now(),
					Message:   fmt.Sprintf("Concurrent test event from worker %d", workerID),
				}
				
				body, _ := json.Marshal(event)
				resp, err := http.Post(baseURL+"/events", "application/json", bytes.NewReader(body))
				
				if err == nil && resp.StatusCode == http.StatusAccepted {
					r.success++
					resp.Body.Close()
				} else {
					r.failed++
					if resp != nil {
						resp.Body.Close()
					}
				}
			}
			
			results <- r
		}(i)
	}
	
	// Collect results
	totalSuccess := 0
	totalFailed := 0
	
	for i := 0; i < concurrency; i++ {
		r := <-results
		totalSuccess += r.success
		totalFailed += r.failed
	}
	
	// Verify results
	t.Logf("Concurrent test results: %d successful, %d failed", totalSuccess, totalFailed)
	assert.Greater(t, totalSuccess, 0)
	assert.Less(t, float64(totalFailed)/float64(totalSuccess+totalFailed), 0.1) // Less than 10% failure rate
}

// TestErrorHandling tests error scenarios
func TestErrorHandling(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultUnifiedServerConfig()
	config.GRPCAddress = ":0"
	config.HTTPAddress = ":0"
	
	server, err := NewUnifiedServer(config, logger)
	require.NoError(t, err)
	
	err = server.Start(context.Background())
	require.NoError(t, err)
	defer server.Stop(context.Background())
	
	httpAddr := server.httpListener.Addr().String()
	baseURL := fmt.Sprintf("http://%s/api/v1", httpAddr)
	
	t.Run("Invalid JSON", func(t *testing.T) {
		resp, err := http.Post(baseURL+"/events", "application/json", bytes.NewReader([]byte("invalid json")))
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		
		var errResp ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Bad Request", errResp.Error)
		assert.Contains(t, errResp.Message, "Invalid JSON")
	})
	
	t.Run("Method Not Allowed", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/events/search") // Should be POST
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})
	
	t.Run("Not Found", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/nonexistent")
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// Helper function to create timestamp
func timestamppb() *timestamppb.Timestamp {
	return &timestamppb.Timestamp{
		Seconds: time.Now().Unix(),
		Nanos:   int32(time.Now().Nanosecond()),
	}
}

// Timestamp type for proto compatibility
type timestamppb struct{}

func (t *timestamppb) Timestamp() *pb.Timestamp {
	now := time.Now()
	return &pb.Timestamp{
		Seconds: now.Unix(),
		Nanos:   int32(now.Nanosecond()),
	}
}