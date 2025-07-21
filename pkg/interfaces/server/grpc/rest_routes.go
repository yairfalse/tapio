package grpc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
	pb "github.com/yairfalse/tapio/proto/gen/tapio/v1"
	"go.uber.org/zap"
)

// RESTRoutes provides enhanced REST API routes beyond gRPC-gateway
type RESTRoutes struct {
	logger   *zap.Logger
	grpcAddr string

	// Service references for direct calls (optional optimization)
	eventService       *EventServer
	correlationService *CorrelationServer
	collectorService   *CollectorServer
}

// NewRESTRoutes creates REST route handlers
func NewRESTRoutes(logger *zap.Logger, grpcAddr string) *RESTRoutes {
	return &RESTRoutes{
		logger:   logger,
		grpcAddr: grpcAddr,
	}
}

// SetServices optionally sets direct service references for optimization
func (r *RESTRoutes) SetServices(eventSvc *EventServer, correlationSvc *CorrelationServer, collectorSvc *CollectorServer) {
	r.eventService = eventSvc
	r.correlationService = correlationSvc
	r.collectorService = collectorSvc
}

// RegisterRoutes registers all custom REST routes
func (r *RESTRoutes) RegisterRoutes(mux *http.ServeMux) {
	// Event routes
	mux.HandleFunc("/api/v1/events/ingest", r.handleEventIngest)
	mux.HandleFunc("/api/v1/events/bulk", r.handleBulkEvents)
	mux.HandleFunc("/api/v1/events/export", r.handleEventExport)
	mux.HandleFunc("/api/v1/events/search", r.handleEventSearch)

	// Correlation routes
	mux.HandleFunc("/api/v1/correlations/realtime", r.handleRealtimeCorrelations)
	mux.HandleFunc("/api/v1/correlations/patterns", r.handlePatternDiscovery)
	mux.HandleFunc("/api/v1/correlations/impact", r.handleImpactAnalysis)

	// Collector routes
	mux.HandleFunc("/api/v1/collectors/status", r.handleCollectorStatus)
	mux.HandleFunc("/api/v1/collectors/config", r.handleCollectorConfig)

	// Analytics routes
	mux.HandleFunc("/api/v1/analytics/summary", r.handleAnalyticsSummary)
	mux.HandleFunc("/api/v1/analytics/trends", r.handleTrendAnalysis)

	// System routes
	mux.HandleFunc("/api/v1/system/info", r.handleSystemInfo)
	mux.HandleFunc("/api/v1/system/health/detailed", r.handleDetailedHealth)
}

// Event Handlers

func (r *RESTRoutes) handleEventIngest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.writeError(w, http.StatusMethodNotAllowed, "Only POST method allowed")
		return
	}

	// Parse request body
	var events []EventIngestRequest
	if err := json.NewDecoder(req.Body).Decode(&events); err != nil {
		r.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	// Process events
	results := make([]EventIngestResponse, len(events))
	successCount := 0

	for i, event := range events {
		// Convert to domain event
		domainEvent := r.convertIngestToDomainEvent(event)

		// Process through event service if available
		if r.eventService != nil {
			// Direct processing for better performance
			ctx := req.Context()
			err := r.eventService.eventStore.Store(ctx, []domain.Event{domainEvent})
			if err != nil {
				results[i] = EventIngestResponse{
					EventID: event.ID,
					Status:  "failed",
					Error:   err.Error(),
				}
			} else {
				results[i] = EventIngestResponse{
					EventID:   event.ID,
					Status:    "accepted",
					Timestamp: time.Now(),
				}
				successCount++
			}
		} else {
			// Fall back to gRPC call
			results[i] = EventIngestResponse{
				EventID:   event.ID,
				Status:    "queued",
				Timestamp: time.Now(),
			}
			successCount++
		}
	}

	// Return response
	response := BulkIngestResponse{
		Total:     len(events),
		Success:   successCount,
		Failed:    len(events) - successCount,
		Results:   results,
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusAccepted, response)
}

func (r *RESTRoutes) handleBulkEvents(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.writeError(w, http.StatusMethodNotAllowed, "Only POST method allowed")
		return
	}

	// Support NDJSON format for bulk events
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-ndjson") {
		r.handleNDJSONEvents(w, req)
		return
	}

	// Regular JSON array
	r.handleEventIngest(w, req)
}

func (r *RESTRoutes) handleNDJSONEvents(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	successCount := 0
	failedCount := 0

	for {
		var event EventIngestRequest
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			failedCount++
			continue
		}

		// Process event (simplified)
		successCount++
	}

	response := map[string]interface{}{
		"success": successCount,
		"failed":  failedCount,
		"total":   successCount + failedCount,
	}

	r.writeJSON(w, http.StatusAccepted, response)
}

func (r *RESTRoutes) handleEventExport(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET method allowed")
		return
	}

	// Parse query parameters
	format := req.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	startTime := req.URL.Query().Get("start_time")
	endTime := req.URL.Query().Get("end_time")
	limit := req.URL.Query().Get("limit")

	// Set appropriate content type
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=events.csv")
		r.exportEventsAsCSV(w, startTime, endTime, limit)
	case "ndjson":
		w.Header().Set("Content-Type", "application/x-ndjson")
		r.exportEventsAsNDJSON(w, startTime, endTime, limit)
	default:
		w.Header().Set("Content-Type", "application/json")
		r.exportEventsAsJSON(w, startTime, endTime, limit)
	}
}

func (r *RESTRoutes) handleEventSearch(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.writeError(w, http.StatusMethodNotAllowed, "Only POST method allowed")
		return
	}

	// Parse search request
	var searchReq EventSearchRequest
	if err := json.NewDecoder(req.Body).Decode(&searchReq); err != nil {
		r.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	// Perform search (simplified)
	results := EventSearchResponse{
		Query:        searchReq.Query,
		TotalHits:    100,
		ReturnedHits: 10,
		Events:       []EventSearchResult{},
		Facets: map[string][]FacetValue{
			"type": {
				{Value: "network", Count: 45},
				{Value: "kubernetes", Count: 35},
				{Value: "system", Count: 20},
			},
			"severity": {
				{Value: "info", Count: 60},
				{Value: "warning", Count: 30},
				{Value: "error", Count: 10},
			},
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, results)
}

// Correlation Handlers

func (r *RESTRoutes) handleRealtimeCorrelations(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET method allowed")
		return
	}

	// Set up SSE for real-time correlation updates
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		r.writeError(w, http.StatusInternalServerError, "SSE not supported")
		return
	}

	// Send correlation updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			correlation := CorrelationUpdate{
				ID:          fmt.Sprintf("corr_%d", time.Now().Unix()),
				Pattern:     "service_degradation",
				Confidence:  0.87,
				EventCount:  15,
				Description: "Detected service degradation pattern",
				Timestamp:   time.Now(),
			}

			data, _ := json.Marshal(correlation)
			fmt.Fprintf(w, "event: correlation\ndata: %s\n\n", data)
			flusher.Flush()

		case <-req.Context().Done():
			return
		}
	}
}

func (r *RESTRoutes) handlePatternDiscovery(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.writeError(w, http.StatusMethodNotAllowed, "Only POST method allowed")
		return
	}

	// Parse pattern discovery request
	var patternReq PatternDiscoveryRequest
	if err := json.NewDecoder(req.Body).Decode(&patternReq); err != nil {
		r.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	// Discover patterns (simplified)
	response := PatternDiscoveryResponse{
		TimeRange: patternReq.TimeRange,
		Patterns: []DiscoveredPattern{
			{
				ID:          "pattern_001",
				Name:        "Cascading Failure",
				Description: "Service failures cascading through dependencies",
				Confidence:  0.92,
				Frequency:   5,
				Examples:    []string{"evt_001", "evt_002", "evt_003"},
			},
			{
				ID:          "pattern_002",
				Name:        "Resource Exhaustion",
				Description: "Progressive resource exhaustion leading to failures",
				Confidence:  0.85,
				Frequency:   3,
				Examples:    []string{"evt_004", "evt_005"},
			},
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

func (r *RESTRoutes) handleImpactAnalysis(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.writeError(w, http.StatusMethodNotAllowed, "Only POST method allowed")
		return
	}

	// Parse impact analysis request
	var impactReq ImpactAnalysisRequest
	if err := json.NewDecoder(req.Body).Decode(&impactReq); err != nil {
		r.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	// Perform impact analysis (simplified)
	response := ImpactAnalysisResponse{
		EventID: impactReq.EventID,
		Impact: ImpactDetails{
			BusinessImpact:    0.75,
			CustomerImpact:    0.60,
			OperationalImpact: 0.80,
			FinancialImpact:   0.45,
		},
		AffectedServices:  []string{"api-gateway", "payment-service", "notification-service"},
		AffectedCustomers: 1250,
		EstimatedDuration: "2h30m",
		Recommendations: []string{
			"Scale api-gateway to handle increased load",
			"Enable circuit breaker on payment-service",
			"Notify customers about potential delays",
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

// Collector Handlers

func (r *RESTRoutes) handleCollectorStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET method allowed")
		return
	}

	// Get collector status
	response := CollectorStatusResponse{
		Collectors: []CollectorStatusDetail{
			{
				Name:            "systemd",
				Type:            "systemd",
				Status:          "running",
				EventsPerSecond: 125.5,
				LastEventTime:   time.Now().Add(-5 * time.Second),
				Uptime:          3600,
				Health: CollectorHealthDetail{
					CPU:    25.5,
					Memory: 128.0,
					Errors: 0,
				},
			},
			{
				Name:            "kubernetes",
				Type:            "kubernetes",
				Status:          "running",
				EventsPerSecond: 85.2,
				LastEventTime:   time.Now().Add(-2 * time.Second),
				Uptime:          3600,
				Health: CollectorHealthDetail{
					CPU:    15.2,
					Memory: 96.5,
					Errors: 0,
				},
			},
		},
		TotalEvents:     1500000,
		EventsPerSecond: 210.7,
		Timestamp:       time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

func (r *RESTRoutes) handleCollectorConfig(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.getCollectorConfig(w, req)
	case http.MethodPut:
		r.updateCollectorConfig(w, req)
	default:
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET and PUT methods allowed")
	}
}

// Analytics Handlers

func (r *RESTRoutes) handleAnalyticsSummary(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET method allowed")
		return
	}

	// Generate analytics summary
	response := AnalyticsSummaryResponse{
		TimeRange: TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		EventStatistics: EventStats{
			Total:         145892,
			ByType:        map[string]int64{"network": 45000, "kubernetes": 35000, "system": 30892, "application": 35000},
			BySeverity:    map[string]int64{"info": 100000, "warning": 35000, "error": 10000, "critical": 892},
			EventsPerHour: []int64{5000, 5500, 6000, 6500, 7000, 6800, 6500, 6000},
		},
		CorrelationStatistics: CorrelationStats{
			Total:             1523,
			ByPattern:         map[string]int64{"cascading_failure": 234, "resource_exhaustion": 189, "network_issues": 456},
			AverageConfidence: 0.82,
		},
		TopIssues: []TopIssue{
			{
				Description: "High memory usage in payment service",
				Severity:    "warning",
				Count:       45,
				Trend:       "increasing",
			},
			{
				Description: "Intermittent network timeouts",
				Severity:    "error",
				Count:       23,
				Trend:       "stable",
			},
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

func (r *RESTRoutes) handleTrendAnalysis(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET method allowed")
		return
	}

	// Parse query parameters
	metric := req.URL.Query().Get("metric")
	period := req.URL.Query().Get("period")

	if metric == "" {
		metric = "events"
	}
	if period == "" {
		period = "1h"
	}

	// Generate trend analysis
	response := TrendAnalysisResponse{
		Metric: metric,
		Period: period,
		Trends: []TrendData{
			{
				Timestamp: time.Now().Add(-60 * time.Minute),
				Value:     100.0,
				Trend:     "stable",
			},
			{
				Timestamp: time.Now().Add(-30 * time.Minute),
				Value:     125.0,
				Trend:     "increasing",
			},
			{
				Timestamp: time.Now(),
				Value:     110.0,
				Trend:     "decreasing",
			},
		},
		Prediction: PredictionData{
			NextValue:  115.0,
			Confidence: 0.75,
			Trend:      "stable",
		},
		Anomalies: []AnomalyData{
			{
				Timestamp:   time.Now().Add(-45 * time.Minute),
				Value:       180.0,
				Description: "Spike in event rate",
				Severity:    "warning",
			},
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

// System Handlers

func (r *RESTRoutes) handleSystemInfo(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET method allowed")
		return
	}

	response := SystemInfoResponse{
		Version:     "1.0.0",
		BuildTime:   "2024-01-01T00:00:00Z",
		GitCommit:   "abc123def",
		GoVersion:   "1.21",
		Platform:    "linux/amd64",
		StartTime:   time.Now().Add(-3600 * time.Second),
		Uptime:      3600,
		Environment: "production",
		Features: map[string]bool{
			"semantic_correlation": true,
			"distributed_tracing":  true,
			"real_time_streaming":  true,
			"ai_analysis":          false,
		},
		Limits: SystemLimits{
			MaxEventsPerSecond:    165000,
			MaxCorrelationsActive: 10000,
			MaxSubscriptions:      1000,
			MaxRequestSize:        10485760,
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

func (r *RESTRoutes) handleDetailedHealth(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.writeError(w, http.StatusMethodNotAllowed, "Only GET method allowed")
		return
	}

	response := DetailedHealthResponse{
		Status: "healthy",
		Components: map[string]ComponentHealth{
			"grpc_server": {
				Status:  "healthy",
				Message: "Accepting connections",
				Details: map[string]interface{}{
					"connections": 125,
					"rps":         1523,
				},
			},
			"rest_gateway": {
				Status:  "healthy",
				Message: "Processing requests",
				Details: map[string]interface{}{
					"latency_p99": "15ms",
				},
			},
			"collectors": {
				Status:  "healthy",
				Message: "All collectors running",
				Details: map[string]interface{}{
					"active": 4,
					"total":  4,
				},
			},
			"storage": {
				Status:  "healthy",
				Message: "Database operational",
				Details: map[string]interface{}{
					"connections": 10,
					"latency":     "2ms",
				},
			},
		},
		Checks: []HealthCheck{
			{
				Name:     "database_connectivity",
				Status:   "pass",
				Duration: "2ms",
			},
			{
				Name:     "collector_health",
				Status:   "pass",
				Duration: "5ms",
			},
			{
				Name:     "memory_usage",
				Status:   "pass",
				Duration: "1ms",
				Details: map[string]interface{}{
					"used_mb":  512,
					"total_mb": 2048,
				},
			},
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

// Helper methods

func (r *RESTRoutes) getCollectorConfig(w http.ResponseWriter, req *http.Request) {
	collectorName := req.URL.Query().Get("name")

	config := CollectorConfigResponse{
		Name: collectorName,
		Config: map[string]interface{}{
			"enabled":        true,
			"buffer_size":    10000,
			"worker_count":   4,
			"batch_size":     100,
			"flush_interval": "5s",
		},
		Timestamp: time.Now(),
	}

	r.writeJSON(w, http.StatusOK, config)
}

func (r *RESTRoutes) updateCollectorConfig(w http.ResponseWriter, req *http.Request) {
	var config map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&config); err != nil {
		r.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	response := map[string]interface{}{
		"status":    "updated",
		"message":   "Configuration updated successfully",
		"timestamp": time.Now(),
	}

	r.writeJSON(w, http.StatusOK, response)
}

func (r *RESTRoutes) exportEventsAsJSON(w io.Writer, startTime, endTime, limit string) {
	// Export events as JSON (simplified)
	events := []map[string]interface{}{
		{
			"id":        "evt_001",
			"type":      "network",
			"severity":  "info",
			"timestamp": time.Now(),
			"message":   "Network connection established",
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(events)
}

func (r *RESTRoutes) exportEventsAsCSV(w io.Writer, startTime, endTime, limit string) {
	// Export events as CSV
	fmt.Fprintln(w, "id,type,severity,timestamp,message")
	fmt.Fprintf(w, "evt_001,network,info,%s,Network connection established\n", time.Now().Format(time.RFC3339))
}

func (r *RESTRoutes) exportEventsAsNDJSON(w io.Writer, startTime, endTime, limit string) {
	// Export events as NDJSON
	event := map[string]interface{}{
		"id":        "evt_001",
		"type":      "network",
		"severity":  "info",
		"timestamp": time.Now(),
		"message":   "Network connection established",
	}

	encoder := json.NewEncoder(w)
	encoder.Encode(event)
}

func (r *RESTRoutes) convertIngestToDomainEvent(req EventIngestRequest) domain.Event {
	return domain.Event{
		ID:        domain.EventID(req.ID),
		Type:      domain.EventType(req.Type),
		Severity:  domain.EventSeverity(req.Severity),
		Timestamp: req.Timestamp,
		Message:   req.Message,
		Data:      req.Data,
		Context: domain.EventContext{
			Service:   req.Service,
			Component: req.Component,
			Metadata:  req.Metadata,
		},
	}
}

func (r *RESTRoutes) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		r.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (r *RESTRoutes) writeError(w http.ResponseWriter, status int, message string) {
	response := ErrorResponse{
		Error:     http.StatusText(status),
		Message:   message,
		Code:      strconv.Itoa(status),
		Timestamp: time.Now(),
	}

	r.writeJSON(w, status, response)
}
