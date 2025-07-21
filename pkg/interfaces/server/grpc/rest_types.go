package grpc

import "time"

// REST API Request/Response Types

// Event Types

type EventIngestRequest struct {
	ID        string                 `json:"id" example:"evt_001"`
	Type      string                 `json:"type" example:"network"`
	Severity  string                 `json:"severity" example:"info"`
	Timestamp time.Time              `json:"timestamp" example:"2024-01-01T00:00:00Z"`
	Message   string                 `json:"message" example:"Network connection established"`
	Service   string                 `json:"service,omitempty" example:"api-gateway"`
	Component string                 `json:"component,omitempty" example:"ingress"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type EventIngestResponse struct {
	EventID   string    `json:"event_id" example:"evt_001"`
	Status    string    `json:"status" example:"accepted"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp" example:"2024-01-01T00:00:00Z"`
}

type BulkIngestResponse struct {
	Total     int                   `json:"total" example:"100"`
	Success   int                   `json:"success" example:"95"`
	Failed    int                   `json:"failed" example:"5"`
	Results   []EventIngestResponse `json:"results"`
	Timestamp time.Time             `json:"timestamp" example:"2024-01-01T00:00:00Z"`
}

type EventSearchRequest struct {
	Query     string              `json:"query" example:"type:network AND severity:error"`
	TimeRange TimeRange           `json:"time_range"`
	Filters   map[string][]string `json:"filters,omitempty"`
	Limit     int                 `json:"limit,omitempty" example:"100"`
	Offset    int                 `json:"offset,omitempty" example:"0"`
	SortBy    string              `json:"sort_by,omitempty" example:"timestamp"`
	SortOrder string              `json:"sort_order,omitempty" example:"desc"`
}

type EventSearchResponse struct {
	Query        string                  `json:"query"`
	TotalHits    int64                   `json:"total_hits" example:"1523"`
	ReturnedHits int                     `json:"returned_hits" example:"100"`
	Events       []EventSearchResult     `json:"events"`
	Facets       map[string][]FacetValue `json:"facets"`
	Timestamp    time.Time               `json:"timestamp"`
}

type EventSearchResult struct {
	ID        string              `json:"id"`
	Type      string              `json:"type"`
	Severity  string              `json:"severity"`
	Timestamp time.Time           `json:"timestamp"`
	Message   string              `json:"message"`
	Score     float64             `json:"score"`
	Highlight map[string][]string `json:"highlight,omitempty"`
}

type FacetValue struct {
	Value string `json:"value" example:"network"`
	Count int64  `json:"count" example:"45"`
}

// Correlation Types

type CorrelationUpdate struct {
	ID          string    `json:"id" example:"corr_001"`
	Pattern     string    `json:"pattern" example:"service_degradation"`
	Confidence  float64   `json:"confidence" example:"0.87"`
	EventCount  int       `json:"event_count" example:"15"`
	Description string    `json:"description" example:"Detected service degradation pattern"`
	Timestamp   time.Time `json:"timestamp"`
}

type PatternDiscoveryRequest struct {
	TimeRange     TimeRange `json:"time_range"`
	MinConfidence float64   `json:"min_confidence,omitempty" example:"0.7"`
	PatternTypes  []string  `json:"pattern_types,omitempty"`
	MaxPatterns   int       `json:"max_patterns,omitempty" example:"10"`
}

type PatternDiscoveryResponse struct {
	TimeRange TimeRange           `json:"time_range"`
	Patterns  []DiscoveredPattern `json:"patterns"`
	Timestamp time.Time           `json:"timestamp"`
}

type DiscoveredPattern struct {
	ID          string   `json:"id" example:"pattern_001"`
	Name        string   `json:"name" example:"Cascading Failure"`
	Description string   `json:"description" example:"Service failures cascading through dependencies"`
	Confidence  float64  `json:"confidence" example:"0.92"`
	Frequency   int      `json:"frequency" example:"5"`
	Examples    []string `json:"examples"`
}

type ImpactAnalysisRequest struct {
	EventID         string `json:"event_id" example:"evt_001"`
	IncludeServices bool   `json:"include_services,omitempty"`
	IncludeMetrics  bool   `json:"include_metrics,omitempty"`
	TimeHorizon     string `json:"time_horizon,omitempty" example:"2h"`
}

type ImpactAnalysisResponse struct {
	EventID           string        `json:"event_id"`
	Impact            ImpactDetails `json:"impact"`
	AffectedServices  []string      `json:"affected_services"`
	AffectedCustomers int           `json:"affected_customers" example:"1250"`
	EstimatedDuration string        `json:"estimated_duration" example:"2h30m"`
	Recommendations   []string      `json:"recommendations"`
	Timestamp         time.Time     `json:"timestamp"`
}

type ImpactDetails struct {
	BusinessImpact    float64 `json:"business_impact" example:"0.75"`
	CustomerImpact    float64 `json:"customer_impact" example:"0.60"`
	OperationalImpact float64 `json:"operational_impact" example:"0.80"`
	FinancialImpact   float64 `json:"financial_impact" example:"0.45"`
}

// Collector Types

type CollectorStatusResponse struct {
	Collectors      []CollectorStatusDetail `json:"collectors"`
	TotalEvents     int64                   `json:"total_events" example:"1500000"`
	EventsPerSecond float64                 `json:"events_per_second" example:"210.7"`
	Timestamp       time.Time               `json:"timestamp"`
}

type CollectorStatusDetail struct {
	Name            string                `json:"name" example:"systemd"`
	Type            string                `json:"type" example:"systemd"`
	Status          string                `json:"status" example:"running"`
	EventsPerSecond float64               `json:"events_per_second" example:"125.5"`
	LastEventTime   time.Time             `json:"last_event_time"`
	Uptime          int64                 `json:"uptime_seconds" example:"3600"`
	Health          CollectorHealthDetail `json:"health"`
}

type CollectorHealthDetail struct {
	CPU    float64 `json:"cpu_percent" example:"25.5"`
	Memory float64 `json:"memory_mb" example:"128.0"`
	Errors int64   `json:"error_count" example:"0"`
}

type CollectorConfigResponse struct {
	Name      string                 `json:"name"`
	Config    map[string]interface{} `json:"config"`
	Timestamp time.Time              `json:"timestamp"`
}

// Analytics Types

type AnalyticsSummaryResponse struct {
	TimeRange             TimeRange        `json:"time_range"`
	EventStatistics       EventStats       `json:"event_statistics"`
	CorrelationStatistics CorrelationStats `json:"correlation_statistics"`
	TopIssues             []TopIssue       `json:"top_issues"`
	Timestamp             time.Time        `json:"timestamp"`
}

type EventStats struct {
	Total         int64            `json:"total" example:"145892"`
	ByType        map[string]int64 `json:"by_type"`
	BySeverity    map[string]int64 `json:"by_severity"`
	EventsPerHour []int64          `json:"events_per_hour"`
}

type CorrelationStats struct {
	Total             int64            `json:"total" example:"1523"`
	ByPattern         map[string]int64 `json:"by_pattern"`
	AverageConfidence float64          `json:"average_confidence" example:"0.82"`
}

type TopIssue struct {
	Description string `json:"description" example:"High memory usage in payment service"`
	Severity    string `json:"severity" example:"warning"`
	Count       int    `json:"count" example:"45"`
	Trend       string `json:"trend" example:"increasing"`
}

type TrendAnalysisResponse struct {
	Metric     string         `json:"metric" example:"events"`
	Period     string         `json:"period" example:"1h"`
	Trends     []TrendData    `json:"trends"`
	Prediction PredictionData `json:"prediction"`
	Anomalies  []AnomalyData  `json:"anomalies"`
	Timestamp  time.Time      `json:"timestamp"`
}

type TrendData struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value" example:"100.0"`
	Trend     string    `json:"trend" example:"stable"`
}

type PredictionData struct {
	NextValue  float64 `json:"next_value" example:"115.0"`
	Confidence float64 `json:"confidence" example:"0.75"`
	Trend      string  `json:"trend" example:"stable"`
}

type AnomalyData struct {
	Timestamp   time.Time `json:"timestamp"`
	Value       float64   `json:"value" example:"180.0"`
	Description string    `json:"description" example:"Spike in event rate"`
	Severity    string    `json:"severity" example:"warning"`
}

// System Types

type SystemInfoResponse struct {
	Version     string          `json:"version" example:"1.0.0"`
	BuildTime   string          `json:"build_time" example:"2024-01-01T00:00:00Z"`
	GitCommit   string          `json:"git_commit" example:"abc123def"`
	GoVersion   string          `json:"go_version" example:"1.21"`
	Platform    string          `json:"platform" example:"linux/amd64"`
	StartTime   time.Time       `json:"start_time"`
	Uptime      int64           `json:"uptime_seconds" example:"3600"`
	Environment string          `json:"environment" example:"production"`
	Features    map[string]bool `json:"features"`
	Limits      SystemLimits    `json:"limits"`
	Timestamp   time.Time       `json:"timestamp"`
}

type SystemLimits struct {
	MaxEventsPerSecond    int `json:"max_events_per_second" example:"165000"`
	MaxCorrelationsActive int `json:"max_correlations_active" example:"10000"`
	MaxSubscriptions      int `json:"max_subscriptions" example:"1000"`
	MaxRequestSize        int `json:"max_request_size_bytes" example:"10485760"`
}

type DetailedHealthResponse struct {
	Status     string                     `json:"status" example:"healthy"`
	Components map[string]ComponentHealth `json:"components"`
	Checks     []HealthCheck              `json:"checks"`
	Timestamp  time.Time                  `json:"timestamp"`
}

type ComponentHealth struct {
	Status  string                 `json:"status" example:"healthy"`
	Message string                 `json:"message" example:"Accepting connections"`
	Details map[string]interface{} `json:"details,omitempty"`
}

type HealthCheck struct {
	Name     string                 `json:"name" example:"database_connectivity"`
	Status   string                 `json:"status" example:"pass"`
	Duration string                 `json:"duration" example:"2ms"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// Common Types

type TimeRange struct {
	Start time.Time `json:"start" example:"2024-01-01T00:00:00Z"`
	End   time.Time `json:"end" example:"2024-01-01T23:59:59Z"`
}

type ErrorResponse struct {
	Error     string    `json:"error" example:"Bad Request"`
	Message   string    `json:"message" example:"Invalid JSON format"`
	Code      string    `json:"code" example:"400"`
	Timestamp time.Time `json:"timestamp"`
}
