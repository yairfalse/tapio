package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/dataflow"
	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/integrations/collector-manager"
	pb "github.com/yairfalse/tapio/proto/gen/tapio/v1"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TapioServer implements the main Tapio service
type TapioServer struct {
	pb.UnimplementedTapioServiceServer
	
	logger *zap.Logger
	tracer trace.Tracer
	
	// L3 Integration layer dependencies
	collectorMgr *manager.CollectorManager
	dataFlow     *dataflow.TapioDataFlow
	
	// Statistics
	stats struct {
		mu           sync.RWMutex
		startTime    time.Time
		requestCount uint64
	}
}

// NewTapioServer creates a new Tapio service implementation
func NewTapioServer(logger *zap.Logger, tracer trace.Tracer) *TapioServer {
	return &TapioServer{
		logger: logger,
		tracer: tracer,
		stats: struct {
			mu           sync.RWMutex
			startTime    time.Time
			requestCount uint64
		}{
			startTime: time.Now(),
		},
	}
}

// SetDependencies injects L3 integration layer dependencies
func (s *TapioServer) SetDependencies(collectorMgr *manager.CollectorManager, dataFlow *dataflow.TapioDataFlow) {
	s.collectorMgr = collectorMgr
	s.dataFlow = dataFlow
}

// GetStatus returns the overall system status
func (s *TapioServer) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	s.incrementRequestCount()
	
	ctx, span := s.tracer.Start(ctx, "tapio.get_status")
	defer span.End()
	
	s.logger.Debug("Getting Tapio system status")
	
	// Get collector manager statistics
	var collectorStats *pb.CollectorManagerStatus
	if s.collectorMgr != nil {
		stats := s.collectorMgr.Statistics()
		collectorStats = &pb.CollectorManagerStatus{
			ActiveCollectors: int32(stats.ActiveCollectors),
			TotalEvents:      stats.TotalEvents,
		}
	}
	
	// Get dataflow metrics
	var dataflowMetrics map[string]float64
	if s.dataFlow != nil {
		metrics := s.dataFlow.GetMetrics()
		dataflowMetrics = make(map[string]float64)
		for k, v := range metrics {
			if val, ok := v.(float64); ok {
				dataflowMetrics[k] = val
			}
		}
	}
	
	s.stats.mu.RLock()
	uptime := time.Since(s.stats.startTime)
	requestCount := s.stats.requestCount
	s.stats.mu.RUnlock()
	
	return &pb.GetStatusResponse{
		Status:    pb.SystemStatus_SYSTEM_STATUS_HEALTHY,
		Timestamp: timestamppb.Now(),
		Uptime:    int64(uptime.Seconds()),
		Version:   "1.0.0",
		Components: &pb.ComponentStatus{
			CollectorManager: collectorStats,
			DataflowEngine: &pb.DataflowEngineStatus{
				EventsPerSecond: dataflowMetrics["events_per_second"],
				ActiveGroups:    int32(dataflowMetrics["semantic_groups_active"]),
			},
		},
		RequestCount: requestCount,
	}, nil
}

// GetConfiguration returns the current system configuration
func (s *TapioServer) GetConfiguration(ctx context.Context, req *pb.GetConfigurationRequest) (*pb.GetConfigurationResponse, error) {
	s.incrementRequestCount()
	
	ctx, span := s.tracer.Start(ctx, "tapio.get_configuration")
	defer span.End()
	
	s.logger.Debug("Getting Tapio system configuration")
	
	// Return basic configuration - this would be expanded based on actual config system
	return &pb.GetConfigurationResponse{
		Environment: "production",
		Features: map[string]bool{
			"semantic_correlation": true,
			"distributed_tracing": true,
			"real_time_streaming": true,
		},
		Settings: map[string]string{
			"correlation_engine": "enabled",
			"buffer_size":       "10000",
		},
	}, nil
}

// GetServiceStats returns statistics for the Tapio service
func (s *TapioServer) GetServiceStats() map[string]interface{} {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"start_time":     s.stats.startTime,
		"uptime_seconds": time.Since(s.stats.startTime).Seconds(),
		"request_count":  s.stats.requestCount,
		"service_type":   "tapio_main",
	}
}

// HealthCheck checks the health of the Tapio service
func (s *TapioServer) HealthCheck() error {
	// Check dependencies
	if s.collectorMgr == nil {
		return fmt.Errorf("collector manager not initialized")
	}
	
	if s.dataFlow == nil {
		return fmt.Errorf("dataflow engine not initialized")
	}
	
	return nil
}

func (s *TapioServer) incrementRequestCount() {
	s.stats.mu.Lock()
	s.stats.requestCount++
	s.stats.mu.Unlock()
}

// CollectorServer implements the collector management service
type CollectorServer struct {
	pb.UnimplementedCollectorServiceServer
	
	logger *zap.Logger
	tracer trace.Tracer
	
	// L3 Integration layer dependencies
	collectorMgr *manager.CollectorManager
	
	// Statistics
	stats struct {
		mu           sync.RWMutex
		startTime    time.Time
		requestCount uint64
	}
}

// NewCollectorServer creates a new collector service implementation
func NewCollectorServer(logger *zap.Logger, tracer trace.Tracer) *CollectorServer {
	return &CollectorServer{
		logger: logger,
		tracer: tracer,
		stats: struct {
			mu           sync.RWMutex
			startTime    time.Time
			requestCount uint64
		}{
			startTime: time.Now(),
		},
	}
}

// SetCollectorManager injects the collector manager dependency
func (s *CollectorServer) SetCollectorManager(collectorMgr *manager.CollectorManager) {
	s.collectorMgr = collectorMgr
}

// ListCollectors returns information about all active collectors
func (s *CollectorServer) ListCollectors(ctx context.Context, req *pb.ListCollectorsRequest) (*pb.ListCollectorsResponse, error) {
	s.incrementRequestCount()
	
	ctx, span := s.tracer.Start(ctx, "collector.list_collectors")
	defer span.End()
	
	s.logger.Debug("Listing active collectors")
	
	if s.collectorMgr == nil {
		return nil, status.Error(codes.Internal, "collector manager not initialized")
	}
	
	// Get statistics from collector manager
	stats := s.collectorMgr.Statistics()
	
	// Create response with collector information
	// Note: This would need to be expanded to get actual collector details
	collectors := []*pb.CollectorInfo{
		{
			Name:     "systemd",
			Type:     pb.CollectorType_COLLECTOR_TYPE_SYSTEMD,
			Status:   pb.CollectorStatus_COLLECTOR_STATUS_RUNNING,
			LastSeen: timestamppb.Now(),
			EventsProcessed: 1000,
		},
		{
			Name:     "kubernetes",
			Type:     pb.CollectorType_COLLECTOR_TYPE_KUBERNETES,
			Status:   pb.CollectorStatus_COLLECTOR_STATUS_RUNNING,
			LastSeen: timestamppb.Now(),
			EventsProcessed: 500,
		},
	}
	
	return &pb.ListCollectorsResponse{
		Collectors:    collectors,
		TotalCount:    int32(stats.ActiveCollectors),
		ResponseTime:  timestamppb.Now(),
	}, nil
}

// GetCollectorHealth returns health information for a specific collector
func (s *CollectorServer) GetCollectorHealth(ctx context.Context, req *pb.GetCollectorHealthRequest) (*pb.GetCollectorHealthResponse, error) {
	s.incrementRequestCount()
	
	ctx, span := s.tracer.Start(ctx, "collector.get_health")
	defer span.End()
	
	s.logger.Debug("Getting collector health", zap.String("collector", req.CollectorName))
	
	if s.collectorMgr == nil {
		return nil, status.Error(codes.Internal, "collector manager not initialized")
	}
	
	// This would need to be implemented to get actual health from specific collector
	return &pb.GetCollectorHealthResponse{
		CollectorName: req.CollectorName,
		Status:        pb.CollectorStatus_COLLECTOR_STATUS_RUNNING,
		LastEventTime: timestamppb.Now(),
		ErrorCount:    0,
		Uptime:        3600, // 1 hour
		Metrics: map[string]float64{
			"events_per_second": 10.5,
			"cpu_usage":        25.0,
			"memory_usage":     128.0,
		},
	}, nil
}

// GetServiceStats returns statistics for the collector service
func (s *CollectorServer) GetServiceStats() map[string]interface{} {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"start_time":     s.stats.startTime,
		"uptime_seconds": time.Since(s.stats.startTime).Seconds(),
		"request_count":  s.stats.requestCount,
		"service_type":   "collector_manager",
	}
}

// HealthCheck checks the health of the collector service
func (s *CollectorServer) HealthCheck() error {
	if s.collectorMgr == nil {
		return fmt.Errorf("collector manager not initialized")
	}
	return nil
}

func (s *CollectorServer) incrementRequestCount() {
	s.stats.mu.Lock()
	s.stats.requestCount++
	s.stats.mu.Unlock()
}

// ObservabilityServer implements observability and monitoring services
type ObservabilityServer struct {
	pb.UnimplementedObservabilityServiceServer
	
	logger *zap.Logger
	tracer trace.Tracer
	
	// Statistics
	stats struct {
		mu           sync.RWMutex
		startTime    time.Time
		requestCount uint64
		metricsCount uint64
	}
}

// NewObservabilityServer creates a new observability service implementation
func NewObservabilityServer(logger *zap.Logger, tracer trace.Tracer) *ObservabilityServer {
	return &ObservabilityServer{
		logger: logger,
		tracer: tracer,
		stats: struct {
			mu           sync.RWMutex
			startTime    time.Time
			requestCount uint64
			metricsCount uint64
		}{
			startTime: time.Now(),
		},
	}
}

// GetMetrics returns system metrics
func (s *ObservabilityServer) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	s.incrementRequestCount()
	
	ctx, span := s.tracer.Start(ctx, "observability.get_metrics")
	defer span.End()
	
	s.logger.Debug("Getting system metrics")
	
	// Create sample metrics - this would integrate with actual metrics collection
	metrics := []*pb.Metric{
		{
			Name:      "tapio.events.processed.total",
			Value:     1000.0,
			Timestamp: timestamppb.Now(),
			Labels: map[string]string{
				"service": "tapio",
				"version": "1.0.0",
			},
		},
		{
			Name:      "tapio.correlation.groups.active",
			Value:     25.0,
			Timestamp: timestamppb.Now(),
			Labels: map[string]string{
				"service": "correlation_engine",
			},
		},
	}
	
	s.stats.mu.Lock()
	s.stats.metricsCount += uint64(len(metrics))
	s.stats.mu.Unlock()
	
	return &pb.GetMetricsResponse{
		Metrics:     metrics,
		TotalCount:  int32(len(metrics)),
		Timestamp:   timestamppb.Now(),
	}, nil
}

// GetServiceStats returns statistics for the observability service
func (s *ObservabilityServer) GetServiceStats() map[string]interface{} {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"start_time":     s.stats.startTime,
		"uptime_seconds": time.Since(s.stats.startTime).Seconds(),
		"request_count":  s.stats.requestCount,
		"metrics_served": s.stats.metricsCount,
		"service_type":   "observability",
	}
}

// HealthCheck checks the health of the observability service
func (s *ObservabilityServer) HealthCheck() error {
	// Always healthy for now - would check metrics backends
	return nil
}

func (s *ObservabilityServer) incrementRequestCount() {
	s.stats.mu.Lock()
	s.stats.requestCount++
	s.stats.mu.Unlock()
}