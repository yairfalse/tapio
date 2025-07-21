package grpc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/dataflow"
	"github.com/yairfalse/tapio/pkg/integrations/collector-manager"
	"github.com/yairfalse/tapio/pkg/intelligence/correlation"
	pb "github.com/yairfalse/tapio/proto/gen/tapio/v1"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// UnifiedServer combines gRPC and REST API servers
type UnifiedServer struct {
	config UnifiedServerConfig
	logger *zap.Logger

	// Core dependencies (following 5-level architecture)
	collectorMgr      *manager.CollectorManager              // L3: Integration
	dataFlow          *dataflow.TapioDataFlow                // L2: Intelligence
	correlationEngine *correlation.SemanticCorrelationEngine // L2: Intelligence

	// gRPC components
	grpcServer   *grpc.Server
	healthServer *health.Server

	// Service implementations
	tapioService         *TapioServer
	collectorService     *CollectorServer
	eventService         *EventServer
	observabilityService *ObservabilityServer
	correlationService   *CorrelationServer

	// REST components
	restGateway *RESTGateway
	restRoutes  *RESTRoutes

	// HTTP server for REST
	httpServer *http.Server

	// Server state
	mu           sync.RWMutex
	running      bool
	grpcListener net.Listener
	httpListener net.Listener
}

// UnifiedServerConfig holds configuration for the unified server
type UnifiedServerConfig struct {
	// Server addresses
	GRPCAddress string
	HTTPAddress string

	// Features
	EnableReflection bool
	EnableHealth     bool
	EnableCORS       bool
	EnableSwagger    bool
	EnableMetrics    bool

	// Security
	EnableAuth        bool
	EnableRateLimit   bool
	MaxRequestsPerSec int

	// Performance
	MaxRecvMessageSize  int
	MaxSendMessageSize  int
	MaxConcurrentStream int
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration

	// REST specific
	SwaggerPath    string
	MaxRequestSize int64
}

// DefaultUnifiedServerConfig returns default configuration
func DefaultUnifiedServerConfig() UnifiedServerConfig {
	return UnifiedServerConfig{
		GRPCAddress:         ":8080",
		HTTPAddress:         ":8081",
		EnableReflection:    true,
		EnableHealth:        true,
		EnableCORS:          true,
		EnableSwagger:       true,
		EnableMetrics:       true,
		EnableAuth:          false, // Disabled for development
		EnableRateLimit:     true,
		MaxRequestsPerSec:   10000,
		MaxRecvMessageSize:  4 * 1024 * 1024, // 4MB
		MaxSendMessageSize:  4 * 1024 * 1024, // 4MB
		MaxConcurrentStream: 1000,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         120 * time.Second,
		SwaggerPath:         "/proto/gen/openapiv2/tapio.swagger.json",
		MaxRequestSize:      10 * 1024 * 1024, // 10MB
	}
}

// NewUnifiedServer creates a new unified gRPC+REST server
func NewUnifiedServer(config UnifiedServerConfig, logger *zap.Logger) (*UnifiedServer, error) {
	// Create tracer
	tracer := otel.Tracer("tapio-server")

	// Create middleware
	middleware := NewServerMiddleware(logger, tracer)

	// Build gRPC server options
	var grpcOpts []grpc.ServerOption

	// Add middleware interceptors
	grpcOpts = append(grpcOpts,
		grpc.UnaryInterceptor(middleware.UnaryInterceptor()),
		grpc.StreamInterceptor(middleware.StreamInterceptor()),
	)

	// Add optional interceptors
	if config.EnableRateLimit {
		grpcOpts = append(grpcOpts, grpc.ChainUnaryInterceptor(
			RateLimitInterceptor(config.MaxRequestsPerSec),
		))
	}

	if config.EnableAuth {
		grpcOpts = append(grpcOpts, grpc.ChainUnaryInterceptor(
			AuthInterceptor(),
		))
	}

	// Add validation and metrics
	grpcOpts = append(grpcOpts, grpc.ChainUnaryInterceptor(
		ValidationInterceptor(),
		MetricsInterceptor(),
		RecoveryInterceptor(),
	))

	// Configure message sizes
	grpcOpts = append(grpcOpts,
		grpc.MaxRecvMsgSize(config.MaxRecvMessageSize),
		grpc.MaxSendMsgSize(config.MaxSendMessageSize),
		grpc.MaxConcurrentStreams(uint32(config.MaxConcurrentStream)),
	)

	// Create gRPC server
	grpcServer := grpc.NewServer(grpcOpts...)

	// Create health server
	healthServer := health.NewServer()

	// Create service instances
	tapioService := NewTapioServiceImpl(logger.Named("tapio"), tracer)
	collectorService := NewCollectorServer(logger.Named("collector"), tracer)
	eventService := NewEventServiceImpl(logger.Named("event"), tracer)
	observabilityService := NewObservabilityServer(logger.Named("observability"), tracer)
	correlationService := NewCorrelationServerWithRealStore(logger.Named("correlation"), tracer)

	// Register services with gRPC server
	pb.RegisterTapioServiceServer(grpcServer, tapioService)
	pb.RegisterCollectorServiceServer(grpcServer, collectorService)
	pb.RegisterEventServiceServer(grpcServer, eventService)
	pb.RegisterObservabilityServiceServer(grpcServer, observabilityService)
	pb.RegisterCorrelationServiceServer(grpcServer, correlationService)

	// Register health service
	if config.EnableHealth {
		grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	}

	// Enable reflection for development
	if config.EnableReflection {
		reflection.Register(grpcServer)
	}

	// Create REST gateway
	restGatewayConfig := RESTGatewayConfig{
		GRPCAddress:    config.GRPCAddress,
		EnableCORS:     config.EnableCORS,
		EnableSwagger:  config.EnableSwagger,
		SwaggerPath:    config.SwaggerPath,
		MaxRequestSize: config.MaxRequestSize,
		ReadTimeout:    int(config.ReadTimeout.Seconds()),
		WriteTimeout:   int(config.WriteTimeout.Seconds()),
	}

	restGateway, err := NewRESTGateway(restGatewayConfig, logger.Named("rest-gateway"))
	if err != nil {
		return nil, fmt.Errorf("failed to create REST gateway: %w", err)
	}

	// Create REST routes
	restRoutes := NewRESTRoutes(logger.Named("rest-routes"), config.GRPCAddress)
	restRoutes.SetServices(eventService, correlationService, collectorService)

	return &UnifiedServer{
		config:               config,
		logger:               logger,
		grpcServer:           grpcServer,
		healthServer:         healthServer,
		tapioService:         tapioService,
		collectorService:     collectorService,
		eventService:         eventService,
		observabilityService: observabilityService,
		correlationService:   correlationService,
		restGateway:          restGateway,
		restRoutes:           restRoutes,
	}, nil
}

// SetDependencies injects the L2 and L3 layer dependencies
func (s *UnifiedServer) SetDependencies(collectorMgr *manager.CollectorManager, dataFlow *dataflow.TapioDataFlow, correlationEngine *correlation.SemanticCorrelationEngine) {
	s.collectorMgr = collectorMgr
	s.dataFlow = dataFlow
	s.correlationEngine = correlationEngine

	// Inject dependencies into services
	s.tapioService.SetDependencies(collectorMgr, dataFlow)
	s.collectorService.SetCollectorManager(collectorMgr)
	s.eventService.SetDependencies(collectorMgr, dataFlow, nil, nil)
	s.correlationService.SetDependencies(dataFlow, correlationEngine)
}

// Start starts both gRPC and REST servers
func (s *UnifiedServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server is already running")
	}

	// Start gRPC server
	grpcListener, err := net.Listen("tcp", s.config.GRPCAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC address %s: %w", s.config.GRPCAddress, err)
	}
	s.grpcListener = grpcListener

	// Start gRPC server in goroutine
	go func() {
		s.logger.Info("Starting gRPC server",
			zap.String("address", grpcListener.Addr().String()),
			zap.Bool("reflection", s.config.EnableReflection),
			zap.Bool("health", s.config.EnableHealth),
		)

		if err := s.grpcServer.Serve(grpcListener); err != nil {
			s.logger.Error("gRPC server failed", zap.Error(err))
		}
	}()

	// Wait for gRPC server to be ready
	time.Sleep(100 * time.Millisecond)

	// Register REST gateway services
	if err := s.restGateway.RegisterServices(ctx); err != nil {
		return fmt.Errorf("failed to register REST gateway services: %w", err)
	}

	// Create HTTP mux
	mux := http.NewServeMux()

	// Register REST gateway handler
	mux.Handle("/", s.restGateway.GetHandler())

	// Register custom REST routes
	s.restRoutes.RegisterRoutes(mux)

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         s.config.HTTPAddress,
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	// Start HTTP server
	httpListener, err := net.Listen("tcp", s.config.HTTPAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on HTTP address %s: %w", s.config.HTTPAddress, err)
	}
	s.httpListener = httpListener

	// Start HTTP server in goroutine
	go func() {
		s.logger.Info("Starting REST API server",
			zap.String("address", httpListener.Addr().String()),
			zap.Bool("cors", s.config.EnableCORS),
			zap.Bool("swagger", s.config.EnableSwagger),
		)

		if err := s.httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server failed", zap.Error(err))
		}
	}()

	// Set health status
	if s.config.EnableHealth {
		s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		s.healthServer.SetServingStatus("tapio.v1.TapioService", grpc_health_v1.HealthCheckResponse_SERVING)
		s.healthServer.SetServingStatus("tapio.v1.CollectorService", grpc_health_v1.HealthCheckResponse_SERVING)
		s.healthServer.SetServingStatus("tapio.v1.EventService", grpc_health_v1.HealthCheckResponse_SERVING)
		s.healthServer.SetServingStatus("tapio.v1.ObservabilityService", grpc_health_v1.HealthCheckResponse_SERVING)
		s.healthServer.SetServingStatus("tapio.v1.CorrelationService", grpc_health_v1.HealthCheckResponse_SERVING)
	}

	// Configure service integrations
	s.configureServiceIntegrations()

	s.running = true

	s.logger.Info("Unified server started successfully",
		zap.String("grpc_address", s.grpcListener.Addr().String()),
		zap.String("http_address", s.httpListener.Addr().String()),
	)

	// Print API endpoints
	s.printAPIEndpoints()

	return nil
}

// Stop gracefully stops both servers
func (s *UnifiedServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("Stopping unified server")

	// Set health status to not serving
	if s.config.EnableHealth {
		s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	}

	// Stop HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("Failed to shutdown HTTP server", zap.Error(err))
		}
	}

	// Stop REST gateway
	if s.restGateway != nil {
		if err := s.restGateway.Close(); err != nil {
			s.logger.Error("Failed to close REST gateway", zap.Error(err))
		}
	}

	// Gracefully stop gRPC server
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("gRPC server stopped gracefully")
	case <-ctx.Done():
		s.logger.Warn("Graceful shutdown timeout, forcing stop")
		s.grpcServer.Stop()
	}

	s.running = false
	s.logger.Info("Unified server stopped")

	return nil
}

// GetServiceStats returns statistics for all services
func (s *UnifiedServer) GetServiceStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"running":      s.running,
			"grpc_address": s.config.GRPCAddress,
			"http_address": s.config.HTTPAddress,
			"features": map[string]bool{
				"reflection": s.config.EnableReflection,
				"health":     s.config.EnableHealth,
				"cors":       s.config.EnableCORS,
				"swagger":    s.config.EnableSwagger,
				"metrics":    s.config.EnableMetrics,
				"auth":       s.config.EnableAuth,
				"rate_limit": s.config.EnableRateLimit,
			},
		},
	}

	// Get stats from each service
	if s.tapioService != nil {
		stats["tapio"] = s.tapioService.GetServiceStats()
	}
	if s.collectorService != nil {
		stats["collector"] = s.collectorService.GetServiceStats()
	}
	if s.eventService != nil {
		stats["event"] = s.eventService.GetServiceStats()
	}
	if s.observabilityService != nil {
		stats["observability"] = s.observabilityService.GetServiceStats()
	}
	if s.correlationService != nil {
		stats["correlation"] = s.correlationService.GetServiceStats()
	}

	return stats
}

// configureServiceIntegrations sets up cross-service integrations
func (s *UnifiedServer) configureServiceIntegrations() {
	s.logger.Info("Configuring service integrations")

	// Configure event ingestion
	if s.eventService != nil {
		s.eventService.ConfigureEventIngestion(EventIngestionConfig{
			EnableCollectorIngestion: true,
			EnableeBPFIngestion:      true,
			EnableK8sIngestion:       true,
			EnableOTELIngestion:      true,
			EnableRealTimeStreaming:  true,
			MaxEventsPerSecond:       s.config.MaxRequestsPerSec,
			MaxEventsPerBatch:        10000,
			EnableContextEnrichment:  true,
			EnableAIEnrichment:       false,
		})
	}

	// Configure correlation analysis
	if s.correlationService != nil {
		s.correlationService.ConfigureCorrelationIngestion(CorrelationIngestionConfig{
			EnableCollectorAnalysis: true,
			EnableeBPFAnalysis:      true,
			EnableK8sAnalysis:       true,
			EnableOTELAnalysis:      true,
			ConfidenceThreshold:     0.7,
			MaxEventsPerAnalysis:    10000,
			AnalysisTimeout:         30 * time.Second,
			EnableRealTimeUpdates:   true,
			EnableRootCause:         true,
			EnablePredictions:       true,
			EnableImpactAssess:      true,
		})

		// Start periodic analysis
		s.correlationService.StartPeriodicAnalysis(5 * time.Minute)
	}

	s.logger.Info("Service integrations configured successfully")
}

// printAPIEndpoints prints available API endpoints
func (s *UnifiedServer) printAPIEndpoints() {
	grpcAddr := s.grpcListener.Addr().String()
	httpAddr := s.httpListener.Addr().String()

	// Handle IPv6 addresses
	if strings.HasPrefix(grpcAddr, "[::]:") {
		grpcAddr = "localhost" + grpcAddr[4:]
	}
	if strings.HasPrefix(httpAddr, "[::]:") {
		httpAddr = "localhost" + httpAddr[4:]
	}

	fmt.Println("\n🚀 Tapio Server Started Successfully!")
	fmt.Println("====================================")

	fmt.Println("\n📡 gRPC Endpoints:")
	fmt.Printf("   - gRPC Server: %s\n", grpcAddr)
	fmt.Printf("   - Health Check: grpcurl -plaintext %s grpc.health.v1.Health/Check\n", grpcAddr)
	if s.config.EnableReflection {
		fmt.Printf("   - List Services: grpcurl -plaintext %s list\n", grpcAddr)
	}

	fmt.Println("\n🌐 REST API Endpoints:")
	fmt.Printf("   - Base URL: http://%s/api/v1\n", httpAddr)
	fmt.Printf("   - Health: http://%s/health\n", httpAddr)
	fmt.Printf("   - Metrics: http://%s/metrics\n", httpAddr)
	if s.config.EnableSwagger {
		fmt.Printf("   - OpenAPI Spec: http://%s/swagger.json\n", httpAddr)
		fmt.Printf("   - Swagger UI: http://%s/swagger/\n", httpAddr)
	}

	fmt.Println("\n📚 Example Requests:")
	fmt.Println("   - Submit Event:")
	fmt.Printf("     curl -X POST http://%s/api/v1/events \\\n", httpAddr)
	fmt.Println("       -H 'Content-Type: application/json' \\")
	fmt.Println("       -d '{\"id\":\"evt_001\",\"type\":\"network\",\"severity\":\"info\",\"timestamp\":\"2024-01-01T00:00:00Z\",\"message\":\"Test event\"}'")

	fmt.Println("\n   - Query Events:")
	fmt.Printf("     curl http://%s/api/v1/events?filter.limit=10\n", httpAddr)

	fmt.Println("\n   - Stream Events (SSE):")
	fmt.Printf("     curl -H 'Accept: text/event-stream' http://%s/api/v1/events/stream\n", httpAddr)

	fmt.Println("\n====================================\n")
}
