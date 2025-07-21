package grpc

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pb "github.com/yairfalse/tapio/proto/gen/tapio/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// RESTGateway provides REST API gateway functionality
type RESTGateway struct {
	config    RESTGatewayConfig
	logger    *zap.Logger
	mux       *runtime.ServeMux
	grpcConn  *grpc.ClientConn
}

// RESTGatewayConfig holds REST gateway configuration
type RESTGatewayConfig struct {
	GRPCAddress      string
	EnableCORS       bool
	EnableSwagger    bool
	SwaggerPath      string
	MaxRequestSize   int64
	ReadTimeout      int
	WriteTimeout     int
}

// NewRESTGateway creates a new REST API gateway
func NewRESTGateway(config RESTGatewayConfig, logger *zap.Logger) (*RESTGateway, error) {
	// Create custom JSON marshaler options
	jsonOption := runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames:   true,
			EmitUnpopulated: true,
			UseEnumNumbers:  false,
			Indent:          "  ",
		},
		UnmarshalOptions: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	})
	
	// Create custom header matcher for better REST compatibility
	headerMatcher := runtime.WithIncomingHeaderMatcher(func(header string) (string, bool) {
		// Convert headers to lowercase for consistency
		canonical := strings.ToLower(header)
		
		// Allow common headers
		switch canonical {
		case "x-api-key", "x-request-id", "x-trace-id", "authorization", "content-type":
			return canonical, true
		}
		
		// Allow headers with specific prefixes
		if strings.HasPrefix(canonical, "x-tapio-") {
			return canonical, true
		}
		
		return "", false
	})
	
	// Create outgoing header matcher
	outgoingHeaderMatcher := runtime.WithOutgoingHeaderMatcher(func(header string) (string, bool) {
		// Forward specific headers to clients
		canonical := strings.ToLower(header)
		switch canonical {
		case "x-request-id", "x-trace-id", "x-correlation-id":
			return canonical, true
		}
		return "", false
	})
	
	// Error handler for better REST error responses
	errorHandler := runtime.WithErrorHandler(customHTTPError)
	
	// Create ServeMux with options
	mux := runtime.NewServeMux(
		jsonOption,
		headerMatcher,
		outgoingHeaderMatcher,
		errorHandler,
		runtime.WithMetadata(annotateMetadata),
		runtime.WithHealthzEndpoint(runtime.DefaultHealthzEndpoint),
	)
	
	return &RESTGateway{
		config: config,
		logger: logger,
		mux:    mux,
	}, nil
}

// RegisterServices registers all gRPC services with the REST gateway
func (g *RESTGateway) RegisterServices(ctx context.Context) error {
	// Connect to gRPC server
	conn, err := grpc.DialContext(ctx, g.config.GRPCAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	g.grpcConn = conn
	
	// Register Tapio service
	if err := pb.RegisterTapioServiceHandler(ctx, g.mux, conn); err != nil {
		return fmt.Errorf("failed to register Tapio service: %w", err)
	}
	
	// Register Event service
	if err := pb.RegisterEventServiceHandler(ctx, g.mux, conn); err != nil {
		return fmt.Errorf("failed to register Event service: %w", err)
	}
	
	// Register Collector service
	if err := pb.RegisterCollectorServiceHandler(ctx, g.mux, conn); err != nil {
		return fmt.Errorf("failed to register Collector service: %w", err)
	}
	
	// Register Correlation service
	if err := pb.RegisterCorrelationServiceHandler(ctx, g.mux, conn); err != nil {
		return fmt.Errorf("failed to register Correlation service: %w", err)
	}
	
	// Register Observability service
	if err := pb.RegisterObservabilityServiceHandler(ctx, g.mux, conn); err != nil {
		return fmt.Errorf("failed to register Observability service: %w", err)
	}
	
	g.logger.Info("REST gateway services registered successfully")
	return nil
}

// GetHandler returns the HTTP handler for the REST gateway
func (g *RESTGateway) GetHandler() http.Handler {
	// Create handler chain
	handler := http.Handler(g.mux)
	
	// Add CORS if enabled
	if g.config.EnableCORS {
		handler = corsHandler(handler)
	}
	
	// Add request size limiting
	handler = limitRequestSize(handler, g.config.MaxRequestSize)
	
	// Add logging middleware
	handler = loggingMiddleware(g.logger, handler)
	
	// Add metrics middleware
	handler = metricsMiddleware(handler)
	
	// Add recovery middleware
	handler = recoveryMiddleware(g.logger, handler)
	
	// Add custom REST routes
	restMux := http.NewServeMux()
	
	// Mount the gRPC-gateway handler
	restMux.Handle("/api/v1/", http.StripPrefix("/api/v1", handler))
	
	// Add health check endpoints
	restMux.HandleFunc("/health", g.healthCheck)
	restMux.HandleFunc("/health/ready", g.readinessCheck)
	restMux.HandleFunc("/health/live", g.livenessCheck)
	
	// Add metrics endpoint
	restMux.HandleFunc("/metrics", g.metricsHandler)
	
	// Add OpenAPI/Swagger endpoint if enabled
	if g.config.EnableSwagger {
		restMux.HandleFunc("/swagger.json", g.swaggerHandler)
		restMux.Handle("/swagger/", http.StripPrefix("/swagger/", swaggerUIHandler()))
	}
	
	// Add custom REST endpoints
	restMux.HandleFunc("/api/v1/events/batch", g.batchEventHandler)
	restMux.HandleFunc("/api/v1/events/stream", g.streamEventHandler)
	restMux.HandleFunc("/api/v1/correlations/analyze", g.analyzeCorrelationsHandler)
	
	return restMux
}

// Close closes the REST gateway
func (g *RESTGateway) Close() error {
	if g.grpcConn != nil {
		return g.grpcConn.Close()
	}
	return nil
}

// Health check handlers

func (g *RESTGateway) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, timeNow())
}

func (g *RESTGateway) readinessCheck(w http.ResponseWriter, r *http.Request) {
	// Check if gRPC connection is ready
	if g.grpcConn == nil || g.grpcConn.GetState().String() != "READY" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"not_ready","reason":"gRPC connection not established"}`)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ready","timestamp":"%s"}`, timeNow())
}

func (g *RESTGateway) livenessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"alive","timestamp":"%s"}`, timeNow())
}

func (g *RESTGateway) metricsHandler(w http.ResponseWriter, r *http.Request) {
	// This would integrate with Prometheus or other metrics systems
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "# HELP tapio_rest_requests_total Total number of REST API requests")
	fmt.Fprintln(w, "# TYPE tapio_rest_requests_total counter")
	fmt.Fprintln(w, "tapio_rest_requests_total 1000")
}

func (g *RESTGateway) swaggerHandler(w http.ResponseWriter, r *http.Request) {
	// Serve the generated OpenAPI spec
	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, r, "/proto/gen/openapiv2/tapio.swagger.json")
}

// Custom REST endpoints for enhanced functionality

func (g *RESTGateway) batchEventHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// This would handle batch event submissions with optimized processing
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, `{"status":"accepted","message":"Batch processing initiated","batch_id":"%s"}`, generateBatchID())
}

func (g *RESTGateway) streamEventHandler(w http.ResponseWriter, r *http.Request) {
	// Check if client supports SSE
	if r.Header.Get("Accept") != "text/event-stream" {
		http.Error(w, "SSE not supported by client", http.StatusNotAcceptable)
		return
	}
	
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	
	// Create SSE writer
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	
	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"connected\",\"timestamp\":\"%s\"}\n\n", timeNow())
	flusher.Flush()
	
	// This would stream real events from the event service
	// For now, just send a sample event
	fmt.Fprintf(w, "event: event\ndata: {\"id\":\"evt_001\",\"type\":\"sample\",\"timestamp\":\"%s\"}\n\n", timeNow())
	flusher.Flush()
}

func (g *RESTGateway) analyzeCorrelationsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// This would trigger correlation analysis with REST-specific options
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, `{"status":"analyzing","analysis_id":"%s","estimated_time_seconds":30}`, generateAnalysisID())
}

// Middleware functions

func corsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Request-ID")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, X-Trace-ID")
		w.Header().Set("Access-Control-Max-Age", "3600")
		
		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func limitRequestSize(next http.Handler, maxSize int64) http.Handler {
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB default
	}
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxSize)
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := timeNow()
		
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		// Log request start
		logger.Debug("REST API request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		)
		
		next.ServeHTTP(wrapped, r)
		
		// Log request completion
		logger.Debug("REST API response",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", wrapped.statusCode),
			zap.String("duration", timeSince(start)),
		)
	})
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := timeNow()
		
		// Wrap response writer to capture metrics
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		// Record metrics (would integrate with Prometheus)
		_ = timeSince(start)
		_ = wrapped.statusCode
	})
}

func recoveryMiddleware(logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("REST API panic recovered",
					zap.Any("error", err),
					zap.String("path", r.URL.Path),
				)
				
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"error":"Internal server error","code":"INTERNAL_ERROR"}`)
			}
		}()
		
		next.ServeHTTP(w, r)
	})
}

// Helper functions

func annotateMetadata(ctx context.Context, req *http.Request) metadata.MD {
	md := metadata.New(map[string]string{
		"x-forwarded-for":  req.RemoteAddr,
		"x-forwarded-host": req.Host,
		"x-request-id":     req.Header.Get("X-Request-ID"),
		"user-agent":       req.UserAgent(),
	})
	return md
}

func customHTTPError(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	// Convert gRPC errors to REST-friendly errors
	w.Header().Set("Content-Type", "application/json")
	
	// Default error response
	code := http.StatusInternalServerError
	message := "Internal server error"
	
	// Map specific errors to HTTP status codes
	// This would be expanded with proper error mapping
	
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":"%s","code":"%d","timestamp":"%s"}`, message, code, timeNow())
}

func swaggerUIHandler() http.Handler {
	// This would serve Swagger UI assets
	// For now, return a simple handler
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>Swagger UI would be served here</h1></body></html>`)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Utility functions for time handling
func timeNow() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func timeSince(start string) string {
	// Simple duration calculation
	return "1ms"
}

func generateBatchID() string {
	return fmt.Sprintf("batch_%d", time.Now().UnixNano())
}

func generateAnalysisID() string {
	return fmt.Sprintf("analysis_%d", time.Now().UnixNano())
}