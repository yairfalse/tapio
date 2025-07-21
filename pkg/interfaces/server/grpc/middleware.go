package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ServerMiddleware provides common middleware for gRPC services
type ServerMiddleware struct {
	logger *zap.Logger
	tracer trace.Tracer

	// Metrics
	mu               sync.RWMutex
	requestCount     int64
	errorCount       int64
	totalLatency     time.Duration
	requestHistogram map[string]int64
}

// NewServerMiddleware creates a new server middleware instance
func NewServerMiddleware(logger *zap.Logger, tracer trace.Tracer) *ServerMiddleware {
	return &ServerMiddleware{
		logger:           logger,
		tracer:           tracer,
		requestHistogram: make(map[string]int64),
	}
}

// UnaryInterceptor returns a unary server interceptor with comprehensive middleware
func (sm *ServerMiddleware) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Start tracing span
		ctx, span := sm.tracer.Start(ctx, info.FullMethod,
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", info.FullMethod),
				attribute.String("rpc.method", info.FullMethod),
			),
		)
		defer span.End()

		// Add request metadata to span
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			for key, values := range md {
				if len(values) > 0 {
					span.SetAttributes(attribute.String("grpc.metadata."+key, values[0]))
				}
			}
		}

		// Log request start
		sm.logger.Debug("gRPC request started",
			zap.String("method", info.FullMethod),
			zap.Time("start_time", start),
		)

		// Call the handler
		resp, err := handler(ctx, req)

		// Calculate latency
		latency := time.Since(start)

		// Update metrics
		sm.updateMetrics(info.FullMethod, latency, err)

		// Add latency to span
		span.SetAttributes(
			attribute.Int64("rpc.duration_ms", latency.Milliseconds()),
		)

		// Handle errors
		if err != nil {
			span.RecordError(err)
			sm.logger.Error("gRPC request failed",
				zap.String("method", info.FullMethod),
				zap.Duration("latency", latency),
				zap.Error(err),
			)

			// Convert error to appropriate gRPC status
			if grpcErr, ok := status.FromError(err); ok {
				span.SetAttributes(attribute.String("grpc.status_code", grpcErr.Code().String()))
			}
		} else {
			span.SetAttributes(attribute.String("grpc.status_code", codes.OK.String()))
			sm.logger.Debug("gRPC request completed",
				zap.String("method", info.FullMethod),
				zap.Duration("latency", latency),
			)
		}

		return resp, err
	}
}

// StreamInterceptor returns a stream server interceptor
func (sm *ServerMiddleware) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()

		// Start tracing span
		ctx, span := sm.tracer.Start(stream.Context(), info.FullMethod,
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", info.FullMethod),
				attribute.String("rpc.method", info.FullMethod),
				attribute.Bool("rpc.streaming", true),
			),
		)
		defer span.End()

		// Wrap stream with tracing context
		wrappedStream := &tracedServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		sm.logger.Debug("gRPC stream started",
			zap.String("method", info.FullMethod),
			zap.Time("start_time", start),
		)

		// Call the handler
		err := handler(srv, wrappedStream)

		// Calculate latency
		latency := time.Since(start)

		// Update metrics
		sm.updateMetrics(info.FullMethod, latency, err)

		// Add latency to span
		span.SetAttributes(
			attribute.Int64("rpc.duration_ms", latency.Milliseconds()),
		)

		if err != nil {
			span.RecordError(err)
			sm.logger.Error("gRPC stream failed",
				zap.String("method", info.FullMethod),
				zap.Duration("latency", latency),
				zap.Error(err),
			)
		} else {
			sm.logger.Debug("gRPC stream completed",
				zap.String("method", info.FullMethod),
				zap.Duration("latency", latency),
			)
		}

		return err
	}
}

// tracedServerStream wraps a grpc.ServerStream with tracing context
type tracedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *tracedServerStream) Context() context.Context {
	return s.ctx
}

// updateMetrics updates internal metrics
func (sm *ServerMiddleware) updateMetrics(method string, latency time.Duration, err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.requestCount++
	sm.totalLatency += latency
	sm.requestHistogram[method]++

	if err != nil {
		sm.errorCount++
	}
}

// GetMetrics returns current middleware metrics
func (sm *ServerMiddleware) GetMetrics() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	avgLatency := float64(0)
	if sm.requestCount > 0 {
		avgLatency = float64(sm.totalLatency.Milliseconds()) / float64(sm.requestCount)
	}

	errorRate := float64(0)
	if sm.requestCount > 0 {
		errorRate = float64(sm.errorCount) / float64(sm.requestCount)
	}

	// Copy request histogram
	histogram := make(map[string]int64)
	for k, v := range sm.requestHistogram {
		histogram[k] = v
	}

	return map[string]interface{}{
		"request_count":     sm.requestCount,
		"error_count":       sm.errorCount,
		"error_rate":        errorRate,
		"avg_latency_ms":    avgLatency,
		"request_histogram": histogram,
	}
}

// RateLimitInterceptor provides rate limiting functionality
func RateLimitInterceptor(requestsPerSecond int) grpc.UnaryServerInterceptor {
	limiter := rate.NewLimiter(rate.Limit(requestsPerSecond), requestsPerSecond)

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !limiter.Allow() {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// AuthInterceptor provides authentication functionality
func AuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip auth for health checks
		if info.FullMethod == "/grpc.health.v1.Health/Check" {
			return handler(ctx, req)
		}

		// Get metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// Check for authorization token
		authTokens := md.Get("authorization")
		if len(authTokens) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization token")
		}

		token := authTokens[0]

		// Validate token (simplified - would use real auth service)
		if !isValidToken(token) {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization token")
		}

		// Add user info to context (would extract from real token)
		ctx = context.WithValue(ctx, "user_id", "authenticated_user")

		return handler(ctx, req)
	}
}

// ValidationInterceptor provides request validation
func ValidationInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Validate request based on method
		if err := validateRequest(info.FullMethod, req); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "validation failed: %v", err)
		}

		return handler(ctx, req)
	}
}

// MetricsInterceptor provides detailed metrics collection
func MetricsInterceptor() grpc.UnaryServerInterceptor {
	metrics := &RequestMetrics{
		methodCounts:  make(map[string]int64),
		methodLatency: make(map[string]time.Duration),
		statusCounts:  make(map[string]int64),
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Call handler
		resp, err := handler(ctx, req)

		// Record metrics
		latency := time.Since(start)
		statusCode := codes.OK
		if err != nil {
			if grpcErr, ok := status.FromError(err); ok {
				statusCode = grpcErr.Code()
			}
		}

		metrics.recordRequest(info.FullMethod, latency, statusCode)

		// Add metrics to context for potential use by handlers
		ctx = context.WithValue(ctx, "metrics", metrics)

		return resp, err
	}
}

// RequestMetrics tracks detailed request metrics
type RequestMetrics struct {
	mu            sync.RWMutex
	methodCounts  map[string]int64
	methodLatency map[string]time.Duration
	statusCounts  map[string]int64
}

func (rm *RequestMetrics) recordRequest(method string, latency time.Duration, statusCode codes.Code) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.methodCounts[method]++
	rm.methodLatency[method] += latency
	rm.statusCounts[statusCode.String()]++
}

func (rm *RequestMetrics) GetMetrics() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Copy maps to avoid race conditions
	methods := make(map[string]int64)
	for k, v := range rm.methodCounts {
		methods[k] = v
	}

	latencies := make(map[string]float64)
	for k, v := range rm.methodLatency {
		if count, exists := rm.methodCounts[k]; exists && count > 0 {
			latencies[k] = float64(v.Milliseconds()) / float64(count)
		}
	}

	statuses := make(map[string]int64)
	for k, v := range rm.statusCounts {
		statuses[k] = v
	}

	return map[string]interface{}{
		"method_counts":    methods,
		"avg_latencies_ms": latencies,
		"status_counts":    statuses,
	}
}

// Helper functions

func isValidToken(token string) bool {
	// Simplified token validation
	// In production, this would validate JWT tokens or call an auth service
	return token != "" && len(token) > 10
}

func validateRequest(method string, req interface{}) error {
	// Basic request validation
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	// Method-specific validation would go here
	switch method {
	case "/tapio.v1.EventService/SubmitEvent":
		// Validate event submission request
		return validateEventSubmission(req)
	case "/tapio.v1.CorrelationService/AnalyzeEvents":
		// Validate correlation analysis request
		return validateCorrelationAnalysis(req)
	default:
		// No specific validation for this method
		return nil
	}
}

func validateEventSubmission(req interface{}) error {
	// Would validate event submission request structure
	// For now, just return nil
	return nil
}

func validateCorrelationAnalysis(req interface{}) error {
	// Would validate correlation analysis request
	// For now, just return nil
	return nil
}

// HealthCheckInterceptor provides health check functionality
func HealthCheckInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Add health check metadata to context
		start := time.Now()
		ctx = context.WithValue(ctx, "health_check_start", start)

		resp, err := handler(ctx, req)

		// Log health check latency
		latency := time.Since(start)
		if latency > 100*time.Millisecond {
			// Log slow health checks
			if logger := ctx.Value("logger"); logger != nil {
				if zapLogger, ok := logger.(*zap.Logger); ok {
					zapLogger.Warn("Slow health check",
						zap.String("method", info.FullMethod),
						zap.Duration("latency", latency),
					)
				}
			}
		}

		return resp, err
	}
}

// RecoveryInterceptor provides panic recovery
func RecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				// Log the panic
				if logger := ctx.Value("logger"); logger != nil {
					if zapLogger, ok := logger.(*zap.Logger); ok {
						zapLogger.Error("gRPC handler panic recovered",
							zap.String("method", info.FullMethod),
							zap.Any("panic", r),
						)
					}
				}

				// Return internal error
				err = status.Error(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}
