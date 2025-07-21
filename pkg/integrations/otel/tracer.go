package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// SimpleOTELIntegration provides basic OpenTelemetry integration for Tapio
// This is intentionally simple - no correlation engines, no complex logic
type SimpleOTELIntegration struct {
	tracer   oteltrace.Tracer
	provider *trace.TracerProvider
	config   Config
}

// Config for OTEL integration
type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	JaegerEndpoint string
	Enabled        bool
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		ServiceName:    "tapio-collector",
		ServiceVersion: "1.0.0",
		Environment:    "development",
		JaegerEndpoint: "http://localhost:14268/api/traces",
		Enabled:        true,
	}
}

// NewSimpleOTEL creates a new simple OTEL integration
func NewSimpleOTEL(config Config) (*SimpleOTELIntegration, error) {
	if !config.Enabled {
		return &SimpleOTELIntegration{
			tracer: otel.Tracer(config.ServiceName),
			config: config,
		}, nil
	}

	// Create resource with service information
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(config.ServiceVersion),
			semconv.DeploymentEnvironmentKey.String(config.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create Jaeger exporter
	exporter, err := jaeger.New(
		jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(config.JaegerEndpoint)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create tracer provider
	provider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(res),
		trace.WithSampler(trace.AlwaysSample()),
	)

	// Set global tracer provider
	otel.SetTracerProvider(provider)

	// Create tracer
	tracer := provider.Tracer(config.ServiceName)

	return &SimpleOTELIntegration{
		tracer:   tracer,
		provider: provider,
		config:   config,
	}, nil
}

// StartSpan creates a new span - that's it, nothing complex!
func (o *SimpleOTELIntegration) StartSpan(ctx context.Context, name string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	if !o.config.Enabled {
		return ctx, oteltrace.SpanFromContext(ctx)
	}
	return o.tracer.Start(ctx, name, opts...)
}

// GetTracer returns the underlying tracer for advanced usage
func (o *SimpleOTELIntegration) GetTracer() oteltrace.Tracer {
	return o.tracer
}

// Shutdown gracefully shuts down the tracer provider
func (o *SimpleOTELIntegration) Shutdown(ctx context.Context) error {
	if o.provider != nil {
		return o.provider.Shutdown(ctx)
	}
	return nil
}

// IsEnabled returns whether OTEL is enabled
func (o *SimpleOTELIntegration) IsEnabled() bool {
	return o.config.Enabled
}