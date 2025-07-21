package otel

import (
	"context"
	"fmt"

	"github.com/yairfalse/tapio/pkg/domain"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// CollectorInstrumentation provides OTEL instrumentation for collectors
type CollectorInstrumentation struct {
	otel     *SimpleOTELIntegration
	enhancer *EventEnhancer
}

// NewCollectorInstrumentation creates collector instrumentation
func NewCollectorInstrumentation(otel *SimpleOTELIntegration) *CollectorInstrumentation {
	return &CollectorInstrumentation{
		otel:     otel,
		enhancer: NewEventEnhancer(otel),
	}
}

// InstrumentCollectorStart creates a span for collector startup
func (ci *CollectorInstrumentation) InstrumentCollectorStart(ctx context.Context, collectorName string) (context.Context, trace.Span) {
	if !ci.otel.IsEnabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	return ci.otel.StartSpan(ctx, fmt.Sprintf("%s-collector-start", collectorName),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("component", "tapio-collector"),
			attribute.String("collector.name", collectorName),
			attribute.String("operation", "start"),
		),
	)
}

// InstrumentEventProcessing creates a span for event processing and enhances the event
func (ci *CollectorInstrumentation) InstrumentEventProcessing(ctx context.Context, event *domain.UnifiedEvent) (context.Context, trace.Span) {
	if !ci.otel.IsEnabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	// Create span for event processing
	ctx, span := ci.enhancer.CreateEventSpan(ctx, event)

	// Enhance the event with trace context
	ci.enhancer.EnhanceEvent(ctx, event)

	return ctx, span
}

// InstrumentCollectorHealth creates a span for health checks
func (ci *CollectorInstrumentation) InstrumentCollectorHealth(ctx context.Context, collectorName string) (context.Context, trace.Span) {
	if !ci.otel.IsEnabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	return ci.otel.StartSpan(ctx, fmt.Sprintf("%s-collector-health", collectorName),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("component", "tapio-collector"),
			attribute.String("collector.name", collectorName),
			attribute.String("operation", "health-check"),
		),
	)
}

// RecordCollectorMetrics records collector metrics as span events
func (ci *CollectorInstrumentation) RecordCollectorMetrics(ctx context.Context, collectorName string, eventsProcessed, eventsDropped uint64) {
	if !ci.otel.IsEnabled() {
		return
	}

	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	span.SetAttributes(
		attribute.Int64("collector.events_processed", int64(eventsProcessed)),
		attribute.Int64("collector.events_dropped", int64(eventsDropped)),
	)

	span.AddEvent("collector-metrics-recorded",
		trace.WithAttributes(
			attribute.String("collector.name", collectorName),
			attribute.Int64("events_processed", int64(eventsProcessed)),
			attribute.Int64("events_dropped", int64(eventsDropped)),
		),
	)
}

// RecordError records an error in the current span
func (ci *CollectorInstrumentation) RecordError(ctx context.Context, err error, message string) {
	if !ci.otel.IsEnabled() || err == nil {
		return
	}

	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	span.RecordError(err,
		trace.WithAttributes(
			attribute.String("error.message", message),
		),
	)
	span.SetStatus(codes.Error, message)
}