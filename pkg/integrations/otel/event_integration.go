package otel

import (
	"context"

	"github.com/yairfalse/tapio/pkg/domain"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// EventEnhancer enhances UnifiedEvents with OTEL trace context
type EventEnhancer struct {
	otel *SimpleOTELIntegration
}

// NewEventEnhancer creates a new event enhancer
func NewEventEnhancer(otel *SimpleOTELIntegration) *EventEnhancer {
	return &EventEnhancer{
		otel: otel,
	}
}

// EnhanceEvent adds OTEL trace context to a UnifiedEvent
// This is the key function that bridges OTEL spans with our UnifiedEvent
func (e *EventEnhancer) EnhanceEvent(ctx context.Context, event *domain.UnifiedEvent) {
	if !e.otel.IsEnabled() {
		return
	}

	// Get current span from context
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	// Extract trace context
	spanContext := span.SpanContext()
	if !spanContext.IsValid() {
		return
	}

	// Add trace context to UnifiedEvent
	event.TraceContext = &domain.TraceContext{
		TraceID:      spanContext.TraceID().String(),
		SpanID:       spanContext.SpanID().String(),
		ParentSpanID: "", // Will be set if there's a parent
	}

	// Add event attributes to span
	span.SetAttributes(
		attribute.String("event.id", event.ID),
		attribute.String("event.source", event.Source),
		attribute.String("event.type", string(event.Type)),
	)

	// Add source-specific attributes
	switch event.Source {
	case string(domain.SourceCNI):
		e.addCNIAttributes(span, event)
	case string(domain.SourceK8s):
		e.addKubernetesAttributes(span, event)
	case string(domain.SourceSystemd):
		e.addSystemDAttributes(span, event)
	}

	// Add semantic attributes if available
	if event.Semantic != nil {
		span.SetAttributes(
			attribute.String("semantic.intent", event.Semantic.Intent),
			attribute.String("semantic.category", event.Semantic.Category),
			attribute.Float64("semantic.confidence", event.Semantic.Confidence),
		)
	}

	// Add entity attributes if available
	if event.Entity != nil {
		span.SetAttributes(
			attribute.String("entity.type", event.Entity.Type),
			attribute.String("entity.name", event.Entity.Name),
			attribute.String("entity.namespace", event.Entity.Namespace),
		)
	}
}

// CreateEventSpan creates a new span for event processing
func (e *EventEnhancer) CreateEventSpan(ctx context.Context, event *domain.UnifiedEvent) (context.Context, trace.Span) {
	if !e.otel.IsEnabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	spanName := e.generateSpanName(event)
	return e.otel.StartSpan(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("component", "tapio-collector"),
			attribute.String("event.source", event.Source),
		),
	)
}

// generateSpanName creates a descriptive span name based on the event
func (e *EventEnhancer) generateSpanName(event *domain.UnifiedEvent) string {
	if event.Semantic != nil && event.Semantic.Intent != "" {
		return event.Semantic.Intent
	}
	return event.Source + "-event-processing"
}

// addCNIAttributes adds CNI-specific attributes to the span
func (e *EventEnhancer) addCNIAttributes(span trace.Span, event *domain.UnifiedEvent) {
	if event.Network == nil {
		return
	}

	span.SetAttributes(
		attribute.String("network.protocol", event.Network.Protocol),
		attribute.String("network.direction", event.Network.Direction),
	)

	if event.Network.SourceIP != "" {
		span.SetAttributes(attribute.String("network.source_ip", event.Network.SourceIP))
	}

	if event.Network.Headers != nil {
		for k, v := range event.Network.Headers {
			span.SetAttributes(attribute.String("network."+k, v))
		}
	}
}

// addKubernetesAttributes adds Kubernetes-specific attributes to the span
func (e *EventEnhancer) addKubernetesAttributes(span trace.Span, event *domain.UnifiedEvent) {
	if event.Kubernetes == nil {
		return
	}

	span.SetAttributes(
		attribute.String("k8s.event_type", event.Kubernetes.EventType),
		attribute.String("k8s.reason", event.Kubernetes.Reason),
		attribute.String("k8s.object", event.Kubernetes.Object),
		attribute.String("k8s.object_kind", event.Kubernetes.ObjectKind),
		attribute.String("k8s.action", event.Kubernetes.Action),
	)
}

// addSystemDAttributes adds SystemD-specific attributes to the span
func (e *EventEnhancer) addSystemDAttributes(span trace.Span, event *domain.UnifiedEvent) {
	// Add SystemD-specific attributes when we have SystemD data structure
	// For now, just add basic attributes
	span.SetAttributes(
		attribute.String("systemd.source", "systemd"),
	)
}