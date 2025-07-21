# Simple OTEL Integration

A **simple, focused** OpenTelemetry integration for Tapio collectors. This is intentionally minimal - no correlation engines, no complex logic, just basic OTEL span creation and trace context propagation.

## Philosophy

After learning from a previous 98K line OTEL implementation, this integration follows the **KISS principle**:
- ✅ **Simple**: ~200 lines total
- ✅ **Focused**: Only span creation and context propagation  
- ✅ **Clean**: Uses official OTEL SDK, doesn't reinvent it
- ❌ **No correlation engines**: That's handled by DataFlow layer
- ❌ **No custom protocols**: Uses standard OTEL
- ❌ **No over-engineering**: Just what we need

## Usage

### Basic Setup

```go
import "github.com/yairfalse/tapio/pkg/integrations/otel"

// Create OTEL integration
config := otel.DefaultConfig()
config.ServiceName = "tapio-cni-collector"
config.JaegerEndpoint = "http://jaeger:14268/api/traces"

otelIntegration, err := otel.NewSimpleOTEL(config)
if err != nil {
    log.Fatal(err)
}
defer otelIntegration.Shutdown(context.Background())
```

### Collector Integration

```go
// Create collector instrumentation
instrumentation := otel.NewCollectorInstrumentation(otelIntegration)

// Instrument collector startup
ctx, span := instrumentation.InstrumentCollectorStart(ctx, "cni")
defer span.End()

// Instrument event processing
for event := range eventChan {
    ctx, span := instrumentation.InstrumentEventProcessing(ctx, &event)
    
    // Process event here...
    // The event now has TraceContext filled in automatically
    
    span.End()
}
```

### Event Enhancement

```go
// Events are automatically enhanced with trace context
func processEvent(ctx context.Context, event *domain.UnifiedEvent) {
    ctx, span := instrumentation.InstrumentEventProcessing(ctx, event)
    defer span.End()
    
    // After instrumentation, event.TraceContext is populated:
    // event.TraceContext.TraceID = "abc123..."
    // event.TraceContext.SpanID = "def456..."
    
    // Send to DataFlow for correlation
    dataFlow.Process(event)
}
```

## Features

### 1. Trace Context Propagation
- Automatically adds `TraceContext` to `UnifiedEvent`
- Propagates trace context through the entire pipeline
- Compatible with existing trace context extraction

### 2. Collector Instrumentation
- **Collector startup**: `InstrumentCollectorStart()`
- **Event processing**: `InstrumentEventProcessing()`
- **Health checks**: `InstrumentCollectorHealth()`
- **Metrics recording**: `RecordCollectorMetrics()`

### 3. Event Enhancement
- Automatically enhances `UnifiedEvent` with trace context
- Adds event attributes to OTEL spans
- Source-specific attribute handling (CNI, K8s, SystemD)

### 4. Error Handling
- `RecordError()` for proper error tracing
- Graceful degradation when OTEL is disabled
- No-op behavior when tracing is not available

## Configuration

```go
type Config struct {
    ServiceName    string  // Service name for traces
    ServiceVersion string  // Service version
    Environment    string  // Environment (dev, staging, prod)
    JaegerEndpoint string  // Jaeger collector endpoint
    Enabled        bool    // Enable/disable OTEL
}
```

## Integration with Existing Code

This integration is designed to work with our existing trace-aware code:

### Before (trace context extraction only)
```go
// pkg/collectors/cni/internal/processor.go:590
func (p *cniEventProcessor) extractTraceContext(raw core.CNIRawEvent) *domain.TraceContext {
    // Extract from annotations...
}
```

### After (active span creation + extraction)
```go
func (p *cniEventProcessor) ProcessEvent(ctx context.Context, raw core.CNIRawEvent) (*domain.UnifiedEvent, error) {
    // Create OTEL span for this processing
    ctx, span := p.instrumentation.InstrumentEventProcessing(ctx, event)
    defer span.End()
    
    // Process event...
    event := &domain.UnifiedEvent{...}
    
    // OTEL automatically adds TraceContext to event
    // Still check annotations as fallback
    if event.TraceContext == nil {
        event.TraceContext = p.extractTraceContext(raw)
    }
    
    return event, nil
}
```

## Architecture Integration

```
┌─────────────────────────────────────────────────────────────┐
│                    Event Flow with OTEL                    │
├─────────────────────────────────────────────────────────────┤
│ CNI Collector                                               │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ 1. Create OTEL span for CNI operation                  │ │
│ │ 2. Process CNI event → UnifiedEvent                    │ │
│ │ 3. Enhance UnifiedEvent with TraceContext              │ │
│ │ 4. Send to CollectorManager                            │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ CollectorManager                                            │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ • Receives UnifiedEvent with TraceContext               │ │
│ │ • Propagates trace context through pipeline            │ │
│ │ • Routes to DataFlow with trace preservation           │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ DataFlow                                                    │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ • Correlates events while preserving trace context     │ │
│ │ • Links related events via TraceID                     │ │
│ │ • Enhanced correlation with distributed tracing        │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## File Structure

```
pkg/integrations/otel/
├── tracer.go                 # Core OTEL setup and tracer creation
├── event_integration.go      # UnifiedEvent enhancement with trace context  
├── collector_integration.go  # Collector instrumentation utilities
└── README.md                # This file
```

## Benefits

1. **End-to-end tracing**: From CNI operation to DataFlow correlation
2. **Distributed correlation**: Link events across different collectors
3. **Performance monitoring**: Track event processing latency
4. **Error tracking**: Proper error recording in traces
5. **Observability**: Full visibility into collector pipeline

## What This Is NOT

- ❌ **Not a correlation engine**: Uses existing DataFlow correlation
- ❌ **Not a custom OTEL implementation**: Uses official SDK
- ❌ **Not over-engineered**: Simple, focused functionality
- ❌ **Not 98K lines**: ~200 lines total

## Next Steps

1. Add OTEL dependencies to `go.mod`
2. Integrate with CNI collector
3. Test trace context propagation
4. Verify Jaeger integration
5. Document trace visualization

This integration provides the foundation for distributed tracing without the complexity of previous implementations.