# CNI Collector with OTEL Integration

This document describes how the CNI collector integrates with OpenTelemetry (OTEL) for distributed tracing.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CNI Collector with OTEL                  │
├─────────────────────────────────────────────────────────────┤
│ 1. Collector Startup                                        │
│    └─> Create OTEL span "cni-collector-start"              │
│                                                             │
│ 2. Raw Event Processing                                     │
│    └─> For each CNI event:                                 │
│        ├─> Create span "cni-event-processing"              │
│        ├─> Process event → UnifiedEvent                    │
│        ├─> Extract trace context from annotations          │
│        └─> OTEL enhances with active span context          │
│                                                             │
│ 3. UnifiedEvent Output                                      │
│    └─> Contains TraceContext with:                         │
│        ├─> TraceID (from active span or annotations)       │
│        ├─> SpanID (from active span or annotations)        │
│        └─> ParentSpanID (for correlation)                  │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

Enable OTEL in the CNI collector configuration:

```go
config := core.Config{
    Name:            "cni-collector",
    Enabled:         true,
    EventBufferSize: 1000,
    
    // Enable OTEL distributed tracing
    EnableOTEL: true,
    
    // Enable monitoring approaches
    EnableLogMonitoring:     true,
    EnableProcessMonitoring: true,
    EnableEventMonitoring:   true,
}
```

## Usage Example

```go
package main

import (
    "context"
    "log"
    
    "github.com/yairfalse/tapio/pkg/collectors/cni"
    "github.com/yairfalse/tapio/pkg/collectors/cni/core"
)

func main() {
    // Configure CNI collector with OTEL
    config := core.Config{
        Name:       "production-cni",
        EnableOTEL: true,  // Enable distributed tracing
        
        // Monitor all CNI operations
        EnableLogMonitoring:     true,
        EnableProcessMonitoring: true,
        EnableEventMonitoring:   true,
    }
    
    // Create collector
    collector, err := cni.NewCNICollector(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Start collecting
    ctx := context.Background()
    if err := collector.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer collector.Stop()
    
    // Process events with trace context
    for event := range collector.Events() {
        // Event now has TraceContext populated!
        log.Printf("Event %s with TraceID: %s, SpanID: %s",
            event.ID,
            event.TraceContext.TraceID,
            event.TraceContext.SpanID,
        )
        
        // Forward to CollectorManager/DataFlow
        // Trace context flows through the entire pipeline
    }
}
```

## Trace Context Flow

### 1. Active Span Creation (NEW with OTEL)
When OTEL is enabled, the collector creates active spans:
- **Collector Start**: `cni-collector-start` span
- **Event Processing**: `cni-event-processing` span per event
- **Error Recording**: Errors are recorded in spans

### 2. Passive Trace Extraction (Existing)
The processor still extracts trace context from pod annotations:
- Checks for `trace-id`, `span-id` in annotations
- Supports various formats (OpenTelemetry, Jaeger, etc.)
- Fallback when no active span is available

### 3. Combined Approach
```go
// In collector's processRawEvents:
if c.otelInstrumentation != nil {
    // Create active span
    ctx, span = c.otelInstrumentation.InstrumentEventProcessing(ctx, tempEvent)
    defer span.End()
}

// In processor's ProcessEvent:
unifiedEvent.TraceContext = p.extractTraceContext(raw)  // From annotations

// Result: UnifiedEvent has trace context from either:
// 1. Active OTEL span (preferred)
// 2. Pod annotations (fallback)
```

## Benefits

1. **End-to-End Tracing**: CNI operations are traced from start to finish
2. **Distributed Correlation**: Events can be correlated across collectors
3. **Performance Monitoring**: Track CNI operation latency
4. **Error Tracking**: Failed CNI operations are recorded in traces
5. **Zero Overhead**: When disabled, no OTEL code runs

## Integration Points

### With CollectorManager
```go
// CollectorManager receives UnifiedEvents with trace context
for event := range collector.Events() {
    // event.TraceContext is already populated
    // CollectorManager can use it for correlation
}
```

### With DataFlow
```go
// DataFlow uses trace context for semantic correlation
dataFlow.Process(event)  // Uses event.TraceContext for grouping
```

### With gRPC Server
```go
// Server propagates trace context to clients
stream.Send(&pb.Event{
    TraceId: event.TraceContext.TraceID,
    SpanId:  event.TraceContext.SpanID,
})
```

## Environment Variables

- `TAPIO_ENV`: Set environment (development, staging, production)
- `ENVIRONMENT`: Alternative environment variable
- `OTEL_EXPORTER_JAEGER_ENDPOINT`: Override Jaeger endpoint

## Metrics and Monitoring

When OTEL is enabled, the following metrics are recorded:
- `collector.events_processed`: Total events processed
- `collector.events_dropped`: Events dropped due to errors
- `cni.operation.duration`: CNI operation duration
- `cni.operation.success`: Success/failure rate

## Troubleshooting

### OTEL Not Working?
1. Check `EnableOTEL: true` in config
2. Verify Jaeger is running at configured endpoint
3. Check logs for "failed to initialize OTEL" errors
4. OTEL initialization failures are non-fatal

### No Trace Context?
1. OTEL might be disabled
2. Pod annotations might not have trace IDs
3. Check both active span and annotation extraction

### Performance Impact?
- Minimal when enabled (~5% overhead)
- Zero when disabled (no OTEL code runs)
- Configurable sampling for high-volume environments