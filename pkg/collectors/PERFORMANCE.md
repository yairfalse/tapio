# Performance Integration Guide for Tapio Collectors

## Overview

Tapio collectors now integrate high-performance data structures from `pkg/performance` to achieve 165k+ events per second throughput. This guide explains how to integrate the performance components into collectors.

## Architecture

### Components

1. **PerformanceAdapter** (`pkg/collectors/common/performance_adapter.go`)
   - Provides a unified interface for all collectors
   - Handles event buffering, batching, and zero-copy operations
   - Manages object pools for GC reduction

2. **RingBuffer** (`pkg/performance/ring_buffer.go`)
   - Lock-free, multi-producer multi-consumer
   - Zero-copy event passing
   - Cache-line padding to prevent false sharing

3. **ObjectPool** (`pkg/performance/object_pool.go`)
   - Per-CPU pools to reduce contention
   - 90%+ reduction in allocations
   - Sub-microsecond Get/Put operations

## Integration Steps

### 1. Import the Performance Adapter

```go
import (
    "github.com/yairfalse/tapio/pkg/collectors/common"
)
```

### 2. Add Performance Adapter to Your Collector

```go
type MyCollector struct {
    // ... existing fields ...
    
    // Performance adapter for high-throughput event handling
    perfAdapter *common.PerformanceAdapter
}
```

### 3. Initialize in Constructor

```go
func NewMyCollector(config Config) (*MyCollector, error) {
    // Initialize performance adapter
    perfConfig := common.DefaultPerformanceConfig("mycollector")
    
    // Optionally customize configuration
    if config.EventBufferSize > 0 {
        // Ensure power of 2
        size := uint64(config.EventBufferSize)
        if size&(size-1) != 0 {
            // Round up to next power of 2
            size = 1
            for size < uint64(config.EventBufferSize) {
                size *= 2
            }
        }
        perfConfig.BufferSize = size
    }
    
    perfAdapter, err := common.NewPerformanceAdapter(perfConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create performance adapter: %w", err)
    }
    
    return &MyCollector{
        // ... other fields ...
        perfAdapter: perfAdapter,
    }, nil
}
```

### 4. Start/Stop the Adapter

```go
func (c *MyCollector) Start(ctx context.Context) error {
    // Start performance adapter first
    if err := c.perfAdapter.Start(); err != nil {
        return fmt.Errorf("failed to start performance adapter: %w", err)
    }
    
    // ... rest of start logic ...
}

func (c *MyCollector) Stop() error {
    // ... stop processing ...
    
    // Stop performance adapter last
    if err := c.perfAdapter.Stop(); err != nil {
        return fmt.Errorf("failed to stop performance adapter: %w", err)
    }
    
    return nil
}
```

### 5. Submit Events

```go
// For single events
func (c *MyCollector) processEvent(rawEvent RawEvent) {
    // Get event from pool (zero allocation)
    event := c.perfAdapter.GetEvent()
    
    // Fill event data
    event.ID = domain.GenerateEventID()
    event.Type = "myevent"
    event.Timestamp = time.Now()
    // ... fill other fields ...
    
    // Submit to performance adapter
    if err := c.perfAdapter.Submit(event); err != nil {
        // Handle error (event dropped)
        c.stats.dropped++
    }
}

// For batch operations
func (c *MyCollector) processBatch(rawEvents []RawEvent) {
    events := make([]*domain.UnifiedEvent, len(rawEvents))
    
    for i, raw := range rawEvents {
        event := c.perfAdapter.GetEvent()
        // ... fill event ...
        events[i] = event
    }
    
    added, err := c.perfAdapter.SubmitBatch(events)
    if err != nil && added < len(events) {
        // Some events were dropped
        c.stats.dropped += len(events) - added
    }
}
```

### 6. Expose Events Channel

```go
func (c *MyCollector) Events() <-chan domain.UnifiedEvent {
    // Return the performance adapter's output channel
    return c.perfAdapter.Events()
}
```

### 7. Include Performance Metrics

```go
func (c *MyCollector) Statistics() core.Statistics {
    perfMetrics := c.perfAdapter.GetMetrics()
    
    return core.Statistics{
        // ... existing stats ...
        Custom: map[string]interface{}{
            // ... other custom stats ...
            "buffer_size":        perfMetrics.BufferSize,
            "buffer_capacity":    perfMetrics.BufferCapacity,
            "buffer_utilization": perfMetrics.BufferUtilization,
            "batches_processed":  perfMetrics.BatchesProcessed,
            "pool_allocated":     perfMetrics.PoolAllocated,
            "pool_recycled":      perfMetrics.PoolRecycled,
            "pool_in_use":        perfMetrics.PoolInUse,
        },
    }
}
```

## Default Configurations

The `DefaultPerformanceConfig` provides optimized settings for each collector:

| Collector | Buffer Size | Batch Size | Batch Timeout | Description |
|-----------|------------|------------|---------------|-------------|
| eBPF      | 131,072    | 1,000      | 10ms         | High-volume kernel events |
| K8s       | 16,384     | 100        | 50ms         | Moderate API events |
| CNI       | 32,768     | 200        | 25ms         | Network events |
| systemd   | 32,768     | 200        | 25ms         | System logs |
| default   | 65,536     | 500        | 20ms         | General purpose |

## Best Practices

1. **Always use power-of-2 buffer sizes** for optimal performance
2. **Get events from the pool** to avoid allocations
3. **Return events to pool** if using zero-copy mode (default)
4. **Monitor buffer utilization** to detect backpressure
5. **Batch operations** when possible for better throughput

## Performance Characteristics

- **Throughput**: 165k+ events/second
- **Latency**: Sub-microsecond for pool operations
- **Memory**: 90%+ reduction in allocations
- **CPU**: Lock-free operations minimize contention

## Example: Full Integration

See `pkg/collectors/ebpf/internal/collector.go` for a complete example of performance integration in the eBPF collector.

## Troubleshooting

### Buffer Full Errors
- Increase buffer size (must be power of 2)
- Reduce event generation rate
- Check downstream processing bottlenecks

### High Memory Usage
- Verify events are returned to pool
- Check for event reference leaks
- Monitor pool statistics

### Performance Degradation
- Check buffer utilization metrics
- Verify batch size is appropriate
- Monitor GC pressure with runtime metrics