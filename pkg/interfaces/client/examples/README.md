# Tapio Client SDK Examples

This directory contains examples of using the Tapio client SDK to interact with the observability platform.

## Installation

```go
import "github.com/yairfalse/tapio/pkg/interfaces/client"
```

## Basic Usage

### Creating a Client

```go
// Create client with default configuration
config := client.DefaultConfig()
config.RESTAddress = "http://localhost:8081"
config.GRPCAddress = "localhost:8080"

// Optional: Set authentication
config.APIKey = "your-api-key"
// OR
config.BearerToken = "your-jwt-token"

// Create client (prefers gRPC by default)
tapioClient, err := client.NewClient(config)
if err != nil {
    log.Fatal(err)
}
defer tapioClient.Close()
```

### Submitting Events

```go
// Submit a single event
event := &client.Event{
    ID:        "evt_001",
    Type:      "network",
    Severity:  "info",
    Timestamp: time.Now(),
    Message:   "Network connection established",
    Service:   "api-gateway",
    Data: map[string]interface{}{
        "source_ip": "10.0.0.1",
        "dest_ip":   "10.0.0.2",
        "protocol":  "tcp",
    },
}

resp, err := tapioClient.SubmitEvent(context.Background(), event)
if err != nil {
    log.Printf("Failed to submit event: %v", err)
} else {
    log.Printf("Event submitted: %s (status: %s)", resp.EventID, resp.Status)
}
```

### Bulk Event Submission

```go
// Submit multiple events at once
events := []*client.Event{
    {
        ID:        "bulk_001",
        Type:      "kubernetes",
        Severity:  "warning",
        Timestamp: time.Now(),
        Message:   "Pod restarted",
    },
    {
        ID:        "bulk_002",
        Type:      "system",
        Severity:  "error",
        Timestamp: time.Now(),
        Message:   "Disk space low",
    },
}

bulkResp, err := tapioClient.SubmitBulkEvents(context.Background(), events)
if err != nil {
    log.Printf("Bulk submission failed: %v", err)
} else {
    log.Printf("Bulk submission: %d successful, %d failed", bulkResp.Success, bulkResp.Failed)
}
```

### Searching Events

```go
// Search for specific events
searchResp, err := tapioClient.SearchEvents(
    context.Background(),
    "type:network AND severity:error",
    map[string][]string{
        "service": {"api-gateway", "payment-service"},
    },
)

if err != nil {
    log.Printf("Search failed: %v", err)
} else {
    log.Printf("Found %d events", searchResp.TotalHits)
    for _, event := range searchResp.Events {
        log.Printf("- %s: %s", event.ID, event.Message)
    }
}
```

### Real-time Event Streaming

```go
// Stream events in real-time
eventStream, err := tapioClient.StreamEvents(context.Background(), "type:error")
if err != nil {
    log.Fatal(err)
}

// Process events as they arrive
for event := range eventStream {
    log.Printf("Real-time event: %s - %s", event.ID, event.Message)
    
    // Process event...
}
```

### Correlation Analysis

```go
// Analyze events for correlations
eventIDs := []string{"evt_001", "evt_002", "evt_003"}

analysis, err := tapioClient.AnalyzeCorrelations(context.Background(), eventIDs)
if err != nil {
    log.Printf("Correlation analysis failed: %v", err)
} else {
    log.Printf("Analysis %s completed with %d findings", analysis.AnalysisID, len(analysis.Findings))
    
    for _, finding := range analysis.Findings {
        log.Printf("- Pattern: %s (confidence: %.2f)", finding.Pattern, finding.Confidence)
        log.Printf("  Description: %s", finding.Description)
        log.Printf("  Related events: %v", finding.EventIDs)
    }
}
```

### System Monitoring

```go
// Get system status
status, err := tapioClient.GetStatus(context.Background())
if err != nil {
    log.Printf("Failed to get status: %v", err)
} else {
    log.Printf("System status: %s", status.Status)
    log.Printf("Version: %s", status.Version)
    log.Printf("Uptime: %s", status.Uptime)
}

// Get detailed system info
info, err := tapioClient.GetSystemInfo(context.Background())
if err != nil {
    log.Printf("Failed to get system info: %v", err)
} else {
    log.Printf("Platform: %s", info.Platform)
    log.Printf("Environment: %s", info.Environment)
    log.Printf("Features: %v", info.Features)
}
```

### Collector Management

```go
// Get collector status
collectors, err := tapioClient.GetCollectorStatus(context.Background())
if err != nil {
    log.Printf("Failed to get collector status: %v", err)
} else {
    log.Printf("Total events: %d", collectors.TotalEvents)
    log.Printf("Events per second: %.2f", collectors.EventsPerSecond)
    
    for _, collector := range collectors.Collectors {
        log.Printf("- %s: %s (%.2f events/sec)", 
            collector.Name, 
            collector.Status, 
            collector.EventsPerSecond,
        )
    }
}
```

### Analytics

```go
// Get analytics summary for the last hour
start := time.Now().Add(-1 * time.Hour)
end := time.Now()

summary, err := tapioClient.GetAnalyticsSummary(context.Background(), start, end)
if err != nil {
    log.Printf("Failed to get analytics: %v", err)
} else {
    log.Printf("Total events: %d", summary.EventStatistics.Total)
    log.Printf("Events by type: %v", summary.EventStatistics.ByType)
    log.Printf("Events by severity: %v", summary.EventStatistics.BySeverity)
    
    log.Printf("\nTop issues:")
    for _, issue := range summary.TopIssues {
        log.Printf("- %s (%s): %d occurrences (%s)", 
            issue.Description, 
            issue.Severity, 
            issue.Count,
            issue.Trend,
        )
    }
}
```

## Advanced Configuration

### Using REST Instead of gRPC

```go
config := client.DefaultConfig()
config.PreferREST = true  // Use REST API instead of gRPC
config.RESTAddress = "https://api.tapio.io"
```

### Custom HTTP Client

```go
config.Timeout = 60 * time.Second
config.MaxRetries = 5
config.RetryDelay = 2 * time.Second
```

### Error Handling

```go
resp, err := tapioClient.SubmitEvent(ctx, event)
if err != nil {
    // Check for specific error types
    if strings.Contains(err.Error(), "rate limit") {
        // Handle rate limiting
        time.Sleep(time.Minute)
    } else if strings.Contains(err.Error(), "unauthorized") {
        // Refresh authentication
    } else {
        // General error handling
        log.Printf("Error: %v", err)
    }
}
```

## Complete Example

See [full_example.go](full_example.go) for a complete working example that demonstrates:
- Event submission and streaming
- Correlation analysis
- System monitoring
- Error handling
- Graceful shutdown