# Tapio REST API Documentation

## Overview

The Tapio REST API provides HTTP/JSON endpoints for all observability platform features. The API is built on top of the gRPC services using grpc-gateway for automatic translation.

## Base URL

```
https://api.tapio.io/api/v1
```

## Authentication

All API requests require authentication using one of the following methods:

### API Key
Include your API key in the `X-API-Key` header:
```
X-API-Key: your-api-key-here
```

### Bearer Token
Include a JWT token in the `Authorization` header:
```
Authorization: Bearer your-jwt-token-here
```

## Rate Limiting

- **Default**: 10,000 requests per minute per API key
- **Event Streaming**: 165,000 events per second
- **Bulk Operations**: Subject to additional limits

Rate limit information is returned in response headers:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Unix timestamp when limit resets

## Common Headers

### Request Headers
- `Content-Type`: `application/json` (required for POST/PUT)
- `X-Request-ID`: Optional request tracking ID
- `X-API-Key` or `Authorization`: Required authentication

### Response Headers
- `X-Request-ID`: Request tracking ID (echoed from request)
- `X-Trace-ID`: Distributed trace ID
- `X-Correlation-ID`: Correlation tracking ID

## Error Responses

All errors follow a consistent format:

```json
{
  "error": "Bad Request",
  "message": "Detailed error message",
  "code": "400",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Common Error Codes
- `400`: Bad Request - Invalid input
- `401`: Unauthorized - Missing or invalid authentication
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource doesn't exist
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error
- `503`: Service Unavailable

---

## Event Management

### Submit Event

Submit a single event to the platform.

**Endpoint:** `POST /api/v1/events`

**Request Body:**
```json
{
  "id": "evt_001",
  "type": "network",
  "severity": "info",
  "timestamp": "2024-01-01T00:00:00Z",
  "message": "Network connection established",
  "service": "api-gateway",
  "component": "ingress",
  "data": {
    "source_ip": "10.0.0.1",
    "destination_ip": "10.0.0.2",
    "protocol": "tcp"
  },
  "metadata": {
    "region": "us-east-1",
    "environment": "production"
  }
}
```

**Response:**
```json
{
  "event_id": "evt_001",
  "status": "accepted",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Bulk Event Ingestion

Submit multiple events in a single request.

**Endpoint:** `POST /api/v1/events/bulk`

**Formats Supported:**
- JSON array (default)
- NDJSON with `Content-Type: application/x-ndjson`

**Request Body (JSON):**
```json
[
  {
    "id": "evt_001",
    "type": "network",
    "severity": "info",
    "timestamp": "2024-01-01T00:00:00Z",
    "message": "Event 1"
  },
  {
    "id": "evt_002",
    "type": "kubernetes",
    "severity": "warning",
    "timestamp": "2024-01-01T00:00:01Z",
    "message": "Event 2"
  }
]
```

**Response:**
```json
{
  "total": 2,
  "success": 2,
  "failed": 0,
  "results": [
    {
      "event_id": "evt_001",
      "status": "accepted",
      "timestamp": "2024-01-01T00:00:00Z"
    },
    {
      "event_id": "evt_002",
      "status": "accepted",
      "timestamp": "2024-01-01T00:00:01Z"
    }
  ],
  "timestamp": "2024-01-01T00:00:02Z"
}
```

### Query Events

Query events with filters and search criteria.

**Endpoint:** `GET /api/v1/events`

**Query Parameters:**
- `filter.time_range.start`: Start time (RFC3339)
- `filter.time_range.end`: End time (RFC3339)
- `filter.event_types`: Comma-separated event types
- `filter.severities`: Comma-separated severities
- `filter.limit`: Maximum results (default: 100, max: 10000)
- `include_correlations`: Include correlation data (boolean)
- `include_statistics`: Include statistics (boolean)

**Response:**
```json
{
  "events": [
    {
      "id": "evt_001",
      "type": "NETWORK",
      "severity": "INFO",
      "timestamp": "2024-01-01T00:00:00Z",
      "message": "Network connection established",
      "context": {
        "service": "api-gateway",
        "namespace": "production"
      }
    }
  ],
  "total_count": 1523,
  "statistics": {
    "time_range": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-01T01:00:00Z"
    },
    "total_events": 1523,
    "events_by_type": {
      "NETWORK": 456,
      "KUBERNETES": 789
    }
  },
  "query_time": "2024-01-01T00:00:02Z"
}
```

### Export Events

Export events in various formats.

**Endpoint:** `GET /api/v1/events/export`

**Query Parameters:**
- `format`: Export format (`json`, `csv`, `ndjson`)
- `start_time`: Start time (RFC3339)
- `end_time`: End time (RFC3339)
- `limit`: Maximum events to export

**Response:** File download in requested format

### Event Search

Advanced event search with full-text and faceted search.

**Endpoint:** `POST /api/v1/events/search`

**Request Body:**
```json
{
  "query": "type:network AND severity:error",
  "time_range": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-01T01:00:00Z"
  },
  "filters": {
    "service": ["api-gateway", "payment-service"],
    "environment": ["production"]
  },
  "limit": 100,
  "offset": 0,
  "sort_by": "timestamp",
  "sort_order": "desc"
}
```

**Response:**
```json
{
  "query": "type:network AND severity:error",
  "total_hits": 1523,
  "returned_hits": 100,
  "events": [
    {
      "id": "evt_001",
      "type": "network",
      "severity": "error",
      "timestamp": "2024-01-01T00:00:00Z",
      "message": "Connection timeout",
      "score": 0.95,
      "highlight": {
        "message": ["Connection <em>timeout</em>"]
      }
    }
  ],
  "facets": {
    "type": [
      {"value": "network", "count": 456},
      {"value": "kubernetes", "count": 234}
    ],
    "severity": [
      {"value": "error", "count": 123},
      {"value": "warning", "count": 456}
    ]
  },
  "timestamp": "2024-01-01T00:00:02Z"
}
```

### Stream Events (SSE)

Stream real-time events using Server-Sent Events.

**Endpoint:** `GET /api/v1/events/stream`

**Headers Required:**
```
Accept: text/event-stream
```

**Query Parameters:**
- `filter`: JSON-encoded filter criteria
- `lookback`: Duration to include historical events (e.g., "5m")

**Response Stream:**
```
event: connected
data: {"status":"connected","timestamp":"2024-01-01T00:00:00Z"}

event: event
data: {"id":"evt_001","type":"network","severity":"info","timestamp":"2024-01-01T00:00:01Z","message":"New connection"}

event: event
data: {"id":"evt_002","type":"kubernetes","severity":"warning","timestamp":"2024-01-01T00:00:02Z","message":"Pod restarted"}
```

---

## Correlation Analysis

### Analyze Events

Perform correlation analysis on a set of events.

**Endpoint:** `POST /api/v1/correlations/analyze`

**Request Body:**
```json
{
  "events": [
    {
      "id": "evt_001",
      "type": "NETWORK",
      "timestamp": "2024-01-01T00:00:00Z"
    }
  ],
  "analysis_type": "SEMANTIC",
  "options": {
    "include_root_cause": true,
    "include_predictions": true,
    "confidence_threshold": 0.7
  }
}
```

**Response:**
```json
{
  "analysis_id": "analysis_123",
  "findings": [
    {
      "id": "corr_001",
      "pattern_type": "cascading_failure",
      "confidence": 0.87,
      "timestamp": "2024-01-01T00:00:02Z",
      "description": "Detected cascading failure pattern",
      "related_event_ids": ["evt_001", "evt_002", "evt_003"]
    }
  ],
  "status": "COMPLETED",
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-01-01T00:00:02Z",
  "event_count": 3
}
```

### Get Correlations

Retrieve existing correlations.

**Endpoint:** `GET /api/v1/correlations`

**Query Parameters:**
- `time_range.start`: Start time
- `time_range.end`: End time
- `pattern_type`: Filter by pattern type
- `min_confidence`: Minimum confidence score (0-1)
- `entity_type`: Filter by entity type
- `limit`: Maximum results

**Response:**
```json
{
  "correlations": [
    {
      "id": "corr_001",
      "pattern_type": "service_degradation",
      "confidence": 0.92,
      "timestamp": "2024-01-01T00:00:00Z",
      "description": "Service degradation detected",
      "metadata": {
        "analysis_type": "semantic",
        "engine": "tapio_correlation"
      }
    }
  ],
  "total_count": 45,
  "query_time": "2024-01-01T00:00:01Z"
}
```

### Real-time Correlations (SSE)

Stream real-time correlation updates.

**Endpoint:** `GET /api/v1/correlations/realtime`

**Headers Required:**
```
Accept: text/event-stream
```

**Response Stream:**
```
event: correlation
data: {"id":"corr_001","pattern":"service_degradation","confidence":0.87,"event_count":15,"description":"Detected service degradation pattern","timestamp":"2024-01-01T00:00:00Z"}
```

### Pattern Discovery

Discover patterns in historical data.

**Endpoint:** `POST /api/v1/correlations/patterns`

**Request Body:**
```json
{
  "time_range": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-01T01:00:00Z"
  },
  "min_confidence": 0.7,
  "pattern_types": ["cascading_failure", "resource_exhaustion"],
  "max_patterns": 10
}
```

**Response:**
```json
{
  "time_range": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-01T01:00:00Z"
  },
  "patterns": [
    {
      "id": "pattern_001",
      "name": "Cascading Failure",
      "description": "Service failures cascading through dependencies",
      "confidence": 0.92,
      "frequency": 5,
      "examples": ["evt_001", "evt_002", "evt_003"]
    }
  ],
  "timestamp": "2024-01-01T00:00:02Z"
}
```

### Impact Analysis

Analyze the impact of specific events.

**Endpoint:** `POST /api/v1/correlations/impact`

**Request Body:**
```json
{
  "event_id": "evt_001",
  "include_services": true,
  "include_metrics": true,
  "time_horizon": "2h"
}
```

**Response:**
```json
{
  "event_id": "evt_001",
  "impact": {
    "business_impact": 0.75,
    "customer_impact": 0.60,
    "operational_impact": 0.80,
    "financial_impact": 0.45
  },
  "affected_services": ["api-gateway", "payment-service", "notification-service"],
  "affected_customers": 1250,
  "estimated_duration": "2h30m",
  "recommendations": [
    "Scale api-gateway to handle increased load",
    "Enable circuit breaker on payment-service",
    "Notify customers about potential delays"
  ],
  "timestamp": "2024-01-01T00:00:02Z"
}
```

---

## Collector Management

### List Collectors

Get information about all active collectors.

**Endpoint:** `GET /api/v1/collectors`

**Response:**
```json
{
  "collectors": [
    {
      "name": "systemd",
      "type": "SYSTEMD",
      "status": "RUNNING",
      "last_seen": "2024-01-01T00:00:00Z",
      "events_processed": 1000
    }
  ],
  "total_count": 4,
  "response_time": "2024-01-01T00:00:01Z"
}
```

### Collector Status

Get detailed status of all collectors.

**Endpoint:** `GET /api/v1/collectors/status`

**Response:**
```json
{
  "collectors": [
    {
      "name": "systemd",
      "type": "systemd",
      "status": "running",
      "events_per_second": 125.5,
      "last_event_time": "2024-01-01T00:00:00Z",
      "uptime_seconds": 3600,
      "health": {
        "cpu_percent": 25.5,
        "memory_mb": 128.0,
        "error_count": 0
      }
    }
  ],
  "total_events": 1500000,
  "events_per_second": 210.7,
  "timestamp": "2024-01-01T00:00:01Z"
}
```

### Collector Configuration

Get or update collector configuration.

**Get Configuration:**
```
GET /api/v1/collectors/config?name=systemd
```

**Update Configuration:**
```
PUT /api/v1/collectors/config?name=systemd

{
  "buffer_size": 20000,
  "worker_count": 8,
  "flush_interval": "10s"
}
```

---

## Analytics

### Analytics Summary

Get analytics summary for a time period.

**Endpoint:** `GET /api/v1/analytics/summary`

**Query Parameters:**
- `start_time`: Start of period
- `end_time`: End of period

**Response:**
```json
{
  "time_range": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-02T00:00:00Z"
  },
  "event_statistics": {
    "total": 145892,
    "by_type": {
      "network": 45000,
      "kubernetes": 35000
    },
    "by_severity": {
      "info": 100000,
      "warning": 35000,
      "error": 10000
    },
    "events_per_hour": [5000, 5500, 6000]
  },
  "correlation_statistics": {
    "total": 1523,
    "by_pattern": {
      "cascading_failure": 234,
      "resource_exhaustion": 189
    },
    "average_confidence": 0.82
  },
  "top_issues": [
    {
      "description": "High memory usage in payment service",
      "severity": "warning",
      "count": 45,
      "trend": "increasing"
    }
  ],
  "timestamp": "2024-01-01T00:00:01Z"
}
```

### Trend Analysis

Analyze trends for specific metrics.

**Endpoint:** `GET /api/v1/analytics/trends`

**Query Parameters:**
- `metric`: Metric to analyze (e.g., "events", "errors")
- `period`: Time period (e.g., "1h", "1d", "1w")

**Response:**
```json
{
  "metric": "events",
  "period": "1h",
  "trends": [
    {
      "timestamp": "2024-01-01T00:00:00Z",
      "value": 100.0,
      "trend": "stable"
    }
  ],
  "prediction": {
    "next_value": 115.0,
    "confidence": 0.75,
    "trend": "stable"
  },
  "anomalies": [
    {
      "timestamp": "2024-01-01T00:45:00Z",
      "value": 180.0,
      "description": "Spike in event rate",
      "severity": "warning"
    }
  ],
  "timestamp": "2024-01-01T00:00:01Z"
}
```

---

## System

### System Information

Get system information and capabilities.

**Endpoint:** `GET /api/v1/system/info`

**Response:**
```json
{
  "version": "1.0.0",
  "build_time": "2024-01-01T00:00:00Z",
  "git_commit": "abc123def",
  "go_version": "1.21",
  "platform": "linux/amd64",
  "start_time": "2024-01-01T00:00:00Z",
  "uptime_seconds": 3600,
  "environment": "production",
  "features": {
    "semantic_correlation": true,
    "distributed_tracing": true,
    "real_time_streaming": true,
    "ai_analysis": false
  },
  "limits": {
    "max_events_per_second": 165000,
    "max_correlations_active": 10000,
    "max_subscriptions": 1000,
    "max_request_size_bytes": 10485760
  },
  "timestamp": "2024-01-01T00:00:01Z"
}
```

### System Status

Get overall system status.

**Endpoint:** `GET /api/v1/status`

**Response:**
```json
{
  "status": "HEALTHY",
  "timestamp": "2024-01-01T00:00:00Z",
  "uptime": 3600,
  "version": "1.0.0",
  "components": {
    "collector_manager": {
      "active_collectors": 4,
      "total_events": 1500000
    },
    "dataflow_engine": {
      "events_per_second": 165.5,
      "active_groups": 25
    }
  },
  "request_count": 10000
}
```

---

## Health Checks

### Basic Health

Simple health check endpoint.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Readiness Check

Check if service is ready to accept requests.

**Endpoint:** `GET /health/ready`

**Response:**
```json
{
  "status": "ready",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Liveness Check

Check if service is alive.

**Endpoint:** `GET /health/live`

**Response:**
```json
{
  "status": "alive",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Detailed Health

Get detailed health information.

**Endpoint:** `GET /api/v1/system/health/detailed`

**Response:**
```json
{
  "status": "healthy",
  "components": {
    "grpc_server": {
      "status": "healthy",
      "message": "Accepting connections",
      "details": {
        "connections": 125,
        "rps": 1523
      }
    },
    "rest_gateway": {
      "status": "healthy",
      "message": "Processing requests",
      "details": {
        "latency_p99": "15ms"
      }
    }
  },
  "checks": [
    {
      "name": "database_connectivity",
      "status": "pass",
      "duration": "2ms"
    }
  ],
  "timestamp": "2024-01-01T00:00:01Z"
}
```

---

## Observability

### Get Metrics

Get system metrics in Prometheus format.

**Endpoint:** `GET /metrics`

**Response:**
```
# HELP tapio_rest_requests_total Total number of REST API requests
# TYPE tapio_rest_requests_total counter
tapio_rest_requests_total 1000

# HELP tapio_events_processed_total Total events processed
# TYPE tapio_events_processed_total counter
tapio_events_processed_total{collector="systemd"} 500000
```

---

## WebSocket Support

For bidirectional real-time communication, WebSocket endpoints are available at:

```
wss://api.tapio.io/ws/v1/events
wss://api.tapio.io/ws/v1/correlations
```

WebSocket protocols follow the same authentication and message formats as REST endpoints.