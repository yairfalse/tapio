package core

import (
	"encoding/json"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// Metric represents a metric to be exported
type Metric struct {
	Name       string            `json:"name"`
	Value      float64           `json:"value"`
	Labels     map[string]string `json:"labels"`
	Timestamp  time.Time         `json:"timestamp"`
	MetricType MetricType        `json:"type"`
}

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeCounter   MetricType = "counter"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// Trace represents a distributed trace following OpenTelemetry conventions
type Trace struct {
	TraceID    string         `json:"trace_id"`
	SpanID     string         `json:"span_id"`
	ParentID   string         `json:"parent_id,omitempty"`
	Name       string         `json:"name"`
	StartTime  time.Time      `json:"start_time"`
	EndTime    time.Time      `json:"end_time"`
	Attributes SpanAttributes `json:"attributes"`
	Events     []TraceEvent   `json:"events,omitempty"`
	Status     TraceStatus    `json:"status"`
}

// TraceEvent represents an event within a trace span following OpenTelemetry conventions
type TraceEvent struct {
	Name       string          `json:"name"`
	Timestamp  time.Time       `json:"timestamp"`
	Attributes EventAttributes `json:"attributes"`
}

// TraceStatus represents the status of a trace span
type TraceStatus struct {
	Code    StatusCode `json:"code"`
	Message string     `json:"message,omitempty"`
}

// StatusCode represents trace status codes
type StatusCode int

const (
	StatusCodeUnset StatusCode = iota
	StatusCodeOK
	StatusCodeError
)

// Webhook represents a webhook payload with typed body
type Webhook struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    WebhookBody       `json:"body"`
	Timeout time.Duration     `json:"timeout"`
}

// IntegrationError represents an integration-specific error
type IntegrationError struct {
	Integration string
	Operation   string
	Err         error
}

func (e IntegrationError) Error() string {
	return e.Integration + " integration failed during " + e.Operation + ": " + e.Err.Error()
}

// SpanAttributes represents OpenTelemetry span attributes with type safety
type SpanAttributes struct {
	// Service attributes
	ServiceName      string `json:"service.name,omitempty"`
	ServiceVersion   string `json:"service.version,omitempty"`
	ServiceNamespace string `json:"service.namespace,omitempty"`
	ServiceInstance  string `json:"service.instance.id,omitempty"`

	// Resource attributes
	ResourceType string `json:"resource.type,omitempty"`
	ResourceName string `json:"resource.name,omitempty"`
	ResourceUID  string `json:"resource.uid,omitempty"`
	K8sNamespace string `json:"k8s.namespace.name,omitempty"`
	K8sPodName   string `json:"k8s.pod.name,omitempty"`
	K8sNodeName  string `json:"k8s.node.name,omitempty"`
	K8sCluster   string `json:"k8s.cluster.name,omitempty"`

	// Operation attributes
	OperationName string `json:"operation.name,omitempty"`
	OperationType string `json:"operation.type,omitempty"`
	Component     string `json:"component,omitempty"`
	Version       string `json:"version,omitempty"`

	// HTTP attributes
	HTTPMethod     string `json:"http.method,omitempty"`
	HTTPURL        string `json:"http.url,omitempty"`
	HTTPStatusCode int32  `json:"http.status_code,omitempty"`
	HTTPUserAgent  string `json:"http.user_agent,omitempty"`

	// Database attributes
	DBSystem    string `json:"db.system,omitempty"`
	DBName      string `json:"db.name,omitempty"`
	DBStatement string `json:"db.statement,omitempty"`
	DBOperation string `json:"db.operation,omitempty"`

	// Network attributes
	NetworkType      string `json:"network.type,omitempty"`
	NetworkTransport string `json:"network.transport,omitempty"`
	NetworkPeerName  string `json:"network.peer.name,omitempty"`
	NetworkPeerPort  int32  `json:"network.peer.port,omitempty"`

	// Error attributes
	ErrorType    string `json:"error.type,omitempty"`
	ErrorMessage string `json:"error.message,omitempty"`
	ErrorStack   string `json:"error.stack,omitempty"`

	// Custom attributes with validation
	Custom map[string]AttributeValue `json:"custom,omitempty"`
}

// EventAttributes represents OpenTelemetry event attributes with type safety
type EventAttributes struct {
	// Event metadata
	EventName     string `json:"event.name,omitempty"`
	EventDomain   string `json:"event.domain,omitempty"`
	EventType     string `json:"event.type,omitempty"`
	EventCategory string `json:"event.category,omitempty"`
	EventSeverity string `json:"event.severity,omitempty"`

	// Source information
	SourceName      string `json:"source.name,omitempty"`
	SourceType      string `json:"source.type,omitempty"`
	SourceComponent string `json:"source.component,omitempty"`
	SourceVersion   string `json:"source.version,omitempty"`

	// Context attributes
	TraceID       string `json:"trace.id,omitempty"`
	SpanID        string `json:"span.id,omitempty"`
	CorrelationID string `json:"correlation.id,omitempty"`
	RequestID     string `json:"request.id,omitempty"`

	// Message details
	Message     string `json:"message,omitempty"`
	Description string `json:"description,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Details     string `json:"details,omitempty"`

	// Exception information
	ExceptionType       string `json:"exception.type,omitempty"`
	ExceptionMessage    string `json:"exception.message,omitempty"`
	ExceptionStacktrace string `json:"exception.stacktrace,omitempty"`
	ExceptionEscaped    bool   `json:"exception.escaped,omitempty"`

	// Custom attributes with validation
	Custom map[string]AttributeValue `json:"custom,omitempty"`
}

// WebhookBody represents a typed webhook payload
type WebhookBody struct {
	// Structured data - using interface{} only for JSON unmarshaling
	Data interface{} `json:"data,omitempty"`

	// Common webhook fields
	Event     string            `json:"event,omitempty"`
	Action    string            `json:"action,omitempty"`
	Timestamp time.Time         `json:"timestamp,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`

	// Metadata
	Source      string `json:"source,omitempty"`
	Version     string `json:"version,omitempty"`
	ID          string `json:"id,omitempty"`
	Correlation string `json:"correlation_id,omitempty"`

	// Raw payload for complex structures
	Raw json.RawMessage `json:"raw,omitempty"`
}

// AttributeValue represents a type-safe attribute value following OpenTelemetry attribute types
type AttributeValue struct {
	Type  AttributeType `json:"type"`
	Value interface{}   `json:"value"`
}

// AttributeType represents the type of an OpenTelemetry attribute
type AttributeType int

const (
	AttributeTypeString AttributeType = iota
	AttributeTypeInt64
	AttributeTypeFloat64
	AttributeTypeBool
	AttributeTypeStringSlice
	AttributeTypeInt64Slice
	AttributeTypeFloat64Slice
	AttributeTypeBoolSlice
)

// NewStringAttribute creates a string attribute value
func NewStringAttribute(value string) AttributeValue {
	return AttributeValue{
		Type:  AttributeTypeString,
		Value: value,
	}
}

// NewInt64Attribute creates an int64 attribute value
func NewInt64Attribute(value int64) AttributeValue {
	return AttributeValue{
		Type:  AttributeTypeInt64,
		Value: value,
	}
}

// NewFloat64Attribute creates a float64 attribute value
func NewFloat64Attribute(value float64) AttributeValue {
	return AttributeValue{
		Type:  AttributeTypeFloat64,
		Value: value,
	}
}

// NewBoolAttribute creates a bool attribute value
func NewBoolAttribute(value bool) AttributeValue {
	return AttributeValue{
		Type:  AttributeTypeBool,
		Value: value,
	}
}

// ToOTelAttribute converts to OpenTelemetry attribute.KeyValue
func (av AttributeValue) ToOTelAttribute(key string) attribute.KeyValue {
	switch av.Type {
	case AttributeTypeString:
		if s, ok := av.Value.(string); ok {
			return attribute.String(key, s)
		}
	case AttributeTypeInt64:
		if i, ok := av.Value.(int64); ok {
			return attribute.Int64(key, i)
		}
	case AttributeTypeFloat64:
		if f, ok := av.Value.(float64); ok {
			return attribute.Float64(key, f)
		}
	case AttributeTypeBool:
		if b, ok := av.Value.(bool); ok {
			return attribute.Bool(key, b)
		}
	case AttributeTypeStringSlice:
		if s, ok := av.Value.([]string); ok {
			return attribute.StringSlice(key, s)
		}
	case AttributeTypeInt64Slice:
		if s, ok := av.Value.([]int64); ok {
			return attribute.Int64Slice(key, s)
		}
	case AttributeTypeFloat64Slice:
		if s, ok := av.Value.([]float64); ok {
			return attribute.Float64Slice(key, s)
		}
	case AttributeTypeBoolSlice:
		if s, ok := av.Value.([]bool); ok {
			return attribute.BoolSlice(key, s)
		}
	}
	return attribute.String(key, "invalid")
}

// FromOTelAttributes converts OpenTelemetry attributes to SpanAttributes
func (sa *SpanAttributes) FromOTelAttributes(attrs []attribute.KeyValue) {
	for _, attr := range attrs {
		key := string(attr.Key)
		value := attr.Value.AsInterface()

		// Map well-known OpenTelemetry semantic conventions
		switch key {
		case "service.name":
			if s, ok := value.(string); ok {
				sa.ServiceName = s
			}
		case "service.version":
			if s, ok := value.(string); ok {
				sa.ServiceVersion = s
			}
		case "service.namespace":
			if s, ok := value.(string); ok {
				sa.ServiceNamespace = s
			}
		case "k8s.namespace.name":
			if s, ok := value.(string); ok {
				sa.K8sNamespace = s
			}
		case "k8s.pod.name":
			if s, ok := value.(string); ok {
				sa.K8sPodName = s
			}
		case "http.method":
			if s, ok := value.(string); ok {
				sa.HTTPMethod = s
			}
		case "http.status_code":
			if i, ok := value.(int64); ok {
				sa.HTTPStatusCode = int32(i)
			}
		// Add other well-known attributes as needed
		default:
			// Store custom attributes
			if sa.Custom == nil {
				sa.Custom = make(map[string]AttributeValue)
			}
			sa.Custom[key] = AttributeValue{
				Type:  getAttributeTypeFromValue(value),
				Value: value,
			}
		}
	}
}

// ToOTelAttributes converts SpanAttributes to OpenTelemetry attributes
func (sa SpanAttributes) ToOTelAttributes() []attribute.KeyValue {
	var attrs []attribute.KeyValue

	// Add well-known attributes
	if sa.ServiceName != "" {
		attrs = append(attrs, attribute.String("service.name", sa.ServiceName))
	}
	if sa.ServiceVersion != "" {
		attrs = append(attrs, attribute.String("service.version", sa.ServiceVersion))
	}
	if sa.ServiceNamespace != "" {
		attrs = append(attrs, attribute.String("service.namespace", sa.ServiceNamespace))
	}
	if sa.K8sNamespace != "" {
		attrs = append(attrs, attribute.String("k8s.namespace.name", sa.K8sNamespace))
	}
	if sa.K8sPodName != "" {
		attrs = append(attrs, attribute.String("k8s.pod.name", sa.K8sPodName))
	}
	if sa.HTTPMethod != "" {
		attrs = append(attrs, attribute.String("http.method", sa.HTTPMethod))
	}
	if sa.HTTPStatusCode != 0 {
		attrs = append(attrs, attribute.Int64("http.status_code", int64(sa.HTTPStatusCode)))
	}

	// Add custom attributes
	for key, value := range sa.Custom {
		attrs = append(attrs, value.ToOTelAttribute(key))
	}

	return attrs
}

func getAttributeTypeFromValue(value interface{}) AttributeType {
	switch value.(type) {
	case string:
		return AttributeTypeString
	case int, int32, int64:
		return AttributeTypeInt64
	case float32, float64:
		return AttributeTypeFloat64
	case bool:
		return AttributeTypeBool
	case []string:
		return AttributeTypeStringSlice
	case []int64:
		return AttributeTypeInt64Slice
	case []float64:
		return AttributeTypeFloat64Slice
	case []bool:
		return AttributeTypeBoolSlice
	default:
		return AttributeTypeString
	}
}
