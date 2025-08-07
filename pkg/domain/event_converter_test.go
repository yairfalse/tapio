package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventConverter_ToUnifiedEvent(t *testing.T) {
	converter := NewEventConverter()

	t.Run("nil event", func(t *testing.T) {
		result := converter.ToUnifiedEvent(nil)
		assert.Nil(t, result)
	})

	t.Run("basic event conversion", func(t *testing.T) {
		event := &Event{
			ID:         "test-123",
			Timestamp:  time.Now(),
			Type:       EventTypeSystem,
			Source:     "kernel",
			Message:    "Test message",
			Severity:   EventSeverityWarning,
			Category:   "system",
			Confidence: 0.85,
			Tags:       []string{"test", "kernel"},
			Data:       make(map[string]interface{}),
			Context: EventContext{
				TraceID:   "trace-123",
				SpanID:    "span-456",
				Namespace: "default",
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		assert.Equal(t, "test-123", unified.ID)
		assert.Equal(t, EventTypeSystem, unified.Type)
		assert.Equal(t, "kernel", unified.Source)
		assert.NotNil(t, unified.TraceContext)
		assert.Equal(t, "trace-123", unified.TraceContext.TraceID)
		assert.Equal(t, "span-456", unified.TraceContext.SpanID)
		assert.NotNil(t, unified.Semantic)
		assert.Equal(t, "system", unified.Semantic.Category)
		assert.Equal(t, 0.85, unified.Semantic.Confidence)
		assert.Equal(t, []string{"test", "kernel"}, unified.Semantic.Tags)
	})

	t.Run("with semantic data", func(t *testing.T) {
		event := &Event{
			ID:        "test-456",
			Timestamp: time.Now(),
			Type:      EventTypeLog,
			Source:    "app",
			Semantic: map[string]interface{}{
				"intent": "user-action",
			},
			Category:   "application",
			Confidence: 0.95,
			Tags:       []string{"app"},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Semantic)
		assert.Equal(t, "user-action", unified.Semantic.Intent)
		assert.Equal(t, "application", unified.Semantic.Category)
		assert.Equal(t, 0.95, unified.Semantic.Confidence)
	})

	t.Run("with entity data", func(t *testing.T) {
		event := &Event{
			ID:        "test-789",
			Timestamp: time.Now(),
			Type:      EventTypeKubernetes,
			Source:    "kubeapi",
			Data: map[string]interface{}{
				"entity_type": "pod",
				"entity_name": "test-pod",
				"entity_uid":  "uid-123",
				"labels": map[string]string{
					"app": "test",
				},
			},
			Context: EventContext{
				Namespace: "production",
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Entity)
		assert.Equal(t, "pod", unified.Entity.Type)
		assert.Equal(t, "test-pod", unified.Entity.Name)
		assert.Equal(t, "uid-123", unified.Entity.UID)
		assert.Equal(t, "production", unified.Entity.Namespace)
	})

	t.Run("with kernel data", func(t *testing.T) {
		event := &Event{
			ID:        "kernel-001",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "ebpf",
			Data: map[string]interface{}{
				"syscall":     "open",
				"pid":         1234,
				"tid":         5678,
				"comm":        "nginx",
				"uid":         1000,
				"gid":         1000,
				"return_code": -1,
				"stack_trace": []string{"func1", "func2"},
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Kernel)
		assert.Equal(t, "open", unified.Kernel.Syscall)
		assert.Equal(t, uint32(1234), unified.Kernel.PID)
		assert.Equal(t, uint32(5678), unified.Kernel.TID)
		assert.Equal(t, "nginx", unified.Kernel.Comm)
		assert.Equal(t, uint32(1000), unified.Kernel.UID)
		assert.Equal(t, uint32(1000), unified.Kernel.GID)
		assert.Equal(t, int32(-1), unified.Kernel.ReturnCode)
		assert.Equal(t, []string{"func1", "func2"}, unified.Kernel.StackTrace)
	})

	t.Run("with network data", func(t *testing.T) {
		event := &Event{
			ID:        "net-001",
			Timestamp: time.Now(),
			Type:      EventTypeNetwork,
			Source:    "network",
			Data: map[string]interface{}{
				"protocol":    "TCP",
				"source_ip":   "10.0.0.1",
				"source_port": 8080,
				"dest_ip":     "10.0.0.2",
				"dest_port":   3000,
				"direction":   "ingress",
				"bytes_sent":  int64(1024),
				"bytes_recv":  int64(2048),
				"latency":     int64(15000000),
				"status_code": 200,
				"method":      "GET",
				"path":        "/api/health",
				"headers": map[string]string{
					"Content-Type": "application/json",
				},
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Network)
		assert.Equal(t, "TCP", unified.Network.Protocol)
		assert.Equal(t, "10.0.0.1", unified.Network.SourceIP)
		assert.Equal(t, uint16(8080), unified.Network.SourcePort)
		assert.Equal(t, "10.0.0.2", unified.Network.DestIP)
		assert.Equal(t, uint16(3000), unified.Network.DestPort)
		assert.Equal(t, "ingress", unified.Network.Direction)
		assert.Equal(t, uint64(1024), unified.Network.BytesSent)
		assert.Equal(t, uint64(2048), unified.Network.BytesRecv)
		assert.Equal(t, int64(15000000), unified.Network.Latency)
		assert.Equal(t, 200, unified.Network.StatusCode)
		assert.Equal(t, "GET", unified.Network.Method)
		assert.Equal(t, "/api/health", unified.Network.Path)
		assert.Equal(t, "application/json", unified.Network.Headers["Content-Type"])
	})

	t.Run("with application data", func(t *testing.T) {
		event := &Event{
			ID:        "app-001",
			Timestamp: time.Now(),
			Type:      EventTypeLog,
			Source:    "app",
			Message:   "Application error occurred",
			Data: map[string]interface{}{
				"level":        "error",
				"logger":       "app.service",
				"stack_trace":  "at line 42",
				"error_type":   "NullPointerException",
				"user_id":      "user-123",
				"session_id":   "session-456",
				"request_id":   "req-789",
				"custom_field": "custom_value",
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Application)
		assert.Equal(t, "error", unified.Application.Level)
		assert.Equal(t, "app.service", unified.Application.Logger)
		assert.Equal(t, "Application error occurred", unified.Application.Message)
		assert.Equal(t, "at line 42", unified.Application.StackTrace)
		assert.Equal(t, "NullPointerException", unified.Application.ErrorType)
		assert.Equal(t, "user-123", unified.Application.UserID)
		assert.Equal(t, "session-456", unified.Application.SessionID)
		assert.Equal(t, "req-789", unified.Application.RequestID)
		assert.NotNil(t, unified.Application.Custom)
	})

	t.Run("with kubernetes data", func(t *testing.T) {
		event := &Event{
			ID:        "k8s-001",
			Timestamp: time.Now(),
			Type:      EventTypeKubernetes,
			Source:    "kubeapi",
			Message:   "Pod failed to start",
			Data: map[string]interface{}{
				"kind":             "Pod",
				"name":             "test-pod",
				"api_version":      "v1",
				"event_type":       "Warning",
				"reason":           "FailedScheduling",
				"resource_version": "12345",
				"labels": map[string]string{
					"app": "test",
				},
				"annotations": map[string]string{
					"kubectl.kubernetes.io/last-applied-configuration": "{}",
				},
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Kubernetes)
		assert.Equal(t, "Pod", unified.Kubernetes.ObjectKind)
		assert.Equal(t, "test-pod", unified.Kubernetes.Object)
		assert.Equal(t, "v1", unified.Kubernetes.APIVersion)
		assert.Equal(t, "Warning", unified.Kubernetes.EventType)
		assert.Equal(t, "FailedScheduling", unified.Kubernetes.Reason)
		assert.Equal(t, "Pod failed to start", unified.Kubernetes.Message)
		assert.Equal(t, "12345", unified.Kubernetes.ResourceVersion)
	})

	t.Run("with impact data", func(t *testing.T) {
		event := &Event{
			ID:        "impact-001",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "monitor",
			Severity:  EventSeverityCritical,
			Data: map[string]interface{}{
				"infrastructure_impact": 0.9,
				"system_critical":       true,
				"cascade_risk":          true,
				"slo_impact":            true,
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Impact)
		assert.Equal(t, "critical", unified.Impact.Severity)
		assert.Equal(t, 0.9, unified.Impact.InfrastructureImpact)
		assert.True(t, unified.Impact.SystemCritical)
		assert.True(t, unified.Impact.CascadeRisk)
		assert.True(t, unified.Impact.SLOImpact)
	})

	t.Run("with causality context", func(t *testing.T) {
		event := &Event{
			ID:        "causal-001",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "correlator",
			Causality: &CausalityContext{
				CausalChain: []string{"event1", "event2", "event3"},
			},
		}

		unified := converter.ToUnifiedEvent(event)
		require.NotNil(t, unified)
		require.NotNil(t, unified.Correlation)
		assert.Equal(t, []string{"event1", "event2", "event3"}, unified.Correlation.CausalChain)
	})
}

func TestEventConverter_FromUnifiedEvent(t *testing.T) {
	converter := NewEventConverter()

	t.Run("nil event", func(t *testing.T) {
		result := converter.FromUnifiedEvent(nil)
		assert.Nil(t, result)
	})

	t.Run("basic conversion", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "test-123",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "kernel",
			Message:   "Test message",
			Impact: &ImpactContext{
				Severity: "warning",
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, EventID("test-123"), event.ID)
		assert.Equal(t, EventType(EventTypeSystem), event.Type)
		assert.Equal(t, SourceType("kernel"), event.Source)
		assert.Equal(t, EventSeverity("warning"), event.Severity)
	})

	t.Run("with semantic context", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "test-456",
			Timestamp: time.Now(),
			Type:      EventTypeLog,
			Source:    "app",
			Semantic: &SemanticContext{
				Intent:     "user-action",
				Category:   "application",
				Confidence: 0.95,
				Tags:       []string{"app", "user"},
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, "application", event.Category)
		assert.Equal(t, 0.95, event.Confidence)
		assert.Equal(t, []string{"app", "user"}, event.Tags)
		assert.NotNil(t, event.Semantic)
		assert.Equal(t, "user-action", event.Semantic["intent"])
	})

	t.Run("with trace context", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "test-789",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "app",
			TraceContext: &TraceContext{
				TraceID: "trace-123",
				SpanID:  "span-456",
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, "trace-123", event.Context.TraceID)
		assert.Equal(t, "span-456", event.Context.SpanID)
	})

	t.Run("with entity context", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "entity-001",
			Timestamp: time.Now(),
			Type:      EventTypeKubernetes,
			Source:    "kubeapi",
			Entity: &EntityContext{
				Type:      "pod",
				Name:      "test-pod",
				UID:       "uid-123",
				Namespace: "production",
				Labels: map[string]string{
					"app": "test",
				},
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, "production", event.Context.Namespace)
		assert.Equal(t, "pod", event.Data["entity_type"])
		assert.Equal(t, "test-pod", event.Data["entity_name"])
		assert.Equal(t, "uid-123", event.Data["entity_uid"])
		labels := event.Data["labels"].(map[string]string)
		assert.Equal(t, "test", labels["app"])
	})

	t.Run("with kernel data", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "kernel-001",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "ebpf",
			Kernel: &KernelData{
				Syscall:    "open",
				PID:        1234,
				TID:        5678,
				Comm:       "nginx",
				UID:        1000,
				GID:        1000,
				ReturnCode: -1,
				StackTrace: []string{"func1", "func2"},
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, "open", event.Data["syscall"])
		assert.Equal(t, uint32(1234), event.Data["pid"])
		assert.Equal(t, uint32(5678), event.Data["tid"])
		assert.Equal(t, "nginx", event.Data["comm"])
		assert.Equal(t, uint32(1000), event.Data["uid"])
		assert.Equal(t, uint32(1000), event.Data["gid"])
		assert.Equal(t, int32(-1), event.Data["return_code"])
		assert.Equal(t, []string{"func1", "func2"}, event.Data["stack_trace"])
	})

	t.Run("with network data", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "net-001",
			Timestamp: time.Now(),
			Type:      EventTypeNetwork,
			Source:    "network",
			Network: &NetworkData{
				Protocol:   "TCP",
				SourceIP:   "10.0.0.1",
				SourcePort: 8080,
				DestIP:     "10.0.0.2",
				DestPort:   3000,
				Direction:  "ingress",
				BytesSent:  1024,
				BytesRecv:  2048,
				Latency:    15000000,
				StatusCode: 200,
				Method:     "GET",
				Path:       "/api/health",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, "TCP", event.Data["protocol"])
		assert.Equal(t, "10.0.0.1", event.Data["source_ip"])
		assert.Equal(t, uint16(8080), event.Data["source_port"])
		assert.Equal(t, "10.0.0.2", event.Data["dest_ip"])
		assert.Equal(t, uint16(3000), event.Data["dest_port"])
		assert.Equal(t, "ingress", event.Data["direction"])
		assert.Equal(t, uint64(1024), event.Data["bytes_sent"])
		assert.Equal(t, uint64(2048), event.Data["bytes_recv"])
		assert.Equal(t, int64(15000000), event.Data["latency"])
		assert.Equal(t, 200, event.Data["status_code"])
		assert.Equal(t, "GET", event.Data["method"])
		assert.Equal(t, "/api/health", event.Data["path"])
		headers := event.Data["headers"].(map[string]string)
		assert.Equal(t, "application/json", headers["Content-Type"])
	})

	t.Run("with application data", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "app-001",
			Timestamp: time.Now(),
			Type:      EventTypeLog,
			Source:    "app",
			Application: &ApplicationData{
				Level:      "error",
				Message:    "Application error",
				Logger:     "app.service",
				StackTrace: "at line 42",
				ErrorType:  "NullPointerException",
				UserID:     "user-123",
				SessionID:  "session-456",
				RequestID:  "req-789",
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, "Application error", event.Message)
		assert.Equal(t, "error", event.Data["level"])
		assert.Equal(t, "app.service", event.Data["logger"])
		assert.Equal(t, "at line 42", event.Data["stack_trace"])
		assert.Equal(t, "NullPointerException", event.Data["error_type"])
		assert.Equal(t, "user-123", event.Data["user_id"])
		assert.Equal(t, "session-456", event.Data["session_id"])
		assert.Equal(t, "req-789", event.Data["request_id"])
	})

	t.Run("with kubernetes data", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "k8s-001",
			Timestamp: time.Now(),
			Type:      EventTypeKubernetes,
			Source:    "kubeapi",
			Kubernetes: &KubernetesData{
				ObjectKind: "Pod",
				Object:     "Pod/test-pod",
				APIVersion: "v1",
				EventType:  "Warning",
				Reason:     "FailedScheduling",
				Message:    "Pod failed",
				Labels: map[string]string{
					"app": "test",
				},
				Annotations: map[string]string{
					"kubectl.kubernetes.io/last-applied-configuration": "{}",
				},
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, "Pod failed", event.Message)
		assert.Equal(t, "Pod", event.Data["kind"])
		assert.Equal(t, "Pod/test-pod", event.Data["name"])
		assert.Equal(t, "v1", event.Data["api_version"])
		assert.Equal(t, "Warning", event.Data["event_type"])
		assert.Equal(t, "FailedScheduling", event.Data["reason"])
		labels := event.Data["labels"].(map[string]string)
		assert.Equal(t, "test", labels["app"])
		annotations := event.Data["annotations"].(map[string]string)
		assert.Equal(t, "{}", annotations["kubectl.kubernetes.io/last-applied-configuration"])
	})

	t.Run("with impact data", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "impact-001",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "monitor",
			Impact: &ImpactContext{
				Severity:             "critical",
				InfrastructureImpact: 0.9,
				SystemCritical:       true,
				CascadeRisk:          true,
				SLOImpact:            true,
				AffectedServices:     []string{"svc1", "svc2"},
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		assert.Equal(t, EventSeverity("critical"), event.Severity)
		assert.Equal(t, 0.9, event.Data["infrastructure_impact"])
		assert.Equal(t, true, event.Data["system_critical"])
		assert.Equal(t, true, event.Data["cascade_risk"])
		assert.Equal(t, true, event.Data["slo_impact"])
		assert.Equal(t, []string{"svc1", "svc2"}, event.Data["affected_services"])
	})

	t.Run("with correlation context", func(t *testing.T) {
		unified := &UnifiedEvent{
			ID:        "corr-001",
			Timestamp: time.Now(),
			Type:      EventTypeSystem,
			Source:    "correlator",
			Correlation: &CorrelationContext{
				CausalChain: []string{"event1", "event2", "event3"},
			},
		}

		event := converter.FromUnifiedEvent(unified)
		require.NotNil(t, event)
		require.NotNil(t, event.Causality)
		assert.Equal(t, []string{"event1", "event2", "event3"}, event.Causality.CausalChain)
	})
}

func TestEventConverter_BatchConversions(t *testing.T) {
	converter := NewEventConverter()

	t.Run("BatchToUnified", func(t *testing.T) {
		events := []Event{
			{
				ID:        "event-1",
				Timestamp: time.Now(),
				Type:      EventTypeSystem,
				Source:    "kernel",
			},
			{
				ID:        "event-2",
				Timestamp: time.Now(),
				Type:      EventTypeNetwork,
				Source:    "network",
			},
			{
				ID:        "event-3",
				Timestamp: time.Now(),
				Type:      EventTypeKubernetes,
				Source:    "kubeapi",
			},
		}

		unified := converter.BatchToUnified(events)
		require.Len(t, unified, 3)
		assert.Equal(t, "event-1", unified[0].ID)
		assert.Equal(t, "event-2", unified[1].ID)
		assert.Equal(t, "event-3", unified[2].ID)
		assert.Equal(t, EventTypeSystem, unified[0].Type)
		assert.Equal(t, EventTypeNetwork, unified[1].Type)
		assert.Equal(t, EventTypeKubernetes, unified[2].Type)
	})

	t.Run("BatchFromUnified", func(t *testing.T) {
		unified := []*UnifiedEvent{
			{
				ID:        "event-1",
				Timestamp: time.Now(),
				Type:      EventTypeSystem,
				Source:    "kernel",
			},
			{
				ID:        "event-2",
				Timestamp: time.Now(),
				Type:      EventTypeNetwork,
				Source:    "network",
			},
			{
				ID:        "event-3",
				Timestamp: time.Now(),
				Type:      EventTypeKubernetes,
				Source:    "kubeapi",
			},
		}

		events := converter.BatchFromUnified(unified)
		require.Len(t, events, 3)
		assert.Equal(t, EventID("event-1"), events[0].ID)
		assert.Equal(t, EventID("event-2"), events[1].ID)
		assert.Equal(t, EventID("event-3"), events[2].ID)
		assert.Equal(t, EventType(EventTypeSystem), events[0].Type)
		assert.Equal(t, EventType(EventTypeNetwork), events[1].Type)
		assert.Equal(t, EventType(EventTypeKubernetes), events[2].Type)
	})
}

func TestEventConverter_HelperFunctions(t *testing.T) {
	t.Run("convertToStringMap", func(t *testing.T) {
		// Test with map[string]string
		input1 := map[string]string{"key": "value"}
		result1 := convertToStringMap(input1)
		assert.Equal(t, map[string]string{"key": "value"}, result1)

		// Test with map[string]interface{}
		input2 := map[string]interface{}{"key": "value", "num": 123}
		result2 := convertToStringMap(input2)
		assert.Equal(t, "value", result2["key"])
		assert.Equal(t, "123", result2["num"])

		// Test with map[interface{}]interface{}
		input3 := map[interface{}]interface{}{"key": "value", 123: "number"}
		result3 := convertToStringMap(input3)
		assert.Equal(t, "value", result3["key"])
		assert.Equal(t, "number", result3["123"])

		// Test with nil
		result4 := convertToStringMap(nil)
		assert.Empty(t, result4)
	})
}
