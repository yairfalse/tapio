package transformer

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
)

// UnifiedEventTransformer transforms raw log data into unified events
type UnifiedEventTransformer struct {
	defaultSource string
	defaultNamespace string
}

// NewUnifiedEventTransformer creates a new transformer
func NewUnifiedEventTransformer(source, namespace string) *UnifiedEventTransformer {
	return &UnifiedEventTransformer{
		defaultSource: source,
		defaultNamespace: namespace,
	}
}

// Transform converts raw log data to a UnifiedEvent
func (t *UnifiedEventTransformer) Transform(data []byte, source string) (*domain.UnifiedEvent, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty log data")
	}

	// Use provided source or fall back to default
	if source == "" {
		source = t.defaultSource
	}

	event := &domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Source:    source,
		Severity:  domain.EventSeverityInfo,
		Type:      domain.EventTypeLog,
		Category:  "application",
	}

	// Try to parse as structured log (JSON)
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		// Structured log - extract standard fields
		if timestamp, ok := jsonData["timestamp"].(string); ok {
			if parsedTime, err := time.Parse(time.RFC3339, timestamp); err == nil {
				event.Timestamp = parsedTime
			}
		}

		if level, ok := jsonData["level"].(string); ok {
			event.Severity = parseSeverity(level)
		}

		if message, ok := jsonData["message"].(string); ok {
			event.Message = message
		}

		if msg, ok := jsonData["msg"].(string); ok && event.Message == "" {
			event.Message = msg
		}

		// Set basic fields
		if event.Message == "" {
			event.Message = string(data)
		}

		// Create entity context data if available
		if namespace := extractStringFromJSON(jsonData, "kubernetes_namespace"); namespace != "" {
			event.Entity = &domain.EntityContext{
				Type:      "pod",
				Name:      extractStringFromJSON(jsonData, "kubernetes_pod_name"),
				Namespace: namespace,
				Attributes: map[string]string{
					"node_name": extractStringFromJSON(jsonData, "kubernetes_node_name"),
				},
			}
		}

		// Add to application data
		event.Application = &domain.ApplicationData{
			Level:   string(event.Severity),
			Message: event.Message,
			Custom:  &domain.ApplicationCustomData{},
		}

		// Map specific JSON fields to typed ApplicationCustomData fields
		for k, v := range jsonData {
			switch k {
			case "http_method":
				if s, ok := v.(string); ok {
					event.Application.Custom.HTTPMethod = s
				}
			case "http_status_code":
				if f, ok := v.(float64); ok {
					event.Application.Custom.HTTPStatusCode = int(f)
				}
			case "http_path":
				if s, ok := v.(string); ok {
					event.Application.Custom.HTTPPath = s
				}
			case "business_unit":
				if s, ok := v.(string); ok {
					event.Application.Custom.BusinessUnit = s
				}
			// Add more mappings as needed
			}
		}
	} else {
		// Raw log line
		event.Message = string(data)

		// Try to detect severity from common log patterns
		if strings.Contains(event.Message, "E1225") || strings.Contains(strings.ToLower(event.Message), "error") {
			event.Severity = domain.EventSeverityError
		} else if strings.Contains(strings.ToLower(event.Message), "warn") {
			event.Severity = domain.EventSeverityWarning
		} else {
			event.Severity = domain.EventSeverityInfo
		}

		// Basic application data
		event.Application = &domain.ApplicationData{
			Level:   string(event.Severity),
			Message: event.Message,
		}
	}

	return event, nil
}

// extractStringFromJSON safely extracts a string value from JSON data
func extractStringFromJSON(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// parseSeverity converts string severity levels to domain.EventSeverity
func parseSeverity(level string) domain.EventSeverity {
	switch strings.ToLower(level) {
	case "error", "err", "fatal", "panic":
		return domain.EventSeverityError
	case "warn", "warning":
		return domain.EventSeverityWarning
	case "info", "information":
		return domain.EventSeverityInfo
	case "debug", "dbg":
		return domain.EventSeverityDebug
	case "trace":
		return domain.EventSeverityDebug
	default:
		return domain.EventSeverityInfo
	}
}

// generateEventID creates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt-%d-%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}