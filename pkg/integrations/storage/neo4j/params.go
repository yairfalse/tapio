package neo4j

import "time"

// CorrelationParams represents parameters for storing correlation data
type CorrelationParams struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Confidence float64   `json:"confidence"`
	TraceID    string    `json:"traceId,omitempty"`
	Summary    string    `json:"summary"`
	Details    string    `json:"details"`
	StartTime  time.Time `json:"startTime"`
	EndTime    time.Time `json:"endTime"`
}

// ToMap converts CorrelationParams to map for Neo4j driver
func (p CorrelationParams) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"id":         p.ID,
		"type":       p.Type,
		"confidence": p.Confidence,
		"summary":    p.Summary,
		"details":    p.Details,
		"startTime":  p.StartTime.Unix(),
		"endTime":    p.EndTime.Unix(),
	}
	if p.TraceID != "" {
		result["traceId"] = p.TraceID
	}
	return result
}

// EventRelationParams represents parameters for event relationships
type EventRelationParams struct {
	CorrelationID string `json:"correlationId"`
	EventID       string `json:"eventId"`
	Role          string `json:"role"`
}

// ToMap converts EventRelationParams to map for Neo4j driver
func (p EventRelationParams) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"correlationId": p.CorrelationID,
		"eventId":       p.EventID,
		"role":          p.Role,
	}
}

// RootCauseParams represents parameters for root cause relationships
type RootCauseParams struct {
	CorrelationID string `json:"correlationId"`
	EventID       string `json:"eventId"`
}

// ToMap converts RootCauseParams to map for Neo4j driver
func (p RootCauseParams) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"correlationId": p.CorrelationID,
		"eventId":       p.EventID,
	}
}

// EvidenceParams represents parameters for evidence relationships
type EvidenceParams struct {
	CorrelationID string  `json:"correlationId"`
	EventID       string  `json:"eventId"`
	Weight        float64 `json:"weight,omitempty"`
}

// ToMap converts EvidenceParams to map for Neo4j driver
func (p EvidenceParams) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"correlationId": p.CorrelationID,
		"eventId":       p.EventID,
	}
	if p.Weight > 0 {
		result["weight"] = p.Weight
	}
	return result
}

// ImpactParams represents parameters for impact relationships
type ImpactParams struct {
	CorrelationID string  `json:"correlationId"`
	EventID       string  `json:"eventId"`
	Severity      string  `json:"severity,omitempty"`
}

// ToMap converts ImpactParams to map for Neo4j driver
func (p ImpactParams) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"correlationId": p.CorrelationID,
		"eventId":       p.EventID,
	}
	if p.Severity != "" {
		result["severity"] = p.Severity
	}
	return result
}

// QueryParams represents common query parameters
type QueryParams struct {
	TraceID        string `json:"traceId,omitempty"`
	CorrelationID  string `json:"correlationId,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	Offset         int    `json:"offset,omitempty"`
	MinConfidence  float64 `json:"minConfidence,omitempty"`
}

// ToMap converts QueryParams to map for Neo4j driver
func (p QueryParams) ToMap() map[string]interface{} {
	result := make(map[string]interface{})
	if p.TraceID != "" {
		result["traceId"] = p.TraceID
	}
	if p.CorrelationID != "" {
		result["correlationId"] = p.CorrelationID
	}
	if p.Limit > 0 {
		result["limit"] = p.Limit
	}
	if p.Offset > 0 {
		result["offset"] = p.Offset
	}
	if p.MinConfidence > 0 {
		result["minConfidence"] = p.MinConfidence
	}
	return result
}