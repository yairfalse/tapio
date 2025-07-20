package internal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/systemd/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

// eventProcessor implements core.EventProcessor
// This is the key component that creates UnifiedEvent directly from systemd sources,
// enabling rich semantic correlation and eliminating conversion overhead.
type eventProcessor struct {
	hostname string
}

func newEventProcessor() core.EventProcessor {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	return &eventProcessor{
		hostname: hostname,
	}
}

// ProcessEvent converts a raw systemd event to a UnifiedEvent with rich semantic context
func (p *eventProcessor) ProcessEvent(ctx context.Context, raw core.RawEvent) (*domain.UnifiedEvent, error) {
	// Generate cryptographically secure event ID like K8s collector
	eventID := p.generateSecureEventID()

	// Determine event type and severity with semantic intelligence
	severity := p.determineSeverity(raw)

	// Create the UnifiedEvent with rich semantic context
	unifiedEvent := &domain.UnifiedEvent{
		// Core event identification
		ID:        eventID,
		Timestamp: raw.Timestamp,
		Source:    string(domain.SourceSystemd),
		Type:      p.mapEventTypeToDomain(raw),

		// Rich semantic correlation context - CRITICAL
		Semantic: p.createSemanticContext(raw),
		Entity:   p.createEntityContext(raw),

		// Application-specific data for systemd services
		Application: p.createApplicationContext(raw),

		// Complete impact context with all fields
		Impact: p.createImpactContext(raw, severity),

		// Original data for debugging
		RawData: []byte(p.generateMessage(raw)),
	}

	return unifiedEvent, nil
}

// generateSecureEventID generates a cryptographically secure event ID
func (p *eventProcessor) generateSecureEventID() string {
	// Generate 16 bytes of random data
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if crypto fails
		return fmt.Sprintf("systemd_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("systemd_%s", hex.EncodeToString(bytes))
}

// createSemanticContext creates rich semantic context for systemd events
func (p *eventProcessor) createSemanticContext(raw core.RawEvent) *domain.SemanticContext {
	// Determine semantic intent based on event type and state
	intent := p.determineSemanticIntent(raw)
	
	// Build semantic tags
	tags := []string{"systemd", raw.UnitType}
	if raw.NewState == core.StateFailed {
		tags = append(tags, "failure", "service-health")
	}
	if raw.Type == core.EventTypeRestart {
		tags = append(tags, "recovery", "restart")
	}
	if p.isCriticalService(raw.UnitName) {
		tags = append(tags, "critical-service")
	}

	// Generate human-readable narrative
	narrative := p.generateNarrative(raw)

	// Calculate confidence based on event completeness
	confidence := p.calculateConfidence(raw)

	return &domain.SemanticContext{
		Intent:     intent,
		Category:   "service-lifecycle",
		Tags:       tags,
		Narrative:  narrative,
		Confidence: confidence,
	}
}

// determineSemanticIntent determines the semantic intent of the systemd event
func (p *eventProcessor) determineSemanticIntent(raw core.RawEvent) string {
	switch raw.Type {
	case core.EventTypeStart:
		if raw.NewState == core.StateActive {
			return "service-started"
		}
		return "service-start-attempted"
	case core.EventTypeStop:
		if raw.Result == "success" {
			return "service-stopped"
		}
		return "service-stop-failed"
	case core.EventTypeRestart:
		return "service-restarted"
	case core.EventTypeReload:
		return "service-reloaded"
	case core.EventTypeFailure:
		if raw.ExitCode != 0 {
			return "service-crashed"
		}
		return "service-failed"
	case core.EventTypeStateChange:
		if raw.OldState == core.StateActive && raw.NewState == core.StateFailed {
			return "service-degraded"
		}
		if raw.OldState == core.StateFailed && raw.NewState == core.StateActive {
			return "service-recovered"
		}
		return "service-state-changed"
	default:
		return "service-event"
	}
}

// generateNarrative creates a human-readable narrative for the event
func (p *eventProcessor) generateNarrative(raw core.RawEvent) string {
	var narrative strings.Builder

	// Start with service name
	narrative.WriteString(fmt.Sprintf("Service '%s'", raw.UnitName))

	// Add action based on event type
	switch raw.Type {
	case core.EventTypeStart:
		if raw.NewState == core.StateActive {
			narrative.WriteString(" started successfully")
		} else {
			narrative.WriteString(" failed to start")
		}
	case core.EventTypeStop:
		narrative.WriteString(" stopped")
	case core.EventTypeRestart:
		narrative.WriteString(" was restarted")
	case core.EventTypeFailure:
		if raw.ExitCode != 0 {
			narrative.WriteString(fmt.Sprintf(" crashed with exit code %d", raw.ExitCode))
		} else {
			narrative.WriteString(" failed")
		}
	case core.EventTypeStateChange:
		narrative.WriteString(fmt.Sprintf(" transitioned from %s to %s", raw.OldState, raw.NewState))
	}

	// Add result if it's a failure
	if raw.Result != "" && raw.Result != "success" {
		narrative.WriteString(fmt.Sprintf(" (result: %s)", raw.Result))
	}

	// Add host context
	narrative.WriteString(fmt.Sprintf(" on host %s", p.hostname))

	return narrative.String()
}

// calculateConfidence calculates confidence score based on event completeness
func (p *eventProcessor) calculateConfidence(raw core.RawEvent) float64 {
	confidence := 1.0 // systemd events are direct observations

	// Reduce confidence for incomplete events
	if raw.UnitName == "" {
		confidence -= 0.3
	}
	if raw.Type == "" {
		confidence -= 0.2
	}
	if raw.NewState == "" && raw.Type == core.EventTypeStateChange {
		confidence -= 0.2
	}

	if confidence < 0.1 {
		confidence = 0.1
	}

	return confidence
}

// createEntityContext identifies what the event is about
func (p *eventProcessor) createEntityContext(raw core.RawEvent) *domain.EntityContext {
	return &domain.EntityContext{
		Type: "SystemdUnit",
		Name: raw.UnitName,
		Labels: map[string]string{
			"unit_type": raw.UnitType,
			"state":     raw.NewState,
			"sub_state": raw.SubState,
			"host":      p.hostname,
		},
	}
}

// createApplicationContext creates application context for systemd services
func (p *eventProcessor) createApplicationContext(raw core.RawEvent) *domain.ApplicationData {
	level := "info"
	if raw.Type == core.EventTypeFailure || raw.NewState == core.StateFailed {
		level = "error"
	} else if raw.Type == core.EventTypeRestart {
		level = "warning"
	}

	// Build custom data with all relevant systemd information
	custom := map[string]interface{}{
		"unit_name": raw.UnitName,
		"unit_type": raw.UnitType,
		"old_state": raw.OldState,
		"new_state": raw.NewState,
		"sub_state": raw.SubState,
		"result":    raw.Result,
	}

	if raw.MainPID > 0 {
		custom["main_pid"] = raw.MainPID
	}
	if raw.ExitCode != 0 {
		custom["exit_code"] = raw.ExitCode
	}
	if raw.ExitStatus != 0 {
		custom["exit_status"] = raw.ExitStatus
	}

	// Add selected properties that are most relevant
	if len(raw.Properties) > 0 {
		// Extract key properties
		relevantProps := []string{
			"ExecMainStartTimestamp",
			"ExecMainExitTimestamp",
			"RestartSec",
			"TimeoutStartSec",
			"TimeoutStopSec",
			"Restart",
			"RestartCount",
		}
		props := make(map[string]interface{})
		for _, key := range relevantProps {
			if value, ok := raw.Properties[key]; ok {
				props[key] = value
			}
		}
		if len(props) > 0 {
			custom["properties"] = props
		}
	}

	return &domain.ApplicationData{
		Level:   level,
		Message: p.generateMessage(raw),
		Logger:  "systemd-collector",
		Custom:  custom,
	}
}

// createImpactContext creates comprehensive impact assessment
func (p *eventProcessor) createImpactContext(raw core.RawEvent, severity domain.EventSeverity) *domain.ImpactContext {
	// Calculate business impact
	businessImpact := p.calculateBusinessImpact(raw)

	// Determine if customer-facing
	customerFacing := p.isCustomerFacing(raw)

	// Identify affected services
	affectedServices := p.identifyAffectedServices(raw)

	// Check SLO impact
	sloImpact := p.checkSLOImpact(raw)

	// Check revenue impact
	revenueImpacting := p.isRevenueImpacting(raw)

	// Estimate affected users
	affectedUsers := p.estimateAffectedUsers(raw)

	return &domain.ImpactContext{
		Severity:         string(severity),
		BusinessImpact:   businessImpact,
		AffectedServices: affectedServices,
		CustomerFacing:   customerFacing,
		SLOImpact:        sloImpact,
		RevenueImpacting: revenueImpacting,
		AffectedUsers:    affectedUsers,
	}
}

// calculateBusinessImpact calculates business impact score (0.0 to 1.0)
func (p *eventProcessor) calculateBusinessImpact(raw core.RawEvent) float64 {
	impact := 0.1 // Base impact

	// Critical services have higher impact
	if p.isCriticalService(raw.UnitName) {
		impact += 0.5
	}

	// Failures have higher impact
	if raw.Type == core.EventTypeFailure || raw.NewState == core.StateFailed {
		impact += 0.3
	}

	// Multiple restarts indicate instability
	if raw.Type == core.EventTypeRestart {
		impact += 0.2
		// Could check Properties["RestartCount"] for even more precision
	}

	// Service degradation
	if raw.OldState == core.StateActive && raw.NewState != core.StateActive {
		impact += 0.2
	}

	if impact > 1.0 {
		impact = 1.0
	}

	return impact
}

// isCustomerFacing determines if the service is customer-facing
func (p *eventProcessor) isCustomerFacing(raw core.RawEvent) bool {
	customerFacingServices := []string{
		"nginx", "apache", "httpd",
		"haproxy", "envoy",
		"api", "web", "frontend",
		"gateway", "loadbalancer",
	}

	serviceLower := strings.ToLower(raw.UnitName)
	for _, svc := range customerFacingServices {
		if strings.Contains(serviceLower, svc) {
			return true
		}
	}

	return false
}

// identifyAffectedServices identifies services that might be affected
func (p *eventProcessor) identifyAffectedServices(raw core.RawEvent) []string {
	affected := []string{raw.UnitName}

	// Map of service dependencies
	dependencies := map[string][]string{
		"docker":           {"kubelet", "containerd"},
		"containerd":       {"kubelet", "docker"},
		"kubelet":          {"kube-proxy", "calico", "cilium"},
		"etcd":             {"kube-apiserver", "calico"},
		"kube-apiserver":   {"kube-controller-manager", "kube-scheduler"},
		"postgresql":       {"api", "backend"},
		"mysql":            {"api", "backend"},
		"redis":            {"cache", "session"},
		"rabbitmq":         {"worker", "queue-processor"},
		"systemd-networkd": {"*network*"},
		"systemd-resolved": {"*dns*"},
	}

	// Check if this service affects others
	for service, deps := range dependencies {
		if strings.Contains(raw.UnitName, service) {
			affected = append(affected, deps...)
			break
		}
	}

	return affected
}

// checkSLOImpact determines if this event impacts SLOs
func (p *eventProcessor) checkSLOImpact(raw core.RawEvent) bool {
	// Critical services that typically have SLOs
	sloServices := []string{
		"api", "web", "database",
		"cache", "queue",
		"nginx", "haproxy", "envoy",
		"postgresql", "mysql", "mongodb",
		"redis", "rabbitmq", "kafka",
	}

	if raw.Type == core.EventTypeFailure || raw.NewState == core.StateFailed {
		serviceLower := strings.ToLower(raw.UnitName)
		for _, svc := range sloServices {
			if strings.Contains(serviceLower, svc) {
				return true
			}
		}
	}

	return false
}

// isRevenueImpacting determines if this could impact revenue
func (p *eventProcessor) isRevenueImpacting(raw core.RawEvent) bool {
	// Services that directly impact revenue
	revenueServices := []string{
		"payment", "checkout", "billing",
		"subscription", "order",
		"shop", "store", "commerce",
		"api", "web", "frontend",
	}

	if raw.Type == core.EventTypeFailure || raw.NewState == core.StateFailed {
		serviceLower := strings.ToLower(raw.UnitName)
		for _, svc := range revenueServices {
			if strings.Contains(serviceLower, svc) {
				return true
			}
		}
	}

	return false
}

// estimateAffectedUsers estimates number of affected users
func (p *eventProcessor) estimateAffectedUsers(raw core.RawEvent) int {
	if !p.isCustomerFacing(raw) {
		return 0
	}

	// Base estimation on service type and state
	baseUsers := 0
	
	if strings.Contains(raw.UnitName, "nginx") || strings.Contains(raw.UnitName, "haproxy") {
		baseUsers = 1000 // Load balancers affect many users
	} else if strings.Contains(raw.UnitName, "api") {
		baseUsers = 500
	} else if strings.Contains(raw.UnitName, "web") {
		baseUsers = 200
	}

	// Adjust based on failure severity
	if raw.NewState == core.StateFailed {
		return baseUsers // Full impact
	} else if raw.Type == core.EventTypeRestart {
		return baseUsers / 10 // Brief disruption
	}

	return 0
}

// mapEventTypeToDomain maps systemd event types to domain event types
func (p *eventProcessor) mapEventTypeToDomain(raw core.RawEvent) domain.EventType {
	// Systemd events are typically service or system events
	if raw.Type == core.EventTypeFailure || raw.ExitCode != 0 {
		return domain.EventTypeSystem
	}
	
	// Most systemd events are service-related
	return domain.EventTypeService
}

// determineSeverity determines the event severity with semantic intelligence
func (p *eventProcessor) determineSeverity(raw core.RawEvent) domain.EventSeverity {
	// Check for failures
	if raw.Type == core.EventTypeFailure || raw.NewState == core.StateFailed {
		// Critical services
		if p.isCriticalService(raw.UnitName) {
			return domain.EventSeverityCritical
		}
		return domain.EventSeverityHigh
	}

	// Check for restart events
	if raw.Type == core.EventTypeRestart {
		return domain.EventSeverityWarning
	}

	// State changes
	if raw.Type == core.EventTypeStateChange {
		if raw.OldState == core.StateActive && raw.NewState == core.StateInactive {
			return domain.EventSeverityWarning
		}
	}

	// Exit codes
	if raw.ExitCode != 0 {
		return domain.EventSeverityWarning
	}

	return domain.EventSeverityLow
}

// isCriticalService checks if a service is considered critical
func (p *eventProcessor) isCriticalService(serviceName string) bool {
	criticalServices := []string{
		"sshd",
		"systemd-networkd",
		"systemd-resolved",
		"dbus",
		"systemd-journald",
		"kubelet",
		"docker",
		"containerd",
		"etcd",
		"kube-apiserver",
		"postgresql",
		"mysql",
		"nginx",
		"haproxy",
	}

	serviceLower := strings.ToLower(serviceName)
	for _, critical := range criticalServices {
		if strings.Contains(serviceLower, critical) {
			return true
		}
	}

	return false
}

// generateMessage generates a descriptive message for the event
func (p *eventProcessor) generateMessage(raw core.RawEvent) string {
	switch raw.Type {
	case core.EventTypeStart:
		if raw.NewState == core.StateActive {
			return fmt.Sprintf("Service %s started successfully on %s", raw.UnitName, p.hostname)
		}
		return fmt.Sprintf("Service %s failed to start on %s: %s", raw.UnitName, p.hostname, raw.Result)
	case core.EventTypeStop:
		return fmt.Sprintf("Service %s stopped on %s", raw.UnitName, p.hostname)
	case core.EventTypeRestart:
		return fmt.Sprintf("Service %s restarted on %s", raw.UnitName, p.hostname)
	case core.EventTypeReload:
		return fmt.Sprintf("Service %s reloaded configuration on %s", raw.UnitName, p.hostname)
	case core.EventTypeFailure:
		if raw.ExitCode != 0 {
			return fmt.Sprintf("Service %s crashed with exit code %d on %s", raw.UnitName, raw.ExitCode, p.hostname)
		}
		return fmt.Sprintf("Service %s failed on %s: %s", raw.UnitName, p.hostname, raw.Result)
	case core.EventTypeStateChange:
		return fmt.Sprintf("Service %s state changed from %s to %s on %s", raw.UnitName, raw.OldState, raw.NewState, p.hostname)
	default:
		return fmt.Sprintf("Service %s event %s on %s", raw.UnitName, raw.Type, p.hostname)
	}
}