package internal

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/systemd/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

func TestSystemdEventProcessor_ProcessEvent(t *testing.T) {
	processor := newEventProcessor()
	ctx := context.Background()

	tests := []struct {
		name     string
		rawEvent core.RawEvent
		validate func(t *testing.T, event *domain.UnifiedEvent, err error)
	}{
		{
			name: "successful service start",
			rawEvent: core.RawEvent{
				Timestamp: time.Now(),
				Type:      core.EventTypeStart,
				UnitName:  "nginx.service",
				UnitType:  "service",
				OldState:  core.StateInactive,
				NewState:  core.StateActive,
				SubState:  "running",
				Result:    "success",
				MainPID:   1234,
			},
			validate: func(t *testing.T, event *domain.UnifiedEvent, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if event == nil {
					t.Fatal("event is nil")
				}

				// Verify basic event properties
				if event.ID == "" {
					t.Error("event ID should not be empty")
				}
				if !strings.HasPrefix(event.ID, "systemd_") {
					t.Errorf("event ID should start with 'systemd_', got %s", event.ID)
				}
				if event.Source != string(domain.SourceSystemd) {
					t.Errorf("expected source %s, got %s", domain.SourceSystemd, event.Source)
				}
				if event.Type != domain.EventTypeService {
					t.Errorf("expected type %s, got %s", domain.EventTypeService, event.Type)
				}

				// Verify semantic context
				if event.Semantic == nil {
					t.Fatal("Semantic context should not be nil")
				}
				sem := event.Semantic
				if sem.Intent != "service-started" {
					t.Errorf("expected intent service-started, got %s", sem.Intent)
				}
				if sem.Category != "service-lifecycle" {
					t.Errorf("expected category service-lifecycle, got %s", sem.Category)
				}
				if !contains(sem.Tags, "systemd") {
					t.Error("semantic tags should contain 'systemd'")
				}
				if !contains(sem.Tags, "critical-service") {
					t.Error("semantic tags should contain 'critical-service' for nginx")
				}
				if !strings.Contains(sem.Narrative, "nginx.service") {
					t.Errorf("narrative should mention service name, got: %s", sem.Narrative)
				}
				if sem.Confidence != 1.0 {
					t.Errorf("expected confidence 1.0, got %f", sem.Confidence)
				}

				// Verify entity context
				if event.Entity == nil {
					t.Fatal("Entity context should not be nil")
				}
				entity := event.Entity
				if entity.Type != "SystemdUnit" {
					t.Errorf("expected entity type SystemdUnit, got %s", entity.Type)
				}
				if entity.Name != "nginx.service" {
					t.Errorf("expected entity name nginx.service, got %s", entity.Name)
				}
				if entity.Labels["unit_type"] != "service" {
					t.Errorf("expected unit_type service, got %s", entity.Labels["unit_type"])
				}
				if entity.Labels["state"] != core.StateActive {
					t.Errorf("expected state active, got %s", entity.Labels["state"])
				}

				// Verify Application context
				if event.Application == nil {
					t.Fatal("Application context should not be nil")
				}
				app := event.Application
				if app.Level != "info" {
					t.Errorf("expected level info, got %s", app.Level)
				}
				if !strings.Contains(app.Message, "started successfully") {
					t.Errorf("expected success message, got %s", app.Message)
				}
				if app.Logger != "systemd-collector" {
					t.Errorf("expected logger systemd-collector, got %s", app.Logger)
				}
				if app.Custom["unit_name"] != "nginx.service" {
					t.Errorf("expected unit_name nginx.service, got %v", app.Custom["unit_name"])
				}
				if app.Custom["main_pid"] != int32(1234) {
					t.Errorf("expected main_pid 1234, got %v", app.Custom["main_pid"])
				}

				// Verify Impact context
				if event.Impact == nil {
					t.Fatal("Impact context should not be nil")
				}
				impact := event.Impact
				if impact.Severity != string(domain.EventSeverityLow) {
					t.Errorf("expected low severity for successful start, got %s", impact.Severity)
				}
				if impact.BusinessImpact < 0.5 {
					t.Errorf("expected higher business impact for critical service, got %f", impact.BusinessImpact)
				}
				if !impact.CustomerFacing {
					t.Error("nginx should be customer-facing")
				}
				if !contains(impact.AffectedServices, "nginx.service") {
					t.Error("affected services should include nginx.service")
				}
			},
		},
		{
			name: "service failure with exit code",
			rawEvent: core.RawEvent{
				Timestamp:  time.Now(),
				Type:       core.EventTypeFailure,
				UnitName:   "api-server.service",
				UnitType:   "service",
				OldState:   core.StateActive,
				NewState:   core.StateFailed,
				SubState:   "failed",
				Result:     "exit-code",
				ExitCode:   127,
				MainPID:    5678,
			},
			validate: func(t *testing.T, event *domain.UnifiedEvent, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify error type
				if event.Type != domain.EventTypeSystem {
					t.Errorf("expected type %s for failure, got %s", domain.EventTypeSystem, event.Type)
				}

				// Verify semantic context for failure
				if event.Semantic == nil || event.Semantic.Intent != "service-crashed" {
					t.Error("expected intent service-crashed for exit code failure")
				}
				if !contains(event.Semantic.Tags, "failure") {
					t.Error("semantic tags should contain 'failure'")
				}

				// Verify application context shows error
				if event.Application == nil || event.Application.Level != "error" {
					t.Error("expected error level in application context")
				}
				if event.Application.Custom["exit_code"] != int32(127) {
					t.Errorf("expected exit_code 127, got %v", event.Application.Custom["exit_code"])
				}

				// Verify impact for failure
				if event.Impact == nil {
					t.Fatal("Impact context should not be nil")
				}
				if event.Impact.Severity != string(domain.EventSeverityHigh) {
					t.Errorf("expected high severity for failure, got %s", event.Impact.Severity)
				}
				if !event.Impact.CustomerFacing {
					t.Error("api-server should be customer-facing")
				}
				if !event.Impact.SLOImpact {
					t.Error("api failure should impact SLOs")
				}
				if !event.Impact.RevenueImpacting {
					t.Error("api failure should be revenue impacting")
				}
			},
		},
		{
			name: "service restart event",
			rawEvent: core.RawEvent{
				Timestamp: time.Now(),
				Type:      core.EventTypeRestart,
				UnitName:  "postgresql.service",
				UnitType:  "service",
				OldState:  core.StateActive,
				NewState:  core.StateActive,
				SubState:  "running",
				Result:    "success",
				Properties: map[string]interface{}{
					"RestartCount": "3",
				},
			},
			validate: func(t *testing.T, event *domain.UnifiedEvent, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify semantic intent
				if event.Semantic == nil || event.Semantic.Intent != "service-restarted" {
					t.Error("expected intent service-restarted")
				}
				if !contains(event.Semantic.Tags, "restart") {
					t.Error("semantic tags should contain 'restart'")
				}
				if !contains(event.Semantic.Tags, "recovery") {
					t.Error("semantic tags should contain 'recovery'")
				}

				// Verify warning level
				if event.Application == nil || event.Application.Level != "warning" {
					t.Error("expected warning level for restart")
				}

				// Verify impact
				if event.Impact == nil || event.Impact.Severity != string(domain.EventSeverityWarning) {
					t.Error("expected warning severity for restart")
				}
				if !contains(event.Impact.AffectedServices, "api") {
					t.Error("postgresql restart should affect api services")
				}
				if event.Impact.AffectedUsers == 0 {
					t.Error("restart should have brief user impact")
				}
			},
		},
		{
			name: "critical service failure",
			rawEvent: core.RawEvent{
				Timestamp: time.Now(),
				Type:      core.EventTypeFailure,
				UnitName:  "kubelet.service",
				UnitType:  "service",
				OldState:  core.StateActive,
				NewState:  core.StateFailed,
				Result:    "timeout",
			},
			validate: func(t *testing.T, event *domain.UnifiedEvent, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify critical severity
				if event.Impact == nil || event.Impact.Severity != string(domain.EventSeverityCritical) {
					t.Error("expected critical severity for kubelet failure")
				}

				// Verify affected services includes dependencies
				if !contains(event.Impact.AffectedServices, "kube-proxy") {
					t.Error("kubelet failure should affect kube-proxy")
				}
				if !contains(event.Impact.AffectedServices, "calico") || !contains(event.Impact.AffectedServices, "cilium") {
					t.Error("kubelet failure should affect CNI plugins")
				}

				// Verify critical service tag
				if !contains(event.Semantic.Tags, "critical-service") {
					t.Error("kubelet should be tagged as critical-service")
				}
			},
		},
		{
			name: "state transition event",
			rawEvent: core.RawEvent{
				Timestamp: time.Now(),
				Type:      core.EventTypeStateChange,
				UnitName:  "worker.service",
				UnitType:  "service",
				OldState:  core.StateFailed,
				NewState:  core.StateActive,
				SubState:  "running",
			},
			validate: func(t *testing.T, event *domain.UnifiedEvent, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify recovery intent
				if event.Semantic == nil || event.Semantic.Intent != "service-recovered" {
					t.Error("expected intent service-recovered for failed->active transition")
				}

				// Verify narrative mentions transition
				if !strings.Contains(event.Semantic.Narrative, "transitioned from") {
					t.Errorf("narrative should describe transition, got: %s", event.Semantic.Narrative)
				}
			},
		},
		{
			name: "minimal event",
			rawEvent: core.RawEvent{
				Timestamp: time.Now(),
				Type:      core.EventTypeStop,
				UnitName:  "test.service",
				UnitType:  "service",
			},
			validate: func(t *testing.T, event *domain.UnifiedEvent, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Should still create valid event
				if event.ID == "" {
					t.Error("event ID should not be empty")
				}
				if event.Source != string(domain.SourceSystemd) {
					t.Errorf("expected source %s, got %s", domain.SourceSystemd, event.Source)
				}

				// All contexts should be present even for minimal event
				if event.Semantic == nil {
					t.Error("Semantic context should be present")
				}
				if event.Entity == nil {
					t.Error("Entity context should be present")
				}
				if event.Application == nil {
					t.Error("Application context should be present")
				}
				if event.Impact == nil {
					t.Error("Impact context should be present")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := processor.ProcessEvent(ctx, tt.rawEvent)
			tt.validate(t, event, err)
		})
	}
}

func TestSystemdEventProcessor_SemanticIntent(t *testing.T) {
	processor := &eventProcessor{}

	tests := []struct {
		name     string
		raw      core.RawEvent
		expected string
	}{
		{
			name: "successful start",
			raw: core.RawEvent{
				Type:     core.EventTypeStart,
				NewState: core.StateActive,
			},
			expected: "service-started",
		},
		{
			name: "failed start",
			raw: core.RawEvent{
				Type:     core.EventTypeStart,
				NewState: core.StateFailed,
			},
			expected: "service-start-attempted",
		},
		{
			name: "service crash with exit code",
			raw: core.RawEvent{
				Type:     core.EventTypeFailure,
				ExitCode: 127,
			},
			expected: "service-crashed",
		},
		{
			name: "service failure without exit code",
			raw: core.RawEvent{
				Type: core.EventTypeFailure,
			},
			expected: "service-failed",
		},
		{
			name: "service degradation",
			raw: core.RawEvent{
				Type:     core.EventTypeStateChange,
				OldState: core.StateActive,
				NewState: core.StateFailed,
			},
			expected: "service-degraded",
		},
		{
			name: "service recovery",
			raw: core.RawEvent{
				Type:     core.EventTypeStateChange,
				OldState: core.StateFailed,
				NewState: core.StateActive,
			},
			expected: "service-recovered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.determineSemanticIntent(tt.raw)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestSystemdEventProcessor_BusinessImpact(t *testing.T) {
	processor := &eventProcessor{}

	tests := []struct {
		name         string
		raw          core.RawEvent
		minExpected  float64
		maxExpected  float64
	}{
		{
			name: "critical service failure",
			raw: core.RawEvent{
				UnitName: "nginx.service",
				Type:     core.EventTypeFailure,
				NewState: core.StateFailed,
			},
			minExpected: 0.9, // Base (0.1) + Critical (0.5) + Failure (0.3)
			maxExpected: 1.0,
		},
		{
			name: "non-critical service running",
			raw: core.RawEvent{
				UnitName: "random.service",
				Type:     core.EventTypeStart,
				NewState: core.StateActive,
			},
			minExpected: 0.1,
			maxExpected: 0.2,
		},
		{
			name: "service restart",
			raw: core.RawEvent{
				UnitName: "app.service",
				Type:     core.EventTypeRestart,
			},
			minExpected: 0.3, // Base (0.1) + Restart (0.2)
			maxExpected: 0.4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.calculateBusinessImpact(tt.raw)
			if result < tt.minExpected || result > tt.maxExpected {
				t.Errorf("expected impact between %f and %f, got %f", tt.minExpected, tt.maxExpected, result)
			}
		})
	}
}

func TestSystemdEventProcessor_CustomerFacing(t *testing.T) {
	processor := &eventProcessor{}

	tests := []struct {
		name     string
		unitName string
		expected bool
	}{
		{"nginx service", "nginx.service", true},
		{"api service", "api-server.service", true},
		{"web frontend", "web-frontend.service", true},
		{"haproxy lb", "haproxy.service", true},
		{"internal worker", "background-worker.service", false},
		{"database", "postgresql.service", false},
		{"system service", "systemd-logind.service", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.isCustomerFacing(core.RawEvent{UnitName: tt.unitName})
			if result != tt.expected {
				t.Errorf("expected %v for %s, got %v", tt.expected, tt.unitName, result)
			}
		})
	}
}

func TestSystemdEventProcessor_AffectedServices(t *testing.T) {
	processor := &eventProcessor{}

	tests := []struct {
		name     string
		unitName string
		contains []string
	}{
		{
			name:     "docker affects kubelet",
			unitName: "docker.service",
			contains: []string{"docker.service", "kubelet", "containerd"},
		},
		{
			name:     "etcd affects kube-apiserver",
			unitName: "etcd.service",
			contains: []string{"etcd.service", "kube-apiserver", "calico"},
		},
		{
			name:     "postgresql affects api",
			unitName: "postgresql.service",
			contains: []string{"postgresql.service", "api", "backend"},
		},
		{
			name:     "standalone service",
			unitName: "standalone.service",
			contains: []string{"standalone.service"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.identifyAffectedServices(core.RawEvent{UnitName: tt.unitName})
			for _, expected := range tt.contains {
				if !contains(result, expected) {
					t.Errorf("expected affected services to contain %s, got %v", expected, result)
				}
			}
		})
	}
}

func TestSystemdEventProcessor_CriticalService(t *testing.T) {
	processor := &eventProcessor{}

	tests := []struct {
		name     string
		unitName string
		expected bool
	}{
		{"sshd", "sshd.service", true},
		{"kubelet", "kubelet.service", true},
		{"docker", "docker.service", true},
		{"nginx", "nginx.service", true},
		{"postgresql", "postgresql-12.service", true},
		{"random app", "myapp.service", false},
		{"user service", "user-app.service", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.isCriticalService(tt.unitName)
			if result != tt.expected {
				t.Errorf("expected %v for %s, got %v", tt.expected, tt.unitName, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkSystemdEventProcessor_ProcessEvent(b *testing.B) {
	processor := newEventProcessor()
	ctx := context.Background()

	testEvent := core.RawEvent{
		Timestamp: time.Now(),
		Type:      core.EventTypeStart,
		UnitName:  "nginx.service",
		UnitType:  "service",
		OldState:  core.StateInactive,
		NewState:  core.StateActive,
		SubState:  "running",
		Result:    "success",
		MainPID:   1234,
		Properties: map[string]interface{}{
			"RestartCount": "0",
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := processor.ProcessEvent(ctx, testEvent)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Helper function for slice contains check
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}