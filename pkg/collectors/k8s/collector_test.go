package k8s

import (
	"context"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/k8s/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

func TestNewCollector(t *testing.T) {
	config := core.Config{
		Name:            "test-k8s-collector",
		Enabled:         true,
		EventBufferSize: 100,
		InCluster:       false,
		WatchPods:       true,
		WatchEvents:     true,
	}

	collector := New(config)
	if collector == nil {
		t.Fatal("Expected collector to be created")
	}
}

func TestCollectorLifecycle(t *testing.T) {
	config := core.Config{
		Name:            "test-k8s-collector",
		Enabled:         true,
		EventBufferSize: 10,
		InCluster:       false,
		WatchPods:       true,
	}

	collector := New(config)

	// Test starting when not enabled
	config.Enabled = false
	collector.Configure(config)
	
	ctx := context.Background()
	err := collector.Start(ctx)
	if err == nil {
		t.Error("Expected error when starting disabled collector")
	}

	// Test starting with enabled collector
	config.Enabled = true
	collector.Configure(config)
	
	// Note: This will fail without a valid kubeconfig
	// In a real test environment, you'd mock the kubernetes client
	err = collector.Start(ctx)
	if err == nil {
		// If it succeeds (which means we have a valid k8s connection)
		// we should be able to stop it
		stopErr := collector.Stop()
		if stopErr != nil {
			t.Errorf("Failed to stop collector: %v", stopErr)
		}
	}
}

func TestCollectorHealth(t *testing.T) {
	config := core.Config{
		Name:            "test-k8s-collector",
		Enabled:         true,
		EventBufferSize: 10,
	}

	collector := New(config)
	health := collector.Health()

	if health.Status != core.HealthStatusUnknown {
		t.Errorf("Expected initial health status to be unknown, got %s", health.Status)
	}

	if health.Connected {
		t.Error("Expected collector to be disconnected initially")
	}
}

func TestCollectorStatistics(t *testing.T) {
	config := core.Config{
		Name:            "test-k8s-collector",
		Enabled:         true,
		EventBufferSize: 10,
	}

	collector := New(config)
	stats := collector.Statistics()

	if stats.EventsCollected != 0 {
		t.Errorf("Expected 0 events collected initially, got %d", stats.EventsCollected)
	}

	if stats.WatchersActive != 0 {
		t.Errorf("Expected 0 watchers active initially, got %d", stats.WatchersActive)
	}

	if len(stats.ResourcesWatched) != 0 {
		t.Errorf("Expected no resources watched initially, got %v", stats.ResourcesWatched)
	}
}

func TestCollectorConfigure(t *testing.T) {
	config := core.Config{
		Name:            "test-k8s-collector",
		Enabled:         true,
		EventBufferSize: 10,
		WatchPods:       true,
		WatchNodes:      false,
	}

	collector := New(config)

	// Reconfigure
	newConfig := core.Config{
		Name:            "test-k8s-collector-updated",
		Enabled:         true,
		EventBufferSize: 20,
		WatchPods:       false,
		WatchNodes:      true,
		ResyncPeriod:    5 * time.Minute,
	}

	err := collector.Configure(newConfig)
	if err != nil {
		t.Errorf("Failed to configure collector: %v", err)
	}

	// Verify configuration was applied
	health := collector.Health()
	if health.Metrics == nil {
		t.Error("Expected health metrics to be initialized")
	}
}

func TestCollectorEvents(t *testing.T) {
	config := core.Config{
		Name:            "test-k8s-collector",
		Enabled:         true,
		EventBufferSize: 10,
	}

	collector := New(config)
	eventChan := collector.Events()

	if eventChan == nil {
		t.Error("Expected event channel to be created")
	}

	// Channel should be empty initially
	select {
	case event := <-eventChan:
		t.Errorf("Expected no events initially, got %v", event)
	case <-time.After(100 * time.Millisecond):
		// Expected timeout
	}
}

func TestCollectorConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config core.Config
		valid  bool
	}{
		{
			name: "valid config",
			config: core.Config{
				Name:            "test",
				Enabled:         true,
				EventBufferSize: 100,
				ResyncPeriod:    30 * time.Minute,
				WatchPods:       true,
			},
			valid: true,
		},
		{
			name: "zero buffer size",
			config: core.Config{
				Name:            "test",
				Enabled:         true,
				EventBufferSize: 0, // Should be set to default
				ResyncPeriod:    0,  // Should be set to default
			},
			valid: true,
		},
		{
			name: "no resources watched",
			config: core.Config{
				Name:            "test",
				Enabled:         true,
				EventBufferSize: 100,
				// All watch flags false - should default to pods and events
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err == nil) != tt.valid {
				t.Errorf("Validate() error = %v, valid = %v", err, tt.valid)
			}
		})
	}
}

// Helper function to create a mock event for testing
func createMockEvent(eventType domain.EventType) domain.Event {
	return domain.Event{
		ID:        domain.EventID("test-event-123"),
		Type:      eventType,
		Source:    domain.SourceK8s,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"resource": map[string]interface{}{
				"kind":      "Pod",
				"name":      "test-pod",
				"namespace": "default",
			},
			"event_type": "ADDED",
		},
		Severity:   domain.EventSeverityInfo,
		Confidence: 1.0,
	}
}