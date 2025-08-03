package systemd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yairfalse/tapio/pkg/collectors"
)

func TestNewCollector(t *testing.T) {
	collector, err := NewCollector("test")
	require.NoError(t, err)
	assert.Equal(t, "test", collector.Name())
	assert.True(t, collector.IsHealthy())
}

func TestCollectorInterface(t *testing.T) {
	collector, err := NewCollector("interface-test")
	require.NoError(t, err)

	// Verify it implements collectors.Collector
	var _ collectors.Collector = collector
}

func TestNullTerminatedString(t *testing.T) {
	collector, _ := NewCollector("test")

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"null terminated", []byte("hello\x00world"), "hello"},
		{"multiple nulls", []byte("systemd\x00\x00\x00"), "systemd"},
		{"no null", []byte("test"), "test"},
		{"empty with null", []byte("\x00"), ""},
		{"empty", []byte{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collector.nullTerminatedString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCollectorStartStop(t *testing.T) {
	collector, err := NewCollector("test-start-stop")
	require.NoError(t, err)

	// Test Start
	ctx := context.Background()
	err = collector.Start(ctx)
	// May fail on non-Linux systems or without eBPF support
	if err != nil {
		t.Skipf("eBPF not supported on this system: %v", err)
	}

	// Test double start
	err = collector.Start(ctx)
	assert.Error(t, err, "Should error on double start")

	// Test Stop
	err = collector.Stop()
	assert.NoError(t, err)

	// Test stopping already stopped collector
	err = collector.Stop()
	assert.NoError(t, err, "Stop should be idempotent")
}

func TestCollectorEvents(t *testing.T) {
	collector, err := NewCollector("test-events")
	require.NoError(t, err)

	// Get events channel
	events := collector.Events()
	assert.NotNil(t, events)

	// Channel should be empty initially
	select {
	case <-events:
		t.Fatal("Events channel should be empty")
	default:
		// Expected
	}
}

func TestEventTypeToString(t *testing.T) {
	collector, _ := NewCollector("test")

	tests := []struct {
		name     string
		eventType uint32
		expected string
	}{
		{"exec event", 1, "exec"},
		{"exit event", 2, "exit"},
		{"kill event", 3, "kill"},
		{"unknown event", 99, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collector.eventTypeToString(tt.eventType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCollectorHealthy(t *testing.T) {
	collector, err := NewCollector("test-health")
	require.NoError(t, err)

	// Initially healthy
	assert.True(t, collector.IsHealthy())

	// Start and stop collector
	ctx := context.Background()
	err = collector.Start(ctx)
	if err != nil {
		t.Skipf("eBPF not supported on this system: %v", err)
	}

	// Should still be healthy
	assert.True(t, collector.IsHealthy())

	// Stop collector
	err = collector.Stop()
	require.NoError(t, err)

	// Should not be healthy after stop
	assert.False(t, collector.IsHealthy())
}

func TestCollectorWithContext(t *testing.T) {
	collector, err := NewCollector("test-context")
	require.NoError(t, err)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = collector.Start(ctx)
	if err != nil {
		t.Skipf("eBPF not supported on this system: %v", err)
	}

	// Wait for context to expire
	<-ctx.Done()

	// Stop should still work
	err = collector.Stop()
	assert.NoError(t, err)
}

func TestCollectorConfig(t *testing.T) {
	// Test with config
	config := DefaultConfig()
	assert.Equal(t, 10000, config.BufferSize)
	assert.True(t, config.EnableEBPF)
	assert.Empty(t, config.ServicePatterns)

	// Test config modifications
	config.BufferSize = 5000
	config.EnableEBPF = false
	config.ServicePatterns = []string{"kubelet", "docker"}

	assert.Equal(t, 5000, config.BufferSize)
	assert.False(t, config.EnableEBPF)
	assert.Len(t, config.ServicePatterns, 2)
}
