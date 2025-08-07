//go:build !linux
// +build !linux

package kubelet

import (
	"context"
	"fmt"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors"
)

// FileSystemConfig configures filesystem monitoring (stub for non-Linux platforms)
type FileSystemConfig struct {
	// Enable filesystem monitoring
	Enabled bool `json:"enabled"`

	// Minimum latency threshold in microseconds (only report slower operations)
	MinLatencyUs uint32 `json:"min_latency_us"`

	// Track only kubelet-related processes
	TrackKubeletOnly bool `json:"track_kubelet_only"`

	// Track only volume-related paths
	TrackVolumesOnly bool `json:"track_volumes_only"`

	// Latency thresholds for alerting
	Thresholds struct {
		Warning  time.Duration `json:"warning"`  // e.g., 100ms
		Critical time.Duration `json:"critical"` // e.g., 1s
	} `json:"thresholds"`
}

// DefaultFileSystemConfig returns default filesystem monitoring configuration
func DefaultFileSystemConfig() FileSystemConfig {
	config := FileSystemConfig{
		Enabled:          false, // Disabled on non-Linux
		MinLatencyUs:     10000, // 10ms minimum
		TrackKubeletOnly: true,
		TrackVolumesOnly: true,
	}

	config.Thresholds.Warning = 100 * time.Millisecond
	config.Thresholds.Critical = 1 * time.Second

	return config
}

// FileSystemEvent represents a filesystem I/O event (stub for non-Linux platforms)
type FileSystemEvent struct {
	Timestamp      time.Time
	PID            uint32
	TID            uint32
	UID            uint32
	Operation      string
	FileDescriptor uint32
	ReturnCode     int32
	LatencyNs      uint64
	BytesRequested uint64
	BytesActual    uint64
	ProcessName    string
	Filename       string
	FullPath       string
	Severity       string
}

// FileSystemStats tracks filesystem monitoring statistics (stub)
type FileSystemStats struct {
	EventsProcessed  uint64
	SlowOperations   uint64
	VerySlowOps      uint64
	ReadOperations   uint64
	WriteOperations  uint64
	OpenOperations   uint64
	SyncOperations   uint64
	CloseOperations  uint64
	AverageLatencyNs uint64
	MaxLatencyNs     uint64
	LastEventTime    time.Time
}

// FileSystemMonitor stub for non-Linux platforms
type FileSystemMonitor struct {
	stats FileSystemStats
}

// NewFileSystemMonitor returns an error on non-Linux platforms
func NewFileSystemMonitor(config FileSystemConfig, eventsChan chan collectors.RawEvent) (*FileSystemMonitor, error) {
	return nil, fmt.Errorf("filesystem monitoring is only supported on Linux")
}

// Start is a no-op on non-Linux platforms
func (f *FileSystemMonitor) Start(ctx context.Context) error {
	return fmt.Errorf("filesystem monitoring is only supported on Linux")
}

// Stop is a no-op on non-Linux platforms
func (f *FileSystemMonitor) Stop() error {
	return nil
}

// GetStats returns empty stats on non-Linux platforms
func (f *FileSystemMonitor) GetStats() FileSystemStats {
	return FileSystemStats{}
}
