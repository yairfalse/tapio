//go:build linux
// +build linux

package kubelet

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yairfalse/tapio/pkg/collectors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang fsMonitor ./bpf_src/fs_monitor.c -- -I../bpf_common

// FileSystemConfig configures filesystem monitoring
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
		Enabled:          true,
		MinLatencyUs:     10000, // 10ms minimum
		TrackKubeletOnly: true,
		TrackVolumesOnly: true,
	}

	config.Thresholds.Warning = 100 * time.Millisecond
	config.Thresholds.Critical = 1 * time.Second

	return config
}

// FileSystemEvent represents a filesystem I/O event
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

// rawFsEvent matches the C struct from BPF program
type rawFsEvent struct {
	Timestamp      uint64
	PID            uint32
	TID            uint32
	UID            uint32
	Operation      uint8
	_              [3]byte // padding
	FD             uint32
	RetCode        int32
	LatencyNs      uint64
	BytesRequested uint64
	BytesActual    uint64
	Comm           [16]byte
	Filename       [64]byte
	FullPath       [256]byte
}

// fsConfig matches the C struct for configuration
type fsConfig struct {
	MinLatencyUs     uint32
	TrackKubeletOnly uint32
	TrackVolumesOnly uint32
	Enabled          uint32
}

// FileSystemMonitor manages filesystem I/O monitoring via eBPF
type FileSystemMonitor struct {
	config     FileSystemConfig
	objs       *FsMonitorObjects
	links      []link.Link
	reader     *ringbuf.Reader
	ctx        context.Context
	cancel     context.CancelFunc
	eventsChan chan collectors.RawEvent
	wg         sync.WaitGroup

	// Statistics
	mu    sync.RWMutex
	stats FileSystemStats
}

// FileSystemStats tracks filesystem monitoring statistics
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

// NewFileSystemMonitor creates a new filesystem monitor
func NewFileSystemMonitor(config FileSystemConfig, eventsChan chan collectors.RawEvent) (*FileSystemMonitor, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("filesystem monitoring is disabled")
	}

	monitor := &FileSystemMonitor{
		config:     config,
		eventsChan: eventsChan,
	}

	return monitor, nil
}

// Start initializes and starts filesystem monitoring
func (f *FileSystemMonitor) Start(ctx context.Context) error {
	f.ctx, f.cancel = context.WithCancel(ctx)

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load eBPF objects
	f.objs = &FsMonitorObjects{}
	if err := LoadFsMonitorObjects(f.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Configure the BPF program
	if err := f.configureBPF(); err != nil {
		f.cleanup()
		return fmt.Errorf("configuring BPF program: %w", err)
	}

	// Attach tracepoints
	if err := f.attachTracepoints(); err != nil {
		f.cleanup()
		return fmt.Errorf("attaching tracepoints: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(f.objs.FsEvents)
	if err != nil {
		f.cleanup()
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	f.reader = reader

	// Start event processing
	f.wg.Add(1)
	go f.processEvents()

	return nil
}

// Stop gracefully shuts down filesystem monitoring
func (f *FileSystemMonitor) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}

	// Wait for event processing to complete
	f.wg.Wait()

	// Clean up resources
	f.cleanup()

	return nil
}

// configureBPF configures the BPF program with current settings
func (f *FileSystemMonitor) configureBPF() error {
	config := fsConfig{
		MinLatencyUs:     f.config.MinLatencyUs,
		TrackKubeletOnly: boolToUint32(f.config.TrackKubeletOnly),
		TrackVolumesOnly: boolToUint32(f.config.TrackVolumesOnly),
		Enabled:          boolToUint32(f.config.Enabled),
	}

	key := uint32(0)
	return f.objs.ConfigMap.Put(&key, &config)
}

// attachTracepoints attaches to all filesystem-related tracepoints
func (f *FileSystemMonitor) attachTracepoints() error {
	tracepoints := []struct {
		group   string
		name    string
		program string
		progPtr interface{}
	}{
		{"syscalls", "sys_enter_openat", "trace_openat_enter", f.objs.TraceOpenatEnter},
		{"syscalls", "sys_exit_openat", "trace_openat_exit", f.objs.TraceOpenatExit},
		{"syscalls", "sys_enter_read", "trace_read_enter", f.objs.TraceReadEnter},
		{"syscalls", "sys_exit_read", "trace_read_exit", f.objs.TraceReadExit},
		{"syscalls", "sys_enter_write", "trace_write_enter", f.objs.TraceWriteEnter},
		{"syscalls", "sys_exit_write", "trace_write_exit", f.objs.TraceWriteExit},
		{"syscalls", "sys_enter_fsync", "trace_fsync_enter", f.objs.TraceFsyncEnter},
		{"syscalls", "sys_exit_fsync", "trace_fsync_exit", f.objs.TraceFsyncExit},
		{"syscalls", "sys_enter_close", "trace_close_enter", f.objs.TraceCloseEnter},
		{"syscalls", "sys_exit_close", "trace_close_exit", f.objs.TraceCloseExit},
	}

	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.progPtr, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint %s:%s: %w", tp.group, tp.name, err)
		}
		f.links = append(f.links, l)
	}

	return nil
}

// processEvents processes filesystem events from the ring buffer
func (f *FileSystemMonitor) processEvents() {
	defer f.wg.Done()
	// Recover from panics to prevent monitor crash
	defer func() {
		if r := recover(); r != nil {
			// Log the panic (would use logger if available)
			fmt.Printf("[ERROR] FileSystemMonitor processEvents panic recovered: %v\n", r)
		}
	}()

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
			record, err := f.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				// Continue on other errors
				continue
			}

			// Parse the raw event
			var rawEvent rawFsEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
				continue
			}

			// Convert to high-level event
			fsEvent := f.convertEvent(&rawEvent)

			// Update statistics
			f.updateStats(fsEvent)

			// Create raw collector event
			rawCollectorEvent := f.createRawEvent(fsEvent)

			// Send to collector's event channel
			select {
			case f.eventsChan <- rawCollectorEvent:
			case <-f.ctx.Done():
				return
			default:
				// Drop event if channel is full
				f.mu.Lock()
				// Could track dropped events here
				f.mu.Unlock()
			}
		}
	}
}

// convertEvent converts raw BPF event to structured FileSystemEvent
func (f *FileSystemMonitor) convertEvent(raw *rawFsEvent) *FileSystemEvent {
	event := &FileSystemEvent{
		Timestamp:      time.Unix(0, int64(raw.Timestamp)),
		PID:            raw.PID,
		TID:            raw.TID,
		UID:            raw.UID,
		Operation:      f.operationToString(raw.Operation),
		FileDescriptor: raw.FD,
		ReturnCode:     raw.RetCode,
		LatencyNs:      raw.LatencyNs,
		BytesRequested: raw.BytesRequested,
		BytesActual:    raw.BytesActual,
		ProcessName:    f.extractString(raw.Comm[:]),
		Filename:       f.extractString(raw.Filename[:]),
		FullPath:       f.extractString(raw.FullPath[:]),
	}

	// Determine severity based on latency
	latency := time.Duration(raw.LatencyNs)
	if latency >= f.config.Thresholds.Critical {
		event.Severity = "critical"
	} else if latency >= f.config.Thresholds.Warning {
		event.Severity = "warning"
	} else {
		event.Severity = "info"
	}

	return event
}

// createRawEvent creates a RawEvent for the collector pipeline
func (f *FileSystemMonitor) createRawEvent(fsEvent *FileSystemEvent) collectors.RawEvent {
	// Create structured data
	data := map[string]interface{}{
		"timestamp":       fsEvent.Timestamp,
		"pid":             fsEvent.PID,
		"tid":             fsEvent.TID,
		"uid":             fsEvent.UID,
		"operation":       fsEvent.Operation,
		"file_descriptor": fsEvent.FileDescriptor,
		"return_code":     fsEvent.ReturnCode,
		"latency_ns":      fsEvent.LatencyNs,
		"latency_ms":      float64(fsEvent.LatencyNs) / 1e6,
		"bytes_requested": fsEvent.BytesRequested,
		"bytes_actual":    fsEvent.BytesActual,
		"process_name":    fsEvent.ProcessName,
		"filename":        fsEvent.Filename,
		"full_path":       fsEvent.FullPath,
		"severity":        fsEvent.Severity,
	}

	// Serialize data
	jsonData, _ := json.Marshal(data)

	// Create metadata
	metadata := map[string]string{
		"collector":    "kubelet",
		"event_type":   "filesystem_io",
		"operation":    fsEvent.Operation,
		"process_name": fsEvent.ProcessName,
		"severity":     fsEvent.Severity,
		"latency_ms":   fmt.Sprintf("%.2f", float64(fsEvent.LatencyNs)/1e6),
		"filename":     fsEvent.Filename,
	}

	// Add K8s context if this is a volume path
	if f.isVolumePath(fsEvent.FullPath) {
		metadata["k8s_volume_path"] = "true"
		if namespace, podName := f.extractPodInfo(fsEvent.FullPath); namespace != "" {
			metadata["k8s_namespace"] = namespace
			metadata["k8s_name"] = podName
			metadata["k8s_kind"] = "Pod"
		}
	}

	return collectors.RawEvent{
		Timestamp: time.Now(),
		Type:      "kubelet_filesystem",
		Data:      jsonData,
		Metadata:  metadata,
		TraceID:   collectors.GenerateTraceID(),
		SpanID:    collectors.GenerateSpanID(),
	}
}

// updateStats updates internal statistics
func (f *FileSystemMonitor) updateStats(event *FileSystemEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.stats.EventsProcessed++
	f.stats.LastEventTime = event.Timestamp

	// Update operation counts
	switch event.Operation {
	case "read":
		f.stats.ReadOperations++
	case "write":
		f.stats.WriteOperations++
	case "open":
		f.stats.OpenOperations++
	case "sync":
		f.stats.SyncOperations++
	case "close":
		f.stats.CloseOperations++
	}

	// Update latency statistics
	latency := event.LatencyNs
	if latency > f.stats.MaxLatencyNs {
		f.stats.MaxLatencyNs = latency
	}

	// Update running average (simple moving average)
	if f.stats.EventsProcessed == 1 {
		f.stats.AverageLatencyNs = latency
	} else {
		f.stats.AverageLatencyNs = ((f.stats.AverageLatencyNs * (f.stats.EventsProcessed - 1)) + latency) / f.stats.EventsProcessed
	}

	// Count slow operations
	if time.Duration(latency) >= f.config.Thresholds.Warning {
		f.stats.SlowOperations++
	}
	if time.Duration(latency) >= f.config.Thresholds.Critical {
		f.stats.VerySlowOps++
	}
}

// Helper methods

func (f *FileSystemMonitor) operationToString(op uint8) string {
	switch op {
	case 1:
		return "open"
	case 2:
		return "read"
	case 3:
		return "write"
	case 4:
		return "sync"
	case 5:
		return "close"
	default:
		return "unknown"
	}
}

func (f *FileSystemMonitor) extractString(data []byte) string {
	// Find null terminator
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

func (f *FileSystemMonitor) isVolumePath(path string) bool {
	volumePaths := []string{
		"/var/lib/kubelet",
		"/var/lib/containers",
		"/run/containers",
		"/var/lib/docker",
	}

	for _, prefix := range volumePaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (f *FileSystemMonitor) extractPodInfo(path string) (namespace, podName string) {
	// Parse kubelet volume paths to extract pod information
	// Example: /var/lib/kubelet/pods/{pod-uid}/volumes/...
	// Example: /var/lib/kubelet/pods/{pod-uid}/containers/{container}/...

	if !strings.HasPrefix(path, "/var/lib/kubelet/pods/") {
		return "", ""
	}

	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		return "", ""
	}

	podUID := parts[4] // The pod UID
	// In a real implementation, you'd look up the pod UID to get namespace/name
	// For now, we'll extract what we can from the path structure

	// This is a simplified extraction - in production you'd maintain a pod UID -> metadata mapping
	return "default", fmt.Sprintf("pod-%s", podUID[:8])
}

func (f *FileSystemMonitor) cleanup() {
	if f.reader != nil {
		f.reader.Close()
	}

	for _, l := range f.links {
		l.Close()
	}
	f.links = nil

	if f.objs != nil {
		f.objs.Close()
	}
}

// GetStats returns current filesystem monitoring statistics
func (f *FileSystemMonitor) GetStats() FileSystemStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.stats
}

// Helper function to convert bool to uint32 for BPF
func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
