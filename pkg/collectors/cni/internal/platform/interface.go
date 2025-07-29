package platform

import (
	"context"
	"time"
)

// Platform defines the interface for platform-specific operations
type Platform interface {
	// GetCNIConfigPaths returns platform-specific CNI configuration paths
	GetCNIConfigPaths() []string

	// GetCNIBinaryPaths returns platform-specific CNI binary paths
	GetCNIBinaryPaths() []string

	// GetIPAMDataPaths returns platform-specific IPAM data storage paths
	GetIPAMDataPaths() []string

	// GetLogPaths returns platform-specific CNI log paths
	GetLogPaths() []string

	// GetNetworkNamespacePath returns the path to network namespaces
	GetNetworkNamespacePath(containerID string) string

	// IsEBPFSupported checks if eBPF is supported on this platform
	IsEBPFSupported() bool

	// IsInotifySupported checks if inotify is supported on this platform
	IsInotifySupported() bool

	// GetProcessMonitor returns a platform-specific process monitor
	GetProcessMonitor() ProcessMonitor

	// GetFileWatcher returns a platform-specific file watcher
	GetFileWatcher() FileWatcher
}

// ProcessMonitor defines platform-specific process monitoring
type ProcessMonitor interface {
	// ListCNIProcesses lists running CNI plugin processes
	ListCNIProcesses(ctx context.Context) ([]ProcessInfo, error)

	// WatchProcess watches for process execution
	WatchProcess(ctx context.Context, processName string) (<-chan ProcessEvent, error)

	// GetProcessDetails gets detailed information about a process
	GetProcessDetails(pid int) (*ProcessDetails, error)
}

// ProcessInfo contains basic process information
type ProcessInfo struct {
	PID         int
	Name        string
	CommandLine string
	StartTime   time.Time
	CPUUsage    float64
	MemoryUsage int64
}

// ProcessEvent represents a process lifecycle event
type ProcessEvent struct {
	Type      string // "start", "stop", "exec"
	PID       int
	Name      string
	Timestamp time.Time
	ExitCode  int
	Duration  time.Duration
}

// ProcessDetails contains detailed process information
type ProcessDetails struct {
	ProcessInfo
	Environment map[string]string
	OpenFiles   []string
	Connections []ConnectionInfo
	Threads     int
	ParentPID   int
	WorkingDir  string
	NetworkNS   string
}

// ConnectionInfo represents network connection information
type ConnectionInfo struct {
	Protocol   string
	LocalAddr  string
	RemoteAddr string
	State      string
}

// FileWatcher defines platform-specific file watching
type FileWatcher interface {
	// Watch starts watching a file or directory
	Watch(path string) error

	// Events returns the channel for file events
	Events() <-chan FileEvent

	// Stop stops the file watcher
	Stop() error
}

// FileEvent represents a file system event
type FileEvent struct {
	Path      string
	Operation string // "create", "modify", "delete", "rename"
	Timestamp time.Time
	IsDir     bool
}
