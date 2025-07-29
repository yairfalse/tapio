//go:build darwin
// +build darwin

package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DarwinPlatform implements Platform for macOS/Darwin systems
type DarwinPlatform struct{}

// NewDarwinPlatform creates a new Darwin platform implementation
func NewDarwinPlatform() Platform {
	return &DarwinPlatform{}
}

// GetCNIConfigPaths returns Darwin CNI configuration paths
func (p *DarwinPlatform) GetCNIConfigPaths() []string {
	home := os.Getenv("HOME")
	return []string{
		"/etc/cni/net.d",
		"/opt/cni/conf",
		fmt.Sprintf("%s/.cni/net.d", home),
		"/tmp/cni/conf", // For testing
		"/var/run/cni/conf",
	}
}

// GetCNIBinaryPaths returns Darwin CNI binary paths
func (p *DarwinPlatform) GetCNIBinaryPaths() []string {
	return []string{
		"/opt/cni/bin",
		"/usr/local/bin",
		"/usr/local/opt/cni/bin",
		"/opt/homebrew/bin",
	}
}

// GetIPAMDataPaths returns Darwin IPAM data storage paths
func (p *DarwinPlatform) GetIPAMDataPaths() []string {
	home := os.Getenv("HOME")
	return []string{
		"/var/lib/cni/networks",
		"/tmp/cni/networks",
		fmt.Sprintf("%s/.cni/networks", home),
		"/var/run/cni/ipam",
	}
}

// GetLogPaths returns Darwin CNI log paths
func (p *DarwinPlatform) GetLogPaths() []string {
	home := os.Getenv("HOME")
	return []string{
		"/var/log/containers",
		"/var/log/pods",
		fmt.Sprintf("%s/Library/Logs/cni", home),
		"/tmp/cni/logs",
		"/var/log/system.log",
	}
}

// GetNetworkNamespacePath returns empty on Darwin (no network namespaces)
func (p *DarwinPlatform) GetNetworkNamespacePath(containerID string) string {
	// macOS doesn't have Linux-style network namespaces
	// Docker/containerd on Mac runs in a VM
	return ""
}

// IsEBPFSupported returns false on Darwin
func (p *DarwinPlatform) IsEBPFSupported() bool {
	// eBPF is Linux-specific
	return false
}

// IsInotifySupported returns true on Darwin (uses FSEvents)
func (p *DarwinPlatform) IsInotifySupported() bool {
	// fsnotify library handles FSEvents on macOS
	return true
}

// GetProcessMonitor returns a Darwin process monitor
func (p *DarwinPlatform) GetProcessMonitor() ProcessMonitor {
	return &DarwinProcessMonitor{}
}

// GetFileWatcher returns a Darwin file watcher
func (p *DarwinPlatform) GetFileWatcher() FileWatcher {
	return &DarwinFileWatcher{
		events: make(chan FileEvent, 100),
	}
}

// DarwinProcessMonitor implements ProcessMonitor for Darwin
type DarwinProcessMonitor struct{}

// ListCNIProcesses lists running CNI plugin processes on Darwin
func (m *DarwinProcessMonitor) ListCNIProcesses(ctx context.Context) ([]ProcessInfo, error) {
	processes := []ProcessInfo{}

	// Use ps command to list processes
	cmd := exec.CommandContext(ctx, "ps", "-eo", "pid,comm,args,lstart,%cpu,rss")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	cniPlugins := getCNIPluginNames()

	for i, line := range lines {
		if i == 0 || line == "" { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		comm := fields[1]

		// Check if it's a CNI plugin
		for _, plugin := range cniPlugins {
			if strings.Contains(comm, plugin) || strings.Contains(line, plugin) {
				// Parse start time (Darwin ps format: Day Mon DD HH:MM:SS YYYY)
				startTimeStr := strings.Join(fields[3:7], " ")
				startTime, _ := time.Parse("Mon Jan 2 15:04:05 2006", startTimeStr)

				cpuUsage, _ := strconv.ParseFloat(fields[7], 64)
				memUsage, _ := strconv.ParseInt(fields[8], 10, 64)

				info := ProcessInfo{
					PID:         pid,
					Name:        plugin,
					CommandLine: strings.Join(fields[2:], " "),
					StartTime:   startTime,
					CPUUsage:    cpuUsage,
					MemoryUsage: memUsage * 1024, // Convert from KB to bytes
				}

				processes = append(processes, info)
				break
			}
		}
	}

	return processes, nil
}

// WatchProcess watches for process execution on Darwin
func (m *DarwinProcessMonitor) WatchProcess(ctx context.Context, processName string) (<-chan ProcessEvent, error) {
	events := make(chan ProcessEvent, 100)

	// Darwin doesn't have a direct equivalent to Linux's proc connector
	// We'll use polling with ps command
	go func() {
		defer close(events)

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		knownPIDs := make(map[int]bool)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				processes, err := m.ListCNIProcesses(ctx)
				if err != nil {
					continue
				}

				// Check for new processes
				for _, proc := range processes {
					if proc.Name == processName && !knownPIDs[proc.PID] {
						knownPIDs[proc.PID] = true
						events <- ProcessEvent{
							Type:      "start",
							PID:       proc.PID,
							Name:      proc.Name,
							Timestamp: time.Now(),
						}
					}
				}

				// Check for terminated processes
				for pid := range knownPIDs {
					found := false
					for _, proc := range processes {
						if proc.PID == pid {
							found = true
							break
						}
					}
					if !found {
						delete(knownPIDs, pid)
						events <- ProcessEvent{
							Type:      "stop",
							PID:       pid,
							Name:      processName,
							Timestamp: time.Now(),
						}
					}
				}
			}
		}
	}()

	return events, nil
}

// GetProcessDetails gets detailed information about a Darwin process
func (m *DarwinProcessMonitor) GetProcessDetails(pid int) (*ProcessDetails, error) {
	details := &ProcessDetails{
		ProcessInfo: ProcessInfo{PID: pid},
		Environment: make(map[string]string),
	}

	// Use ps to get basic info
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=,args=")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(output))
	if len(fields) > 0 {
		details.Name = fields[0]
		details.CommandLine = strings.Join(fields, " ")
	}

	// Get environment using ps
	envCmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-E")
	if envOutput, err := envCmd.Output(); err == nil {
		lines := strings.Split(string(envOutput), "\n")
		for _, line := range lines {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				details.Environment[parts[0]] = parts[1]
			}
		}
	}

	// Get open files using lsof
	lsofCmd := exec.Command("lsof", "-p", strconv.Itoa(pid))
	if lsofOutput, err := lsofCmd.Output(); err == nil {
		lines := strings.Split(string(lsofOutput), "\n")
		for i, line := range lines {
			if i == 0 || line == "" { // Skip header
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 9 {
				details.OpenFiles = append(details.OpenFiles, fields[8])
			}
		}
	}

	// Get network connections using netstat
	netstatCmd := exec.Command("netstat", "-anp", "tcp")
	if netstatOutput, err := netstatCmd.Output(); err == nil {
		lines := strings.Split(string(netstatOutput), "\n")
		for _, line := range lines {
			if strings.Contains(line, strconv.Itoa(pid)) {
				fields := strings.Fields(line)
				if len(fields) >= 6 {
					conn := ConnectionInfo{
						Protocol:   fields[0],
						LocalAddr:  fields[3],
						RemoteAddr: fields[4],
						State:      fields[5],
					}
					details.Connections = append(details.Connections, conn)
				}
			}
		}
	}

	return details, nil
}

// DarwinFileWatcher implements FileWatcher using FSEvents
type DarwinFileWatcher struct {
	watcher *fsnotify.Watcher
	events  chan FileEvent
}

// Watch starts watching a file or directory on Darwin
func (w *DarwinFileWatcher) Watch(path string) error {
	if w.watcher == nil {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return err
		}
		w.watcher = watcher

		// Start event processing
		go w.processEvents()
	}

	return w.watcher.Add(path)
}

// Events returns the channel for file events
func (w *DarwinFileWatcher) Events() <-chan FileEvent {
	return w.events
}

// Stop stops the Darwin file watcher
func (w *DarwinFileWatcher) Stop() error {
	if w.watcher != nil {
		close(w.events)
		return w.watcher.Close()
	}
	return nil
}

// processEvents processes FSEvents
func (w *DarwinFileWatcher) processEvents() {
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			fileEvent := FileEvent{
				Path:      event.Name,
				Timestamp: time.Now(),
			}

			switch {
			case event.Op&fsnotify.Create == fsnotify.Create:
				fileEvent.Operation = "create"
			case event.Op&fsnotify.Write == fsnotify.Write:
				fileEvent.Operation = "modify"
			case event.Op&fsnotify.Remove == fsnotify.Remove:
				fileEvent.Operation = "delete"
			case event.Op&fsnotify.Rename == fsnotify.Rename:
				fileEvent.Operation = "rename"
			}

			// Check if it's a directory
			if info, err := os.Stat(event.Name); err == nil {
				fileEvent.IsDir = info.IsDir()
			}

			w.events <- fileEvent

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			// Log error but continue
			_ = err
		}
	}
}

// Helper functions

func getCNIPluginNames() []string {
	return []string{
		"bridge", "calico", "cilium", "flannel", "weave",
		"macvlan", "ipvlan", "host-local", "dhcp", "portmap",
		"bandwidth", "tuning", "vlan", "firewall", "sbr",
	}
}
