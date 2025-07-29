//go:build linux
// +build linux

package platform

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LinuxPlatform implements Platform for Linux systems
type LinuxPlatform struct{}

// NewLinuxPlatform creates a new Linux platform implementation
func NewLinuxPlatform() Platform {
	return &LinuxPlatform{}
}

// GetCNIConfigPaths returns Linux CNI configuration paths
func (p *LinuxPlatform) GetCNIConfigPaths() []string {
	return []string{
		"/etc/cni/net.d",
		"/etc/cni/conf.d",
		"/opt/cni/conf",
		"/var/lib/cni/conf",
		"/run/flannel",
		"/etc/kubernetes/cni/net.d",
	}
}

// GetCNIBinaryPaths returns Linux CNI binary paths
func (p *LinuxPlatform) GetCNIBinaryPaths() []string {
	return []string{
		"/opt/cni/bin",
		"/usr/libexec/cni",
		"/var/lib/cni/bin",
		"/usr/local/bin",
	}
}

// GetIPAMDataPaths returns Linux IPAM data storage paths
func (p *LinuxPlatform) GetIPAMDataPaths() []string {
	return []string{
		"/var/lib/cni/networks",
		"/var/lib/cni/ipam",
		"/var/run/cni/ipam",
		"/tmp/cni/networks",
	}
}

// GetLogPaths returns Linux CNI log paths
func (p *LinuxPlatform) GetLogPaths() []string {
	return []string{
		"/var/log/pods",
		"/var/log/containers",
		"/var/log/calico/cni",
		"/var/log/cilium-cni.log",
		"/var/log/flannel",
		"/var/log/messages",
		"/var/log/syslog",
	}
}

// GetNetworkNamespacePath returns the Linux network namespace path
func (p *LinuxPlatform) GetNetworkNamespacePath(containerID string) string {
	// Try different container runtime paths
	paths := []string{
		fmt.Sprintf("/var/run/netns/cni-%s", containerID),
		fmt.Sprintf("/var/run/docker/netns/%s", containerID),
		fmt.Sprintf("/var/run/containerd/netns/%s", containerID),
		fmt.Sprintf("/proc/%s/ns/net", containerID),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// IsEBPFSupported checks if eBPF is supported on Linux
func (p *LinuxPlatform) IsEBPFSupported() bool {
	// Check kernel version
	if kversion, err := getKernelVersion(); err == nil {
		// eBPF is well supported in kernel 4.x+
		major, minor := parseKernelVersion(kversion)
		if major >= 4 {
			return true
		}
	}

	// Check for BPF filesystem
	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		return true
	}

	return false
}

// IsInotifySupported checks if inotify is supported on Linux
func (p *LinuxPlatform) IsInotifySupported() bool {
	// inotify is supported on all modern Linux systems
	// Check for inotify syscalls availability
	return true
}

// GetProcessMonitor returns a Linux process monitor
func (p *LinuxPlatform) GetProcessMonitor() ProcessMonitor {
	return &LinuxProcessMonitor{}
}

// GetFileWatcher returns a Linux file watcher
func (p *LinuxPlatform) GetFileWatcher() FileWatcher {
	return &LinuxFileWatcher{
		events: make(chan FileEvent, 100),
	}
}

// LinuxProcessMonitor implements ProcessMonitor for Linux
type LinuxProcessMonitor struct{}

// ListCNIProcesses lists running CNI plugin processes on Linux
func (m *LinuxProcessMonitor) ListCNIProcesses(ctx context.Context) ([]ProcessInfo, error) {
	processes := []ProcessInfo{}

	// Read /proc directory
	procDirs, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	cniPlugins := getCNIPluginNames()

	for _, dir := range procDirs {
		if !dir.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}

		// Read command line
		cmdline, err := readProcFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}

		// Check if it's a CNI plugin
		for _, plugin := range cniPlugins {
			if strings.Contains(cmdline, plugin) {
				info := ProcessInfo{
					PID:         pid,
					Name:        plugin,
					CommandLine: cmdline,
				}

				// Get start time
				if stat, err := readProcStat(pid); err == nil {
					info.StartTime = stat.StartTime
					info.CPUUsage = stat.CPUUsage
				}

				// Get memory usage
				if status, err := readProcStatus(pid); err == nil {
					info.MemoryUsage = status.VmRSS
				}

				processes = append(processes, info)
				break
			}
		}
	}

	return processes, nil
}

// WatchProcess watches for process execution on Linux
func (m *LinuxProcessMonitor) WatchProcess(ctx context.Context, processName string) (<-chan ProcessEvent, error) {
	events := make(chan ProcessEvent, 100)

	// In a real implementation, this would use:
	// - netlink proc connector
	// - eBPF tracepoints
	// - audit subsystem
	// For now, we'll use polling as a fallback

	go func() {
		defer close(events)

		ticker := time.NewTicker(1 * time.Second)
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

// GetProcessDetails gets detailed information about a Linux process
func (m *LinuxProcessMonitor) GetProcessDetails(pid int) (*ProcessDetails, error) {
	details := &ProcessDetails{
		ProcessInfo: ProcessInfo{PID: pid},
		Environment: make(map[string]string),
	}

	// Read basic info
	cmdline, err := readProcFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	details.CommandLine = cmdline

	// Read environment
	environ, err := readProcFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err == nil {
		for _, env := range strings.Split(environ, "\x00") {
			if parts := strings.SplitN(env, "=", 2); len(parts) == 2 {
				details.Environment[parts[0]] = parts[1]
			}
		}
	}

	// Read working directory
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		details.WorkingDir = cwd
	}

	// Read network namespace
	if netns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid)); err == nil {
		details.NetworkNS = netns
	}

	// Read open files
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	if fds, err := ioutil.ReadDir(fdDir); err == nil {
		for _, fd := range fds {
			if link, err := os.Readlink(filepath.Join(fdDir, fd.Name())); err == nil {
				details.OpenFiles = append(details.OpenFiles, link)
			}
		}
	}

	// Read network connections
	details.Connections = readNetworkConnections(pid)

	return details, nil
}

// LinuxFileWatcher implements FileWatcher using inotify
type LinuxFileWatcher struct {
	watcher *fsnotify.Watcher
	events  chan FileEvent
}

// Watch starts watching a file or directory on Linux
func (w *LinuxFileWatcher) Watch(path string) error {
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
func (w *LinuxFileWatcher) Events() <-chan FileEvent {
	return w.events
}

// Stop stops the Linux file watcher
func (w *LinuxFileWatcher) Stop() error {
	if w.watcher != nil {
		close(w.events)
		return w.watcher.Close()
	}
	return nil
}

// processEvents processes inotify events
func (w *LinuxFileWatcher) processEvents() {
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

func getKernelVersion() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", err
	}

	release := make([]byte, 0, len(uname.Release))
	for _, b := range uname.Release {
		if b == 0 {
			break
		}
		release = append(release, byte(b))
	}

	return string(release), nil
}

func parseKernelVersion(version string) (major, minor int) {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		major, _ = strconv.Atoi(parts[0])
		minor, _ = strconv.Atoi(parts[1])
	}
	return
}

func getCNIPluginNames() []string {
	return []string{
		"bridge", "calico", "cilium", "flannel", "weave",
		"macvlan", "ipvlan", "host-local", "dhcp", "portmap",
		"bandwidth", "tuning", "vlan", "firewall", "sbr",
	}
}

func readProcFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

type procStat struct {
	StartTime time.Time
	CPUUsage  float64
}

func readProcStat(pid int) (*procStat, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}

	// Parse stat file (simplified)
	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return nil, fmt.Errorf("invalid stat format")
	}

	// Field 22 is start time in clock ticks since boot
	startTicks, _ := strconv.ParseInt(fields[21], 10, 64)

	// Get system boot time
	bootTime := getBootTime()

	return &procStat{
		StartTime: bootTime.Add(time.Duration(startTicks) * time.Second / 100),
		CPUUsage:  0.0, // Would need to calculate from utime/stime
	}, nil
}

type procStatus struct {
	VmRSS int64
}

func readProcStatus(pid int) (*procStatus, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	status := &procStatus{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				status.VmRSS = value * 1024 // Convert from KB to bytes
			}
		}
	}

	return status, nil
}

func getBootTime() time.Time {
	// Read from /proc/stat
	file, err := os.Open("/proc/stat")
	if err != nil {
		return time.Now().Add(-1 * time.Hour) // Fallback
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				btime, _ := strconv.ParseInt(fields[1], 10, 64)
				return time.Unix(btime, 0)
			}
		}
	}

	return time.Now().Add(-1 * time.Hour) // Fallback
}

func readNetworkConnections(pid int) []ConnectionInfo {
	connections := []ConnectionInfo{}

	// Read TCP connections from /proc/pid/net/tcp
	// This is simplified - real implementation would parse the hex addresses

	return connections
}
