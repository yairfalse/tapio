package bpf

import "runtime"

// IsSupported checks if eBPF is supported on this platform
func IsSupported() bool {
	// eBPF is only supported on Linux
	return runtime.GOOS == "linux"
}

// Export generated types for CNI monitoring
type CniMonitorObjects = cniMonitorObjects

// Export the generated loader function
var LoadCniMonitorObjects = loadCniMonitorObjects
