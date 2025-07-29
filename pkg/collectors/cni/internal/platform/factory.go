package platform

import (
	"runtime"
)

// GetPlatform returns the appropriate platform implementation
func GetPlatform() Platform {
	switch runtime.GOOS {
	case "linux":
		return NewLinuxPlatform()
	case "darwin":
		return NewDarwinPlatform()
	case "windows":
		return NewWindowsPlatform()
	default:
		// Fallback to a generic platform
		return NewGenericPlatform()
	}
}

// NewGenericPlatform creates a generic platform implementation
func NewGenericPlatform() Platform {
	return &GenericPlatform{}
}

// GenericPlatform provides a fallback implementation
type GenericPlatform struct{}

// GetCNIConfigPaths returns generic CNI configuration paths
func (p *GenericPlatform) GetCNIConfigPaths() []string {
	return []string{
		"/etc/cni/net.d",
		"/opt/cni/conf",
	}
}

// GetCNIBinaryPaths returns generic CNI binary paths
func (p *GenericPlatform) GetCNIBinaryPaths() []string {
	return []string{
		"/opt/cni/bin",
		"/usr/local/bin",
	}
}

// GetIPAMDataPaths returns generic IPAM data storage paths
func (p *GenericPlatform) GetIPAMDataPaths() []string {
	return []string{
		"/var/lib/cni/networks",
	}
}

// GetLogPaths returns generic CNI log paths
func (p *GenericPlatform) GetLogPaths() []string {
	return []string{
		"/var/log/containers",
	}
}

// GetNetworkNamespacePath returns empty for generic platform
func (p *GenericPlatform) GetNetworkNamespacePath(containerID string) string {
	return ""
}

// IsEBPFSupported returns false for generic platform
func (p *GenericPlatform) IsEBPFSupported() bool {
	return false
}

// IsInotifySupported returns false for generic platform
func (p *GenericPlatform) IsInotifySupported() bool {
	return false
}

// GetProcessMonitor returns nil for generic platform
func (p *GenericPlatform) GetProcessMonitor() ProcessMonitor {
	return nil
}

// GetFileWatcher returns nil for generic platform
func (p *GenericPlatform) GetFileWatcher() FileWatcher {
	return nil
}
