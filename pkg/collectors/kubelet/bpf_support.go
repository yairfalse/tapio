package kubelet

import "github.com/yairfalse/tapio/pkg/collectors/kubelet/bpf"

// Export generated types for filesystem monitoring
type FsMonitorObjects = bpf.FsMonitorObjects
type FsMonitorMaps = bpf.FsMonitorMaps
type FsMonitorPrograms = bpf.FsMonitorPrograms

// Export the generated loader function
var LoadFsMonitorObjects = bpf.LoadFsMonitorObjects
