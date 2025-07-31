package k8s

import (
	"github.com/yairfalse/tapio/pkg/collectors"
)

// DefaultK8sConfig returns default configuration for K8s collector
func DefaultK8sConfig() collectors.CollectorConfig {
	return collectors.CollectorConfig{
		Name:       "k8s-minimal",
		BufferSize: 1000,
		Labels: map[string]string{
			"collector": "k8s",
			"version":   "1.0.0",
		},
	}
}