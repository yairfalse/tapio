package dns

import (
	"fmt"

	"github.com/yairfalse/tapio/pkg/collectors"
	"github.com/yairfalse/tapio/pkg/collectors/registry"
)

func init() {
	// Register the DNS collector factory
	registry.MustRegister("dns", NewCollectorFromConfig)
}

// NewCollectorFromConfig creates a new DNS collector from configuration
func NewCollectorFromConfig(config map[string]interface{}) (collectors.Collector, error) {
	// Get name from config or use default
	name := "dns"
	if n, ok := config["name"].(string); ok {
		name = n
	}

	// Parse DNS config
	dnsConfig := DefaultConfig()

	// Parse buffer size
	if bufferSize, ok := config["buffer_size"].(float64); ok {
		dnsConfig.BufferSize = int(bufferSize)
	}

	// Parse enable eBPF
	if enableEBPF, ok := config["enable_ebpf"].(bool); ok {
		dnsConfig.EnableEBPF = enableEBPF
	}

	// Parse interfaces
	if interfaces, ok := config["interfaces"].([]interface{}); ok {
		dnsConfig.Interfaces = []string{}
		for _, iface := range interfaces {
			if ifaceStr, ok := iface.(string); ok {
				dnsConfig.Interfaces = append(dnsConfig.Interfaces, ifaceStr)
			}
		}
	}

	// Parse DNS servers
	if dnsServers, ok := config["dns_servers"].([]interface{}); ok {
		dnsConfig.DNSServers = []string{}
		for _, server := range dnsServers {
			if serverStr, ok := server.(string); ok {
				dnsConfig.DNSServers = append(dnsConfig.DNSServers, serverStr)
			}
		}
	}

	// Parse failure threshold settings
	if threshold, ok := config["failure_threshold"].(map[string]interface{}); ok {
		if responseTime, ok := threshold["response_time_ms"].(float64); ok {
			dnsConfig.FailureThreshold.ResponseTimeMs = int(responseTime)
		}
		if consecutiveFailures, ok := threshold["consecutive_failures"].(float64); ok {
			dnsConfig.FailureThreshold.ConsecutiveFailures = int(consecutiveFailures)
		}
	}

	// Parse filters
	if filters, ok := config["filters"].(map[string]interface{}); ok {
		if domains, ok := filters["domains"].([]interface{}); ok {
			dnsConfig.Filters.Domains = []string{}
			for _, domain := range domains {
				if domainStr, ok := domain.(string); ok {
					dnsConfig.Filters.Domains = append(dnsConfig.Filters.Domains, domainStr)
				}
			}
		}
		if ignoreLocal, ok := filters["ignore_local"].(bool); ok {
			dnsConfig.Filters.IgnoreLocal = ignoreLocal
		}
	}

	// Create DNS collector with config
	collector, err := NewCollector(name, dnsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS collector: %w", err)
	}

	return collector, nil
}
