package dns

import "time"

// Config holds configuration for DNS collector
type Config struct {
	// Buffer size for events channel
	BufferSize int `json:"buffer_size"`

	// Enable eBPF monitoring
	EnableEBPF bool `json:"enable_ebpf"`

	// Network interfaces to monitor (empty = all)
	Interfaces []string `json:"interfaces"`

	// DNS servers to monitor (for correlation)
	DNSServers []string `json:"dns_servers"`

	// Failure threshold settings
	FailureThreshold struct {
		// Maximum acceptable response time (ms)
		ResponseTimeMs int `json:"response_time_ms"`

		// Consecutive failures before alert
		ConsecutiveFailures int `json:"consecutive_failures"`

		// Time window for failure rate calculation
		WindowDuration time.Duration `json:"window_duration"`
	} `json:"failure_threshold"`

	// Query correlation settings
	QueryCorrelation struct {
		// Maximum time to wait for DNS response correlation
		CorrelationTimeout time.Duration `json:"correlation_timeout"`

		// Maximum number of pending queries to track
		MaxPendingQueries int `json:"max_pending_queries"`
	} `json:"query_correlation"`

	// Filtering options
	Filters struct {
		// Only monitor specific domains (empty = monitor all)
		Domains []string `json:"domains"`

		// Ignore internal/localhost queries
		IgnoreLocal bool `json:"ignore_local"`

		// Monitor only specific DNS record types
		RecordTypes []string `json:"record_types"` // A, AAAA, CNAME, MX, etc.
	} `json:"filters"`
}

// DefaultConfig returns default configuration for DNS collector
func DefaultConfig() Config {
	config := Config{
		BufferSize: 10000,
		EnableEBPF: true,
		Interfaces: []string{}, // Monitor all interfaces
		DNSServers: []string{
			"8.8.8.8",
			"8.8.4.4",
			"1.1.1.1",
			"1.0.0.1",
		},
	}

	// Set failure threshold defaults
	config.FailureThreshold.ResponseTimeMs = 5000 // 5 seconds
	config.FailureThreshold.ConsecutiveFailures = 3
	config.FailureThreshold.WindowDuration = 5 * time.Minute

	// Set correlation defaults
	config.QueryCorrelation.CorrelationTimeout = 30 * time.Second
	config.QueryCorrelation.MaxPendingQueries = 10000

	// Set filter defaults
	config.Filters.Domains = []string{} // Monitor all domains
	config.Filters.IgnoreLocal = true
	config.Filters.RecordTypes = []string{} // Monitor all record types

	return config
}

// TLSConfig holds TLS configuration for DoH/DoT monitoring
type TLSConfig struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}
