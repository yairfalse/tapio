package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors"
)

// Collector implements DNS resolution failure monitoring
type Collector struct {
	name      string
	config    Config
	events    chan collectors.RawEvent
	ctx       context.Context
	cancel    context.CancelFunc
	healthy   bool
	mu        sync.RWMutex
	ebpfState interface{} // Platform-specific eBPF state

	// Statistics
	stats CollectorStats

	// Query correlation tracking
	pendingQueries   map[string]*PendingQuery
	pendingQueriesMu sync.RWMutex

	// DNS failure tracking
	failureTracker   map[string]*FailureStats
	failureTrackerMu sync.RWMutex
}

// CollectorStats tracks collector statistics
type CollectorStats struct {
	QueriesTracked   uint64
	ResponsesTracked uint64
	FailuresDetected uint64
	TimeoutsDetected uint64
	ErrorsDetected   uint64
	LastEventTime    time.Time
}

// PendingQuery represents a DNS query waiting for response
type PendingQuery struct {
	TransactionID uint16
	QueryName     string
	QueryType     string
	SourceIP      string
	DestinationIP string
	Port          uint16
	Timestamp     time.Time
	ProcessID     uint32
	ThreadID      uint32
}

// FailureStats tracks DNS failure patterns for a domain
type FailureStats struct {
	Domain              string
	ConsecutiveFailures int
	TotalQueries        int
	FailedQueries       int
	LastFailureTime     time.Time
	LastSuccessTime     time.Time
	AverageResponseTime time.Duration
}

// NewCollector creates a new DNS collector
func NewCollector(name string, config Config) (*Collector, error) {
	return &Collector{
		name:           name,
		config:         config,
		events:         make(chan collectors.RawEvent, config.BufferSize),
		healthy:        true,
		pendingQueries: make(map[string]*PendingQuery),
		failureTracker: make(map[string]*FailureStats),
	}, nil
}

// Name returns collector name
func (c *Collector) Name() string {
	return c.name
}

// Start begins collection
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx != nil {
		return fmt.Errorf("collector already started")
	}

	c.ctx, c.cancel = context.WithCancel(ctx)

	// Start eBPF monitoring if enabled
	if c.config.EnableEBPF {
		if err := c.startEBPF(); err != nil {
			// Log error but don't fail - can fallback to other methods
			fmt.Printf("[WARN] DNS collector: eBPF monitoring failed to start: %v (falling back to other methods)\n", err)
		}
	}

	// Start query correlation cleanup
	go c.cleanupExpiredQueries()

	// Start failure analysis
	go c.analyzeFailurePatterns()

	c.healthy = true
	return nil
}

// Stop gracefully shuts down
func (c *Collector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}

	// Stop eBPF if running
	c.stopEBPF()

	// Close events channel
	if c.events != nil {
		close(c.events)
		c.events = nil
	}

	c.healthy = false
	return nil
}

// Events returns the event channel
func (c *Collector) Events() <-chan collectors.RawEvent {
	return c.events
}

// IsHealthy returns health status
func (c *Collector) IsHealthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

// processDNSFailure processes a DNS failure event from eBPF
func (c *Collector) processDNSFailure(dnsEvent *DNSEvent) {
	c.mu.Lock()
	c.stats.ErrorsDetected++
	c.stats.LastEventTime = time.Now()
	c.mu.Unlock()

	// Update failure tracking
	c.updateFailureStats(dnsEvent)

	// Create metadata with full K8s context
	metadata := map[string]string{
		"collector":      "dns",
		"event_type":     "dns_failure",
		"query_name":     dnsEvent.QueryName,
		"dns_rcode":      fmt.Sprintf("%d", dnsEvent.ResponseCode),
		"dns_rcode_name": c.getRCodeName(dnsEvent.ResponseCode),
		"src_ip":         dnsEvent.SourceIP,
		"dst_ip":         dnsEvent.DestinationIP,
		"protocol":       c.getProtocolName(dnsEvent.Protocol),
		"src_port":       fmt.Sprintf("%d", dnsEvent.SourcePort),
		"dst_port":       fmt.Sprintf("%d", dnsEvent.DestinationPort),
		"process_id":     fmt.Sprintf("%d", dnsEvent.ProcessID),
		"thread_id":      fmt.Sprintf("%d", dnsEvent.ThreadID),
	}

	// Add K8s metadata if available (would need integration with K8s API)
	if k8sMetadata := c.extractK8sMetadata(dnsEvent.ProcessID); k8sMetadata != nil {
		for k, v := range k8sMetadata {
			metadata[k] = v
		}
	}

	// Create event data
	eventData := map[string]interface{}{
		"timestamp":        dnsEvent.Timestamp,
		"query_name":       dnsEvent.QueryName,
		"response_code":    dnsEvent.ResponseCode,
		"response_name":    c.getRCodeName(dnsEvent.ResponseCode),
		"source_ip":        dnsEvent.SourceIP,
		"destination_ip":   dnsEvent.DestinationIP,
		"protocol":         c.getProtocolName(dnsEvent.Protocol),
		"source_port":      dnsEvent.SourcePort,
		"destination_port": dnsEvent.DestinationPort,
		"process_id":       dnsEvent.ProcessID,
		"thread_id":        dnsEvent.ThreadID,
		"dns_flags":        dnsEvent.Flags,
		"dns_opcode":       dnsEvent.Opcode,
		"query_data":       dnsEvent.RawData,
	}

	// Create raw event
	jsonData, _ := json.Marshal(eventData)
	rawEvent := collectors.RawEvent{
		Timestamp: time.Now(),
		Type:      "dns_failure",
		Data:      jsonData,
		Metadata:  metadata,
		TraceID:   collectors.GenerateTraceID(),
		SpanID:    collectors.GenerateSpanID(),
	}

	// Send event
	select {
	case c.events <- rawEvent:
	case <-c.ctx.Done():
		return
	default:
		// Buffer full, drop event
	}
}

// processDNSTimeout processes DNS query timeouts
func (c *Collector) processDNSTimeout(pendingQuery *PendingQuery) {
	c.mu.Lock()
	c.stats.TimeoutsDetected++
	c.stats.LastEventTime = time.Now()
	c.mu.Unlock()

	// Create metadata
	metadata := map[string]string{
		"collector":  "dns",
		"event_type": "dns_timeout",
		"query_name": pendingQuery.QueryName,
		"query_type": pendingQuery.QueryType,
		"src_ip":     pendingQuery.SourceIP,
		"dst_ip":     pendingQuery.DestinationIP,
		"src_port":   fmt.Sprintf("%d", pendingQuery.Port),
		"process_id": fmt.Sprintf("%d", pendingQuery.ProcessID),
		"thread_id":  fmt.Sprintf("%d", pendingQuery.ThreadID),
		"timeout_ms": fmt.Sprintf("%d", c.config.FailureThreshold.ResponseTimeMs),
	}

	// Add K8s metadata
	if k8sMetadata := c.extractK8sMetadata(pendingQuery.ProcessID); k8sMetadata != nil {
		for k, v := range k8sMetadata {
			metadata[k] = v
		}
	}

	// Create event data
	eventData := map[string]interface{}{
		"timestamp":        time.Now(),
		"query_name":       pendingQuery.QueryName,
		"query_type":       pendingQuery.QueryType,
		"source_ip":        pendingQuery.SourceIP,
		"destination_ip":   pendingQuery.DestinationIP,
		"port":             pendingQuery.Port,
		"process_id":       pendingQuery.ProcessID,
		"thread_id":        pendingQuery.ThreadID,
		"timeout_duration": time.Since(pendingQuery.Timestamp),
		"query_timestamp":  pendingQuery.Timestamp,
	}

	// Create raw event
	jsonData, _ := json.Marshal(eventData)
	rawEvent := collectors.RawEvent{
		Timestamp: time.Now(),
		Type:      "dns_timeout",
		Data:      jsonData,
		Metadata:  metadata,
		TraceID:   collectors.GenerateTraceID(),
		SpanID:    collectors.GenerateSpanID(),
	}

	// Send event
	select {
	case c.events <- rawEvent:
	case <-c.ctx.Done():
		return
	default:
		// Buffer full, drop event
	}
}

// updateFailureStats updates failure tracking statistics
func (c *Collector) updateFailureStats(dnsEvent *DNSEvent) {
	c.failureTrackerMu.Lock()
	defer c.failureTrackerMu.Unlock()

	domain := dnsEvent.QueryName
	stats, exists := c.failureTracker[domain]
	if !exists {
		stats = &FailureStats{
			Domain: domain,
		}
		c.failureTracker[domain] = stats
	}

	stats.TotalQueries++
	if dnsEvent.ResponseCode != 0 { // 0 = NOERROR
		stats.FailedQueries++
		stats.ConsecutiveFailures++
		stats.LastFailureTime = time.Now()
	} else {
		stats.ConsecutiveFailures = 0
		stats.LastSuccessTime = time.Now()
	}
}

// cleanupExpiredQueries removes expired pending queries and generates timeout events
func (c *Collector) cleanupExpiredQueries() {
	// Recover from panics to prevent collector crash
	defer func() {
		if r := recover(); r != nil {
			c.mu.Lock()
			c.stats.ErrorsDetected++
			c.mu.Unlock()
			fmt.Printf("[ERROR] DNS collector cleanupExpiredQueries panic recovered: %v\n", r)
		}
	}()

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.pendingQueriesMu.Lock()
			now := time.Now()
			timeout := time.Duration(c.config.FailureThreshold.ResponseTimeMs) * time.Millisecond

			for key, query := range c.pendingQueries {
				if now.Sub(query.Timestamp) > timeout {
					// Generate timeout event
					c.processDNSTimeout(query)
					delete(c.pendingQueries, key)
				}
			}
			c.pendingQueriesMu.Unlock()
		}
	}
}

// analyzeFailurePatterns analyzes DNS failure patterns
func (c *Collector) analyzeFailurePatterns() {
	// Recover from panics to prevent collector crash
	defer func() {
		if r := recover(); r != nil {
			c.mu.Lock()
			c.stats.ErrorsDetected++
			c.mu.Unlock()
			fmt.Printf("[ERROR] DNS collector analyzeFailurePatterns panic recovered: %v\n", r)
		}
	}()

	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.analyzeAndReportPatterns()
		}
	}
}

// analyzeAndReportPatterns analyzes failure patterns and creates summary events
func (c *Collector) analyzeAndReportPatterns() {
	c.failureTrackerMu.RLock()
	defer c.failureTrackerMu.RUnlock()

	for domain, stats := range c.failureTracker {
		// Check if domain has high failure rate
		if stats.TotalQueries > 10 {
			failureRate := float64(stats.FailedQueries) / float64(stats.TotalQueries)
			if failureRate > 0.5 { // 50% failure rate threshold
				c.createFailurePatternEvent(domain, stats, failureRate)
			}
		}

		// Check for consecutive failures
		if stats.ConsecutiveFailures >= c.config.FailureThreshold.ConsecutiveFailures {
			c.createConsecutiveFailureEvent(domain, stats)
		}
	}
}

// createFailurePatternEvent creates an event for high failure rate patterns
func (c *Collector) createFailurePatternEvent(domain string, stats *FailureStats, failureRate float64) {
	metadata := map[string]string{
		"collector":            "dns",
		"event_type":           "dns_failure_pattern",
		"domain":               domain,
		"failure_rate":         fmt.Sprintf("%.2f", failureRate),
		"total_queries":        fmt.Sprintf("%d", stats.TotalQueries),
		"failed_queries":       fmt.Sprintf("%d", stats.FailedQueries),
		"consecutive_failures": fmt.Sprintf("%d", stats.ConsecutiveFailures),
	}

	eventData := map[string]interface{}{
		"timestamp":            time.Now(),
		"domain":               domain,
		"failure_rate":         failureRate,
		"total_queries":        stats.TotalQueries,
		"failed_queries":       stats.FailedQueries,
		"consecutive_failures": stats.ConsecutiveFailures,
		"last_failure_time":    stats.LastFailureTime,
		"last_success_time":    stats.LastSuccessTime,
	}

	jsonData, _ := json.Marshal(eventData)
	rawEvent := collectors.RawEvent{
		Timestamp: time.Now(),
		Type:      "dns_failure_pattern",
		Data:      jsonData,
		Metadata:  metadata,
		TraceID:   collectors.GenerateTraceID(),
		SpanID:    collectors.GenerateSpanID(),
	}

	select {
	case c.events <- rawEvent:
	case <-c.ctx.Done():
		return
	default:
		// Buffer full, drop event
	}
}

// createConsecutiveFailureEvent creates an event for consecutive failures
func (c *Collector) createConsecutiveFailureEvent(domain string, stats *FailureStats) {
	metadata := map[string]string{
		"collector":            "dns",
		"event_type":           "dns_consecutive_failures",
		"domain":               domain,
		"consecutive_failures": fmt.Sprintf("%d", stats.ConsecutiveFailures),
		"total_queries":        fmt.Sprintf("%d", stats.TotalQueries),
	}

	eventData := map[string]interface{}{
		"timestamp":            time.Now(),
		"domain":               domain,
		"consecutive_failures": stats.ConsecutiveFailures,
		"total_queries":        stats.TotalQueries,
		"last_failure_time":    stats.LastFailureTime,
	}

	jsonData, _ := json.Marshal(eventData)
	rawEvent := collectors.RawEvent{
		Timestamp: time.Now(),
		Type:      "dns_consecutive_failures",
		Data:      jsonData,
		Metadata:  metadata,
		TraceID:   collectors.GenerateTraceID(),
		SpanID:    collectors.GenerateSpanID(),
	}

	select {
	case c.events <- rawEvent:
	case <-c.ctx.Done():
		return
	default:
	}
}

// Helper functions

// getRCodeName returns human-readable DNS response code name
func (c *Collector) getRCodeName(rcode uint8) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", rcode)
	}
}

// getProtocolName returns protocol name
func (c *Collector) getProtocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO_%d", protocol)
	}
}

// extractK8sMetadata extracts Kubernetes metadata for a process ID
func (c *Collector) extractK8sMetadata(processID uint32) map[string]string {
	metadata := make(map[string]string)

	// Try to get container ID from /proc/{pid}/cgroup
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", processID)
	cgroupData, err := os.ReadFile(cgroupPath)
	if err != nil {
		// Process might have exited or we don't have permissions
		return metadata
	}

	// Parse cgroup to extract container ID
	containerID := c.extractContainerID(string(cgroupData))
	if containerID == "" {
		return metadata
	}

	metadata["container_id"] = containerID

	// Try to extract pod UID from cgroup path (for Kubernetes pods)
	// Format: /kubepods/burstable/pod{uuid}/{container_id}
	lines := strings.Split(string(cgroupData), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/kubepods") {
			parts := strings.Split(line, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, "pod") && len(part) > 3 {
					// Extract pod UID (remove "pod" prefix)
					podUID := strings.TrimPrefix(part, "pod")
					metadata["k8s_uid"] = podUID

					// Try to extract QoS class
					if i > 0 {
						qos := parts[i-1]
						if qos == "besteffort" || qos == "burstable" || qos == "guaranteed" {
							metadata["k8s_qos"] = qos
						}
					}
					break
				}
			}
		}
	}

	// Extract namespace and pod name from environment if available
	// This would be more reliable with actual K8s API integration
	environPath := fmt.Sprintf("/proc/%d/environ", processID)
	environData, err := os.ReadFile(environPath)
	if err == nil {
		environ := string(environData)
		// Look for Kubernetes downward API environment variables
		for _, env := range strings.Split(environ, "\x00") {
			if strings.HasPrefix(env, "KUBERNETES_POD_NAME=") {
				metadata["k8s_name"] = strings.TrimPrefix(env, "KUBERNETES_POD_NAME=")
			} else if strings.HasPrefix(env, "KUBERNETES_POD_NAMESPACE=") {
				metadata["k8s_namespace"] = strings.TrimPrefix(env, "KUBERNETES_POD_NAMESPACE=")
			} else if strings.HasPrefix(env, "KUBERNETES_SERVICE_HOST=") {
				metadata["k8s_cluster"] = strings.TrimPrefix(env, "KUBERNETES_SERVICE_HOST=")
			}
		}
	}

	// Add process info
	metadata["process_id"] = fmt.Sprintf("%d", processID)

	// Try to get process command
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", processID)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err == nil {
		cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline != "" {
			// Extract just the command name, not full args
			parts := strings.Fields(cmdline)
			if len(parts) > 0 {
				metadata["process_cmd"] = parts[0]
			}
		}
	}

	return metadata
}

// extractContainerID extracts container ID from cgroup data
func (c *Collector) extractContainerID(cgroupData string) string {
	// Docker container ID pattern: /docker/[64-char-hex]
	if idx := strings.Index(cgroupData, "/docker/"); idx >= 0 {
		start := idx + len("/docker/")
		end := start + 64
		if end <= len(cgroupData) {
			containerID := cgroupData[start:end]
			// Validate it's hex
			for _, ch := range containerID {
				if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
					return ""
				}
			}
			return containerID
		}
	}

	// Containerd pattern: /containerd/[64-char-hex]
	if idx := strings.Index(cgroupData, "/containerd/"); idx >= 0 {
		start := idx + len("/containerd/")
		end := start + 64
		if end <= len(cgroupData) {
			return cgroupData[start:end]
		}
	}

	// CRI-O pattern: /crio/[64-char-hex]
	if idx := strings.Index(cgroupData, "/crio/"); idx >= 0 {
		start := idx + len("/crio/")
		end := start + 64
		if end <= len(cgroupData) {
			return cgroupData[start:end]
		}
	}

	return ""
}

// Health returns detailed health information
func (c *Collector) Health() (bool, map[string]interface{}) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	health := map[string]interface{}{
		"healthy":           c.healthy,
		"queries_tracked":   c.stats.QueriesTracked,
		"responses_tracked": c.stats.ResponsesTracked,
		"failures_detected": c.stats.FailuresDetected,
		"timeouts_detected": c.stats.TimeoutsDetected,
		"errors_detected":   c.stats.ErrorsDetected,
		"last_event":        c.stats.LastEventTime,
		"pending_queries":   len(c.pendingQueries),
		"tracked_domains":   len(c.failureTracker),
	}

	return c.healthy, health
}
