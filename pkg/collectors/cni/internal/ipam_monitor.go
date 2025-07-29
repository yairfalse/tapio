package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/collectors/cni/internal/platform"
	"github.com/yairfalse/tapio/pkg/domain"
)

// IPAMMonitor tracks IP Address Management pool utilization
type IPAMMonitor struct {
	config      core.Config
	mu          sync.RWMutex
	pools       map[string]*IPPool
	allocations map[string]*IPAllocation
	events      chan<- domain.UnifiedEvent
	logger      Logger
	stopCh      chan struct{}
	wg          sync.WaitGroup
	analytics   *IPAMAnalytics
	platform    platform.Platform
}

// IPPool represents an IPAM pool
type IPPool struct {
	Name         string
	Subnet       *net.IPNet
	Gateway      net.IP
	RangeStart   net.IP
	RangeEnd     net.IP
	TotalIPs     int
	AllocatedIPs int
	ReservedIPs  []net.IP
	LastUpdated  time.Time
}

// IPAllocation tracks an allocated IP
type IPAllocation struct {
	IP           net.IP
	PodName      string
	PodNamespace string
	ContainerID  string
	Interface    string
	AllocatedAt  time.Time
	PoolName     string
}

// IPAMMetrics provides pool utilization metrics
type IPAMMetrics struct {
	Pools              []PoolMetrics `json:"pools"`
	TotalCapacity      int           `json:"total_capacity"`
	TotalAllocated     int           `json:"total_allocated"`
	UtilizationPercent float64       `json:"utilization_percent"`
}

// PoolMetrics provides metrics for a single pool
type PoolMetrics struct {
	Name               string  `json:"name"`
	Subnet             string  `json:"subnet"`
	TotalIPs           int     `json:"total_ips"`
	AllocatedIPs       int     `json:"allocated_ips"`
	AvailableIPs       int     `json:"available_ips"`
	UtilizationPercent float64 `json:"utilization_percent"`
	FragmentationScore float64 `json:"fragmentation_score"`
}

// NewIPAMMonitor creates a new IPAM monitor
func NewIPAMMonitor(config core.Config) (*IPAMMonitor, error) {
	logger := &StandardLogger{}

	analytics, err := NewIPAMAnalytics(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPAM analytics: %w", err)
	}

	return &IPAMMonitor{
		config:      config,
		pools:       make(map[string]*IPPool),
		allocations: make(map[string]*IPAllocation),
		logger:      logger,
		stopCh:      make(chan struct{}),
		analytics:   analytics,
	}, nil
}

// Start begins monitoring IPAM pools
func (m *IPAMMonitor) Start(ctx context.Context, events chan<- domain.UnifiedEvent) error {
	m.events = events

	// Discover initial pools
	if err := m.discoverPools(); err != nil {
		return fmt.Errorf("failed to discover IPAM pools: %w", err)
	}

	// Start analytics engine
	if err := m.analytics.Start(ctx, events); err != nil {
		return fmt.Errorf("failed to start IPAM analytics: %w", err)
	}

	// Start monitoring routines
	m.wg.Add(2)
	go m.monitorPools(ctx)
	go m.trackAllocations(ctx)

	m.logger.Info("IPAM monitor started", map[string]interface{}{
		"pools": len(m.pools),
	})

	return nil
}

// Stop stops the IPAM monitor
func (m *IPAMMonitor) Stop() error {
	close(m.stopCh)
	m.wg.Wait()

	// Stop analytics engine
	if m.analytics != nil {
		if err := m.analytics.Stop(); err != nil {
			m.logger.Error("Failed to stop IPAM analytics", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	m.logger.Info("IPAM monitor stopped", nil)
	return nil
}

// discoverPools discovers IPAM pools from CNI configurations
func (m *IPAMMonitor) discoverPools() error {
	// Check common CNI config paths
	configPaths := []string{
		m.config.CNIConfPath,
		"/etc/cni/net.d",
		"/opt/cni/conf",
	}

	for _, path := range configPaths {
		if err := m.scanConfigPath(path); err != nil {
			m.logger.Warn("Failed to scan config path", map[string]interface{}{
				"path":  path,
				"error": err.Error(),
			})
		}
	}

	// Also check for host-local IPAM data
	if err := m.scanHostLocalData(); err != nil {
		m.logger.Warn("Failed to scan host-local data", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return nil
}

// scanConfigPath scans a directory for CNI configurations
func (m *IPAMMonitor) scanConfigPath(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	return filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if filepath.Ext(file) == ".conf" || filepath.Ext(file) == ".conflist" {
			m.parseConfigFile(file)
		}

		return nil
	})
}

// parseConfigFile parses a CNI config file for IPAM information
func (m *IPAMMonitor) parseConfigFile(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	// Check for IPAM configuration
	if ipamConfig, ok := config["ipam"].(map[string]interface{}); ok {
		m.parseIPAMConfig(filepath.Base(file), ipamConfig)
	}

	// Check for plugin list (conflist format)
	if plugins, ok := config["plugins"].([]interface{}); ok {
		for _, plugin := range plugins {
			if p, ok := plugin.(map[string]interface{}); ok {
				if ipam, ok := p["ipam"].(map[string]interface{}); ok {
					m.parseIPAMConfig(filepath.Base(file), ipam)
				}
			}
		}
	}
}

// parseIPAMConfig parses IPAM configuration
func (m *IPAMMonitor) parseIPAMConfig(name string, ipam map[string]interface{}) {
	ipamType, _ := ipam["type"].(string)

	switch ipamType {
	case "host-local":
		m.parseHostLocalIPAM(name, ipam)
	case "calico-ipam":
		m.parseCalicoIPAM(name, ipam)
	case "azure-vnet-ipam":
		m.parseAzureIPAM(name, ipam)
	case "aws-vpc-ipam":
		m.parseAWSIPAM(name, ipam)
	}
}

// parseHostLocalIPAM parses host-local IPAM configuration
func (m *IPAMMonitor) parseHostLocalIPAM(name string, ipam map[string]interface{}) {
	subnet, _ := ipam["subnet"].(string)
	if subnet == "" {
		return
	}

	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return
	}

	pool := &IPPool{
		Name:        name,
		Subnet:      ipnet,
		LastUpdated: time.Now(),
	}

	// Parse range if specified
	if rangeStart, ok := ipam["rangeStart"].(string); ok {
		pool.RangeStart = net.ParseIP(rangeStart)
	}
	if rangeEnd, ok := ipam["rangeEnd"].(string); ok {
		pool.RangeEnd = net.ParseIP(rangeEnd)
	}

	// Parse gateway
	if gateway, ok := ipam["gateway"].(string); ok {
		pool.Gateway = net.ParseIP(gateway)
	}

	// Calculate total IPs
	pool.TotalIPs = m.calculatePoolSize(pool)

	m.mu.Lock()
	m.pools[name] = pool
	m.mu.Unlock()

	// Emit pool discovered event
	m.emitPoolEvent("ipam_pool_discovered", pool, "")
}

// parseCalicoIPAM handles Calico IPAM
func (m *IPAMMonitor) parseCalicoIPAM(name string, ipam map[string]interface{}) {
	// Calico uses IP pools defined in CRDs
	// This would integrate with Calico's API
	m.logger.Debug("Calico IPAM detected", map[string]interface{}{
		"name": name,
	})
}

// parseAzureIPAM handles Azure CNI IPAM
func (m *IPAMMonitor) parseAzureIPAM(name string, ipam map[string]interface{}) {
	// Azure CNI delegates to Azure VNET
	m.logger.Debug("Azure IPAM detected", map[string]interface{}{
		"name": name,
	})
}

// parseAWSIPAM handles AWS VPC CNI IPAM
func (m *IPAMMonitor) parseAWSIPAM(name string, ipam map[string]interface{}) {
	// AWS VPC CNI uses ENI secondary IPs
	m.logger.Debug("AWS VPC IPAM detected", map[string]interface{}{
		"name": name,
	})
}

// scanHostLocalData scans host-local IPAM data directory
func (m *IPAMMonitor) scanHostLocalData() error {
	dataDir := "/var/lib/cni/networks"

	return filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || path == dataDir {
			return nil
		}

		network := filepath.Base(path)

		// Count allocated IPs
		allocated := 0
		filepath.Walk(path, func(ipFile string, ipInfo os.FileInfo, err error) error {
			if err != nil || ipInfo.IsDir() {
				return nil
			}

			// Each file represents an allocated IP
			ip := net.ParseIP(filepath.Base(ipFile))
			if ip != nil {
				allocated++

				// Read allocation info
				if data, err := os.ReadFile(ipFile); err == nil {
					m.parseAllocation(network, ip, string(data))
				}
			}

			return nil
		})

		// Update pool allocation count
		m.mu.Lock()
		if pool, ok := m.pools[network]; ok {
			pool.AllocatedIPs = allocated
			pool.LastUpdated = time.Now()
		}
		m.mu.Unlock()

		return nil
	})
}

// parseAllocation parses an IP allocation record
func (m *IPAMMonitor) parseAllocation(poolName string, ip net.IP, data string) {
	allocation := &IPAllocation{
		IP:          ip,
		PoolName:    poolName,
		AllocatedAt: time.Now(),
		ContainerID: data, // host-local stores container ID
	}

	key := ip.String()
	m.mu.Lock()
	m.allocations[key] = allocation
	m.mu.Unlock()
}

// monitorPools monitors pool utilization
func (m *IPAMMonitor) monitorPools(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkPoolUtilization()
		}
	}
}

// trackAllocations tracks IP allocations and deallocations
func (m *IPAMMonitor) trackAllocations(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.scanHostLocalData()
		}
	}
}

// checkPoolUtilization checks pool utilization and emits events
func (m *IPAMMonitor) checkPoolUtilization() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, pool := range m.pools {
		utilization := float64(pool.AllocatedIPs) / float64(pool.TotalIPs) * 100

		// Emit high utilization warning
		if utilization > 80 {
			m.emitPoolEvent("ipam_pool_high_utilization", pool,
				fmt.Sprintf("Pool %s at %.1f%% utilization", name, utilization))
		}

		// Emit critical utilization alert
		if utilization > 95 {
			m.emitPoolEvent("ipam_pool_critical_utilization", pool,
				fmt.Sprintf("Pool %s at %.1f%% utilization - IP exhaustion imminent", name, utilization))
		}
	}
}

// calculatePoolSize calculates the total IPs in a pool
func (m *IPAMMonitor) calculatePoolSize(pool *IPPool) int {
	ones, bits := pool.Subnet.Mask.Size()
	total := 1 << (bits - ones)

	// Subtract network and broadcast addresses
	if total > 2 {
		total -= 2
	}

	// If range is specified, calculate range size
	if pool.RangeStart != nil && pool.RangeEnd != nil {
		start := ipToInt(pool.RangeStart)
		end := ipToInt(pool.RangeEnd)
		if end > start {
			total = int(end - start + 1)
		}
	}

	return total
}

// emitPoolEvent emits an IPAM pool event
func (m *IPAMMonitor) emitPoolEvent(eventType string, pool *IPPool, message string) {
	if m.events == nil {
		return
	}

	event := domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      domain.EventType("cni.ipam." + eventType),
		Source:    "cni-ipam-monitor",
		Category:  "cni",
		Severity:  domain.EventSeverityInfo,
		Message:   message,
		Semantic: &domain.SemanticContext{
			Intent:   "ipam-monitoring",
			Category: "network",
			Tags:     []string{"ipam", "pool", pool.Name},
			Narrative: fmt.Sprintf("IPAM pool %s: %d/%d IPs allocated (%.1f%% utilization)",
				pool.Name, pool.AllocatedIPs, pool.TotalIPs,
				float64(pool.AllocatedIPs)/float64(pool.TotalIPs)*100),
		},
	}

	if eventType == "ipam_pool_critical_utilization" {
		event.Severity = domain.EventSeverityCritical
	} else if eventType == "ipam_pool_high_utilization" {
		event.Severity = domain.EventSeverityWarning
	}

	select {
	case m.events <- event:
	default:
		m.logger.Warn("Event channel full, dropping IPAM event", nil)
	}
}

// GetMetrics returns current IPAM metrics
func (m *IPAMMonitor) GetMetrics() IPAMMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := IPAMMetrics{
		Pools: make([]PoolMetrics, 0, len(m.pools)),
	}

	for name, pool := range m.pools {
		available := pool.TotalIPs - pool.AllocatedIPs
		utilization := float64(pool.AllocatedIPs) / float64(pool.TotalIPs) * 100

		poolMetric := PoolMetrics{
			Name:               name,
			Subnet:             pool.Subnet.String(),
			TotalIPs:           pool.TotalIPs,
			AllocatedIPs:       pool.AllocatedIPs,
			AvailableIPs:       available,
			UtilizationPercent: utilization,
			FragmentationScore: m.calculateFragmentation(pool),
		}

		metrics.Pools = append(metrics.Pools, poolMetric)
		metrics.TotalCapacity += pool.TotalIPs
		metrics.TotalAllocated += pool.AllocatedIPs
	}

	if metrics.TotalCapacity > 0 {
		metrics.UtilizationPercent = float64(metrics.TotalAllocated) / float64(metrics.TotalCapacity) * 100
	}

	return metrics
}

// calculateFragmentation calculates IP fragmentation score
func (m *IPAMMonitor) calculateFragmentation(pool *IPPool) float64 {
	// Simple fragmentation metric based on allocation patterns
	// In production, this would analyze IP allocation gaps
	return 0.0
}

// ipToInt converts IP to integer for range calculations
func ipToInt(ip net.IP) int64 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return int64(ip[0])<<24 | int64(ip[1])<<16 | int64(ip[2])<<8 | int64(ip[3])
}

// ProcessCNIEvent processes CNI events for IPAM analytics
func (m *IPAMMonitor) ProcessCNIEvent(event core.CNIRawEvent) {
	// Forward to analytics engine
	if m.analytics != nil {
		m.analytics.ProcessIPAMEvent(event)
	}

	// Update local tracking
	switch event.Operation {
	case core.CNIOperationAdd:
		if event.AssignedIP != "" && event.Success {
			ip := net.ParseIP(event.AssignedIP)
			if ip != nil {
				allocation := &IPAllocation{
					IP:           ip,
					PodName:      event.PodName,
					PodNamespace: event.PodNamespace,
					ContainerID:  event.ContainerID,
					Interface:    event.InterfaceName,
					AllocatedAt:  event.Timestamp,
					PoolName:     m.detectPoolForIP(ip),
				}

				m.mu.Lock()
				m.allocations[ip.String()] = allocation
				// Update pool allocation count
				if pool, exists := m.pools[allocation.PoolName]; exists {
					pool.AllocatedIPs++
					pool.LastUpdated = time.Now()
				}
				m.mu.Unlock()
			}
		}
	case core.CNIOperationDel:
		if event.AssignedIP != "" {
			ip := net.ParseIP(event.AssignedIP)
			if ip != nil {
				m.mu.Lock()
				if allocation, exists := m.allocations[ip.String()]; exists {
					// Update pool allocation count
					if pool, exists := m.pools[allocation.PoolName]; exists {
						pool.AllocatedIPs--
						pool.LastUpdated = time.Now()
					}
					delete(m.allocations, ip.String())
				}
				m.mu.Unlock()
			}
		}
	}
}

// detectPoolForIP detects which pool an IP belongs to
func (m *IPAMMonitor) detectPoolForIP(ip net.IP) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, pool := range m.pools {
		if pool.Subnet != nil && pool.Subnet.Contains(ip) {
			return name
		}
	}

	return "unknown"
}

// GetAnalytics returns IPAM analytics report
func (m *IPAMMonitor) GetAnalytics() *IPAMAnalyticsReport {
	if m.analytics != nil {
		return m.analytics.GetAnalytics()
	}
	return nil
}

// Implement CNIMonitor interface
func (m *IPAMMonitor) MonitorType() string {
	return "ipam"
}

func (m *IPAMMonitor) Events() <-chan core.CNIRawEvent {
	// IPAM monitor doesn't emit raw CNI events directly
	// It processes them and emits analytics events
	return nil
}
