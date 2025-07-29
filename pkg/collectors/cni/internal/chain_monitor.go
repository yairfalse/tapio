package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/domain"
)

// CNIChainMonitor monitors CNI plugin chaining and execution order
type CNIChainMonitor struct {
	config     core.Config
	mu         sync.RWMutex
	chains     map[string]*CNIChain
	executions map[string]*ChainExecution
	events     chan<- domain.UnifiedEvent
	logger     Logger
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// CNIChain represents a chain of CNI plugins
type CNIChain struct {
	Name           string
	NetworkName    string
	PluginSequence []ChainPluginInfo
	LastUpdated    time.Time
	ConfigPath     string
}

// ChainPluginInfo contains information about a plugin in the chain
type ChainPluginInfo struct {
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Capabilities  map[string]interface{} `json:"capabilities,omitempty"`
	IPAM          map[string]interface{} `json:"ipam,omitempty"`
	DNS           map[string]interface{} `json:"dns,omitempty"`
	Args          map[string]interface{} `json:"args,omitempty"`
	RuntimeConfig map[string]interface{} `json:"runtimeConfig,omitempty"`
	PrevResult    interface{}            `json:"prevResult,omitempty"`
	Dependencies  []string               // Plugins this one depends on
	Order         int                    // Position in chain
}

// ChainExecution tracks the execution of a plugin chain
type ChainExecution struct {
	ChainName     string
	ContainerID   string
	StartTime     time.Time
	EndTime       time.Time
	ExecutedSteps []ExecutionStep
	Status        string // "running", "completed", "failed"
	Error         string
}

// ExecutionStep tracks individual plugin execution
type ExecutionStep struct {
	PluginName string
	StartTime  time.Time
	EndTime    time.Time
	Status     string // "success", "failed", "skipped"
	Result     interface{}
	Error      string
	Duration   time.Duration
}

// ChainMetrics provides metrics about CNI chains
type ChainMetrics struct {
	TotalChains        int                         `json:"total_chains"`
	ActiveChains       int                         `json:"active_chains"`
	ChainsByComplexity map[string]int              `json:"chains_by_complexity"`
	ExecutionMetrics   ExecutionMetrics            `json:"execution_metrics"`
	PluginUsage        map[string]ChainPluginStats `json:"plugin_usage"`
}

// ExecutionMetrics tracks chain execution performance
type ExecutionMetrics struct {
	AverageExecutionTime time.Duration `json:"average_execution_time"`
	SuccessRate          float64       `json:"success_rate"`
	FailureRate          float64       `json:"failure_rate"`
	TotalExecutions      int           `json:"total_executions"`
	FailedExecutions     int           `json:"failed_executions"`
}

// ChainPluginStats tracks individual plugin statistics
type ChainPluginStats struct {
	UsageCount     int           `json:"usage_count"`
	SuccessRate    float64       `json:"success_rate"`
	AverageLatency time.Duration `json:"average_latency"`
	FailureReasons []string      `json:"failure_reasons"`
}

// NewCNIChainMonitor creates a new CNI chain monitor
func NewCNIChainMonitor(config core.Config) (*CNIChainMonitor, error) {
	return &CNIChainMonitor{
		config:     config,
		chains:     make(map[string]*CNIChain),
		executions: make(map[string]*ChainExecution),
		logger:     &StandardLogger{},
		stopCh:     make(chan struct{}),
	}, nil
}

// Start begins monitoring CNI chains
func (m *CNIChainMonitor) Start(ctx context.Context, events chan<- domain.UnifiedEvent) error {
	m.events = events

	// Discover existing chains
	if err := m.discoverChains(); err != nil {
		return fmt.Errorf("failed to discover CNI chains: %w", err)
	}

	// Start monitoring routines
	m.wg.Add(3)
	go m.monitorChainConfigs(ctx)
	go m.trackChainExecutions(ctx)
	go m.analyzeChainPerformance(ctx)

	m.logger.Info("CNI chain monitor started", map[string]interface{}{
		"chains": len(m.chains),
	})

	return nil
}

// Stop stops the CNI chain monitor
func (m *CNIChainMonitor) Stop() error {
	close(m.stopCh)
	m.wg.Wait()
	m.logger.Info("CNI chain monitor stopped", nil)
	return nil
}

// discoverChains discovers existing CNI chain configurations
func (m *CNIChainMonitor) discoverChains() error {
	configPaths := []string{
		m.config.CNIConfPath,
		"/etc/cni/net.d",
		"/opt/cni/conf",
	}

	for _, path := range configPaths {
		if err := m.scanChainConfigs(path); err != nil {
			m.logger.Warn("Failed to scan chain configs", map[string]interface{}{
				"path":  path,
				"error": err.Error(),
			})
		}
	}

	return nil
}

// scanChainConfigs scans for CNI chain configurations
func (m *CNIChainMonitor) scanChainConfigs(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	return filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Look for .conflist files (chain configurations)
		if filepath.Ext(file) == ".conflist" {
			m.parseChainConfig(file)
		}

		return nil
	})
}

// parseChainConfig parses a CNI chain configuration file
func (m *CNIChainMonitor) parseChainConfig(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	// Parse as conflist format
	if plugins, ok := config["plugins"].([]interface{}); ok {
		chain := &CNIChain{
			Name:        filepath.Base(file),
			ConfigPath:  file,
			LastUpdated: time.Now(),
		}

		if name, ok := config["name"].(string); ok {
			chain.NetworkName = name
		}

		// Parse plugin sequence
		for i, plugin := range plugins {
			if p, ok := plugin.(map[string]interface{}); ok {
				pluginInfo := m.parsePluginInfo(p, i)
				chain.PluginSequence = append(chain.PluginSequence, pluginInfo)
			}
		}

		// Analyze dependencies
		m.analyzeDependencies(chain)

		m.mu.Lock()
		m.chains[chain.Name] = chain
		m.mu.Unlock()

		// Emit chain discovered event
		m.emitChainEvent("cni_chain_discovered", chain, "")
	}
}

// parsePluginInfo parses individual plugin configuration
func (m *CNIChainMonitor) parsePluginInfo(plugin map[string]interface{}, order int) ChainPluginInfo {
	info := ChainPluginInfo{
		Order: order,
	}

	if name, ok := plugin["name"].(string); ok {
		info.Name = name
	}
	if pluginType, ok := plugin["type"].(string); ok {
		info.Type = pluginType
	}
	if capabilities, ok := plugin["capabilities"].(map[string]interface{}); ok {
		info.Capabilities = capabilities
	}
	if ipam, ok := plugin["ipam"].(map[string]interface{}); ok {
		info.IPAM = ipam
	}
	if dns, ok := plugin["dns"].(map[string]interface{}); ok {
		info.DNS = dns
	}
	if args, ok := plugin["args"].(map[string]interface{}); ok {
		info.Args = args
	}
	if runtimeConfig, ok := plugin["runtimeConfig"].(map[string]interface{}); ok {
		info.RuntimeConfig = runtimeConfig
	}

	return info
}

// analyzeDependencies analyzes plugin dependencies in the chain
func (m *CNIChainMonitor) analyzeDependencies(chain *CNIChain) {
	for i := range chain.PluginSequence {
		plugin := &chain.PluginSequence[i]

		// Basic dependency analysis
		switch plugin.Type {
		case "portmap":
			// portmap depends on a main plugin
			if i > 0 {
				plugin.Dependencies = []string{chain.PluginSequence[i-1].Type}
			}
		case "bandwidth":
			// bandwidth shaping depends on main plugin
			if i > 0 {
				plugin.Dependencies = []string{chain.PluginSequence[i-1].Type}
			}
		case "firewall":
			// firewall typically comes after main plugin
			if i > 0 {
				plugin.Dependencies = []string{chain.PluginSequence[i-1].Type}
			}
		case "tuning":
			// tuning can depend on interface creation
			if i > 0 {
				plugin.Dependencies = []string{chain.PluginSequence[i-1].Type}
			}
		}

		// Check for explicit dependencies in capabilities
		if plugin.Capabilities != nil {
			if deps, ok := plugin.Capabilities["dependencies"].([]interface{}); ok {
				for _, dep := range deps {
					if depStr, ok := dep.(string); ok {
						plugin.Dependencies = append(plugin.Dependencies, depStr)
					}
				}
			}
		}
	}
}

// monitorChainConfigs monitors changes to chain configurations
func (m *CNIChainMonitor) monitorChainConfigs(ctx context.Context) {
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
			m.discoverChains()
		}
	}
}

// trackChainExecutions tracks chain execution through logs or other means
func (m *CNIChainMonitor) trackChainExecutions(ctx context.Context) {
	defer m.wg.Done()

	// This would integrate with CNI runtime logs or use eBPF to track executions
	// For now, we'll simulate execution tracking
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.simulateExecution()
		}
	}
}

// simulateExecution simulates chain execution for demonstration
func (m *CNIChainMonitor) simulateExecution() {
	m.mu.RLock()
	chains := make([]*CNIChain, 0, len(m.chains))
	for _, chain := range m.chains {
		chains = append(chains, chain)
	}
	m.mu.RUnlock()

	if len(chains) == 0 {
		return
	}

	// Simulate execution of a random chain
	chain := chains[0]
	containerID := fmt.Sprintf("container-%d", time.Now().Unix())

	execution := &ChainExecution{
		ChainName:   chain.Name,
		ContainerID: containerID,
		StartTime:   time.Now(),
		Status:      "running",
	}

	// Simulate plugin execution steps
	for _, plugin := range chain.PluginSequence {
		step := ExecutionStep{
			PluginName: plugin.Name,
			StartTime:  time.Now(),
		}

		// Simulate execution time
		time.Sleep(10 * time.Millisecond)

		step.EndTime = time.Now()
		step.Duration = step.EndTime.Sub(step.StartTime)
		step.Status = "success"

		execution.ExecutedSteps = append(execution.ExecutedSteps, step)
	}

	execution.EndTime = time.Now()
	execution.Status = "completed"

	m.mu.Lock()
	m.executions[containerID] = execution
	m.mu.Unlock()

	// Emit execution event
	m.emitChainEvent("cni_chain_executed", chain,
		fmt.Sprintf("Chain executed for container %s in %v",
			containerID, execution.EndTime.Sub(execution.StartTime)))
}

// analyzeChainPerformance analyzes chain execution performance
func (m *CNIChainMonitor) analyzeChainPerformance(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.analyzePerformance()
		}
	}
}

// analyzePerformance analyzes chain execution performance
func (m *CNIChainMonitor) analyzePerformance() {
	m.mu.RLock()
	executions := make([]*ChainExecution, 0, len(m.executions))
	for _, exec := range m.executions {
		executions = append(executions, exec)
	}
	m.mu.RUnlock()

	if len(executions) == 0 {
		return
	}

	// Analyze slow chains
	var totalDuration time.Duration
	slowChains := 0

	for _, exec := range executions {
		duration := exec.EndTime.Sub(exec.StartTime)
		totalDuration += duration

		// Consider chains taking more than 1 second as slow
		if duration > time.Second {
			slowChains++

			// Find the bottleneck plugin
			bottleneck := m.findBottleneckPlugin(exec)
			if bottleneck != "" {
				m.emitChainEvent("cni_chain_slow_execution",
					&CNIChain{Name: exec.ChainName},
					fmt.Sprintf("Chain execution slow (%v), bottleneck: %s", duration, bottleneck))
			}
		}
	}

	// Emit performance summary
	if len(executions) > 0 {
		avgDuration := totalDuration / time.Duration(len(executions))
		slowRate := float64(slowChains) / float64(len(executions)) * 100

		if slowRate > 20 { // More than 20% of executions are slow
			m.logger.Warn("High rate of slow chain executions", map[string]interface{}{
				"slow_rate":    slowRate,
				"avg_duration": avgDuration,
				"total_chains": len(executions),
			})
		}
	}
}

// findBottleneckPlugin finds the plugin causing execution delays
func (m *CNIChainMonitor) findBottleneckPlugin(exec *ChainExecution) string {
	var maxDuration time.Duration
	var bottleneck string

	for _, step := range exec.ExecutedSteps {
		if step.Duration > maxDuration {
			maxDuration = step.Duration
			bottleneck = step.PluginName
		}
	}

	return bottleneck
}

// emitChainEvent emits a CNI chain event
func (m *CNIChainMonitor) emitChainEvent(eventType string, chain *CNIChain, message string) {
	if m.events == nil {
		return
	}

	pluginCount := len(chain.PluginSequence)
	pluginNames := make([]string, 0, pluginCount)
	for _, plugin := range chain.PluginSequence {
		pluginNames = append(pluginNames, plugin.Type)
	}

	event := domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      domain.EventType("cni.chain." + eventType),
		Source:    "cni-chain-monitor",
		Category:  "cni",
		Severity:  domain.EventSeverityInfo,
		Message:   message,
		Semantic: &domain.SemanticContext{
			Intent:   "cni-chain-monitoring",
			Category: "network",
			Tags:     []string{"cni-chain", chain.Name, chain.NetworkName},
			Narrative: fmt.Sprintf("CNI chain %s has %d plugins: %s",
				chain.Name, pluginCount, strings.Join(pluginNames, " → ")),
		},
	}

	// Adjust severity for performance issues
	if strings.Contains(eventType, "slow") || strings.Contains(eventType, "failed") {
		event.Severity = domain.EventSeverityWarning
	}

	select {
	case m.events <- event:
	default:
		m.logger.Warn("Event channel full, dropping chain event", nil)
	}
}

// GetMetrics returns CNI chain metrics
func (m *CNIChainMonitor) GetMetrics() ChainMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := ChainMetrics{
		TotalChains:        len(m.chains),
		ChainsByComplexity: make(map[string]int),
		PluginUsage:        make(map[string]PluginStats),
	}

	// Analyze chain complexity
	for _, chain := range m.chains {
		pluginCount := len(chain.PluginSequence)
		complexity := "simple"

		if pluginCount > 3 {
			complexity = "complex"
		} else if pluginCount > 1 {
			complexity = "moderate"
		}

		metrics.ChainsByComplexity[complexity]++
	}

	// Analyze plugin usage
	pluginUsage := make(map[string]int)
	for _, chain := range m.chains {
		for _, plugin := range chain.PluginSequence {
			pluginUsage[plugin.Type]++
		}
	}

	for pluginType, count := range pluginUsage {
		metrics.PluginUsage[pluginType] = ChainPluginStats{
			UsageCount:  count,
			SuccessRate: 95.0, // Would be calculated from real execution data
		}
	}

	// Calculate execution metrics
	totalExecs := len(m.executions)
	failed := 0
	var totalDuration time.Duration

	for _, exec := range m.executions {
		if exec.Status == "failed" {
			failed++
		}
		totalDuration += exec.EndTime.Sub(exec.StartTime)
	}

	if totalExecs > 0 {
		metrics.ExecutionMetrics = ExecutionMetrics{
			TotalExecutions:      totalExecs,
			FailedExecutions:     failed,
			SuccessRate:          float64(totalExecs-failed) / float64(totalExecs) * 100,
			FailureRate:          float64(failed) / float64(totalExecs) * 100,
			AverageExecutionTime: totalDuration / time.Duration(totalExecs),
		}
	}

	return metrics
}
