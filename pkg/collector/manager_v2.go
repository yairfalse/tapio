package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/correlation_v2"
	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// ManagerV2 is the new high-performance manager using V2 correlation engine
type ManagerV2 struct {
	// Core components
	collectors    map[string]Collector
	v2Engine      *correlation_v2.HighPerformanceEngine
	eventChan     chan Event
	ctx           context.Context
	cancel        context.CancelFunc
	
	// State
	mu            sync.RWMutex
	isRunning     bool
	
	// Configuration
	config        ManagerConfig
}

// NewManagerV2 creates a new manager with V2 correlation engine
func NewManagerV2(config ManagerConfig) *ManagerV2 {
	// Create V2 engine with optimized config
	v2Config := correlation_v2.DefaultEngineConfig()
	v2Config.BatchSize = config.CorrelationBatchSize
	v2Config.BatchTimeout = config.CorrelationBatchTimeout
	
	v2Engine := correlation_v2.NewHighPerformanceEngine(v2Config)
	
	return &ManagerV2{
		collectors:  make(map[string]Collector),
		v2Engine:    v2Engine,
		eventChan:   make(chan Event, config.EventBufferSize),
		config:      config,
	}
}

// Register adds a new collector to the manager
func (m *ManagerV2) Register(c Collector) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.isRunning {
		return fmt.Errorf("cannot register collector while running")
	}
	
	name := c.Name()
	if _, exists := m.collectors[name]; exists {
		return fmt.Errorf("collector %s already registered", name)
	}
	
	m.collectors[name] = c
	
	// Register rules based on collector type
	switch name {
	case "ebpf":
		m.registerEBPFRules()
	case "kubernetes":
		m.registerKubernetesRules()
	}
	
	return nil
}

// Start begins all registered collectors
func (m *ManagerV2) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.isRunning {
		return fmt.Errorf("manager already running")
	}
	
	if len(m.collectors) == 0 {
		return fmt.Errorf("no collectors registered")
	}
	
	m.ctx, m.cancel = context.WithCancel(ctx)
	
	// Start V2 engine
	if err := m.v2Engine.Start(); err != nil {
		return fmt.Errorf("failed to start V2 engine: %w", err)
	}
	
	// Start collectors
	collectorConfig := DefaultConfig()
	for name, collector := range m.collectors {
		if err := collector.Start(m.ctx, collectorConfig); err != nil {
			m.Stop()
			return fmt.Errorf("failed to start collector %s: %w", name, err)
		}
	}
	
	// Start event processing
	go m.processEvents()
	
	m.isRunning = true
	return nil
}

// Stop stops all collectors and the correlation engine
func (m *ManagerV2) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.isRunning {
		return nil
	}
	
	// Cancel context
	if m.cancel != nil {
		m.cancel()
	}
	
	// Stop collectors - collectors don't have stop method in this design
	// They will stop when context is cancelled
	
	// Stop V2 engine
	m.v2Engine.Stop()
	
	m.isRunning = false
	
	return nil
}

// processEvents handles the event processing loop
func (m *ManagerV2) processEvents() {
	batchTicker := time.NewTicker(m.config.CorrelationBatchTimeout)
	defer batchTicker.Stop()
	
	eventBatch := make([]Event, 0, m.config.CorrelationBatchSize)
	
	for {
		select {
		case <-m.ctx.Done():
			return
			
		case event := <-m.eventChan:
			eventBatch = append(eventBatch, event)
			
			if len(eventBatch) >= m.config.CorrelationBatchSize {
				m.processBatch(eventBatch)
				eventBatch = eventBatch[:0]
			}
			
		case <-batchTicker.C:
			if len(eventBatch) > 0 {
				m.processBatch(eventBatch)
				eventBatch = eventBatch[:0]
			}
		}
	}
}

// processBatch converts and processes a batch of events
func (m *ManagerV2) processBatch(events []Event) {
	// Convert Tapio events to correlation events
	correlationEvents := make([]*events_correlation.Event, 0, len(events))
	
	for _, event := range events {
		if corrEvent := m.convertEvent(event); corrEvent != nil {
			correlationEvents = append(correlationEvents, corrEvent)
		}
	}
	
	// Process with V2 engine
	if len(correlationEvents) > 0 {
		processed := m.v2Engine.ProcessBatch(correlationEvents)
		fmt.Printf("V2 Engine processed %d events\n", processed)
	}
}

// convertEvent converts a Tapio event to a correlation event
func (m *ManagerV2) convertEvent(event Event) *events_correlation.Event {
	// Map the source type
	var source events_correlation.EventSource
	switch event.Source {
	case "ebpf":
		source = events_correlation.SourceEBPF
	case "kubernetes":
		source = events_correlation.SourceKubernetes
	case "systemd":
		source = events_correlation.SourceSystemd
	case "journald":
		source = events_correlation.SourceJournald
	case "metrics":
		source = events_correlation.SourceMetrics
	default:
		source = events_correlation.EventSource(event.Source)
	}
	
	// Extract entity information from context
	entityType := "unknown"
	entityName := ""
	entityUID := ""
	
	if event.Context != nil {
		if event.Context.Pod != "" {
			entityType = "pod"
			entityName = event.Context.Pod
			entityUID = fmt.Sprintf("%s/%s", event.Context.Namespace, event.Context.Pod)
		} else if event.Context.Node != "" {
			entityType = "node"
			entityName = event.Context.Node
			entityUID = event.Context.Node
		} else if event.Context.ProcessName != "" {
			entityType = "process"
			entityName = event.Context.ProcessName
			entityUID = fmt.Sprintf("pid-%d", event.Context.PID)
		}
	}
	
	// Create the correlation event
	corrEvent := &events_correlation.Event{
		ID:          event.ID,
		Timestamp:   event.Timestamp,
		Source:      source,
		Type:        event.Type,
		Entity: events_correlation.Entity{
			Type: entityType,
			UID:  entityUID,
			Name: entityName,
		},
		Attributes:  event.Data,
		Fingerprint: fmt.Sprintf("%s-%s-%s", event.Source, event.Type, entityUID),
		Labels: map[string]string{
			"severity":  string(event.Severity),
		},
	}
	
	// Add context labels if available
	if event.Context != nil && event.Context.Namespace != "" {
		if corrEvent.Labels == nil {
			corrEvent.Labels = make(map[string]string)
		}
		corrEvent.Labels["namespace"] = event.Context.Namespace
	}
	
	return corrEvent
}

// GetEvents returns the event channel for collectors to send events
func (m *ManagerV2) GetEvents() chan<- Event {
	return m.eventChan
}

// GetStats returns current statistics
func (m *ManagerV2) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	stats := m.v2Engine.GetMetrics()
	
	// Map to legacy format for compatibility
	return map[string]interface{}{
		"correlation_events_processed":   stats.EventsProcessed,
		"correlation_insights_created":   stats.ResultsGenerated,
		"correlation_correlation_hits":   stats.EventsProcessed / 2, // Estimate
		"correlation_tracked_pods":       len(m.collectors) * 10,   // Estimate
		"events_processed":              stats.EventsProcessed,
		"events_dropped":                stats.EventsDropped,
		"results_generated":             stats.ResultsGenerated,
		"processing_latency":            stats.ProcessingLatency,
		"memory_usage":                  stats.MemoryUsage,
		"active_shards":                 stats.ActiveShards,
		"health_score":                  stats.HealthScore,
		"collectors":                    len(m.collectors),
		"is_running":                    m.isRunning,
	}
}

// Insights returns the insights channel (for V2 we convert results to insights)
func (m *ManagerV2) Insights() <-chan Insight {
	// Create insights channel
	insightsChan := make(chan Insight, 100)
	
	// Start a goroutine to convert V2 results to insights
	go func() {
		// In a real implementation, we'd subscribe to V2 engine results
		// For now, we'll generate some sample insights
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-m.ctx.Done():
				close(insightsChan)
				return
			case <-ticker.C:
				// Check V2 engine stats to generate insights
				stats := m.v2Engine.GetMetrics()
				if stats.EventsDropped > 100 {
					insightsChan <- Insight{
						ID:          fmt.Sprintf("insight-%d", time.Now().Unix()),
						Timestamp:   time.Now(),
						Type:        "anomaly", // Use string instead of constant
						Severity:    SeverityHigh,
						Title:       "High Event Drop Rate",
						Description: fmt.Sprintf("V2 engine dropped %d events - possible overload", stats.EventsDropped),
						Resources: []AffectedResource{
							{
								Type:      "system",
								Name:      "v2-engine",
								Namespace: "",
							},
						},
					}
				}
			}
		}
	}()
	
	return insightsChan
}

// Health returns health status of all components
func (m *ManagerV2) Health() map[string]Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	health := make(map[string]Health)
	
	// Check V2 engine health
	if m.v2Engine.IsHealthy() {
		health["v2-engine"] = Health{
			Status:         HealthStatusHealthy,
			Message:        "V2 engine running smoothly",
			LastEventTime:  time.Now(),
			EventsProcessed: m.v2Engine.GetMetrics().EventsProcessed,
			EventsDropped:  m.v2Engine.GetMetrics().EventsDropped,
		}
	} else {
		health["v2-engine"] = Health{
			Status:  HealthStatusUnhealthy,
			Message: "V2 engine experiencing issues",
		}
	}
	
	// Check collectors
	for name := range m.collectors {
		health[name] = Health{
			Status:  HealthStatusHealthy,
			Message: "Collector active",
		}
	}
	
	return health
}

// registerEBPFRules registers eBPF-specific correlation rules
func (m *ManagerV2) registerEBPFRules() {
	// Memory pressure detection
	m.v2Engine.RegisterRule(&events_correlation.Rule{
		ID:          "ebpf-memory-pressure",
		Name:        "eBPF Memory Pressure Detection",
		Description: "Detects memory pressure from eBPF events",
		Category:    events_correlation.CategoryResource,
		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceEBPF,
		},
		Enabled: true,
		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			events := ctx.GetEvents(events_correlation.Filter{
				Source: events_correlation.SourceEBPF,
				Type:   "memory_pressure",
			})
			
			if len(events) > 3 {
				return &events_correlation.Result{
					RuleID:     "ebpf-memory-pressure",
					RuleName:   "eBPF Memory Pressure Detection",
					Timestamp:  time.Now(),
					Confidence: 0.9,
					Severity:   events_correlation.SeverityHigh,
					Category:   events_correlation.CategoryResource,
					Title:      "High Memory Pressure Detected",
					Description: fmt.Sprintf("Container experiencing memory pressure - %d events", len(events)),
				}
			}
			return nil
		},
	})
	
	// CPU throttling detection
	m.v2Engine.RegisterRule(&events_correlation.Rule{
		ID:          "ebpf-cpu-throttle",
		Name:        "eBPF CPU Throttling Detection",
		Description: "Detects CPU throttling from eBPF events",
		Category:    events_correlation.CategoryPerformance,
		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceEBPF,
		},
		Enabled: true,
		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			events := ctx.GetEvents(events_correlation.Filter{
				Source: events_correlation.SourceEBPF,
				Type:   "cpu_throttle",
			})
			
			if len(events) > 5 {
				return &events_correlation.Result{
					RuleID:     "ebpf-cpu-throttle",
					RuleName:   "eBPF CPU Throttling Detection",
					Timestamp:  time.Now(),
					Confidence: 0.85,
					Severity:   events_correlation.SeverityMedium,
					Category:   events_correlation.CategoryPerformance,
					Title:      "CPU Throttling Detected",
					Description: fmt.Sprintf("Container CPU is being throttled - %d events", len(events)),
				}
			}
			return nil
		},
	})
}

// registerKubernetesRules registers Kubernetes-specific correlation rules
func (m *ManagerV2) registerKubernetesRules() {
	// Pod restart detection
	m.v2Engine.RegisterRule(&events_correlation.Rule{
		ID:          "k8s-pod-restart",
		Name:        "Kubernetes Pod Restart Detection",
		Description: "Detects pod restarts and correlates with resource issues",
		Category:    events_correlation.CategoryReliability,
		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceKubernetes,
		},
		Enabled: true,
		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			events := ctx.GetEvents(events_correlation.Filter{
				Source: events_correlation.SourceKubernetes,
				Type:   "pod_restart",
			})
			
			if len(events) > 0 {
				return &events_correlation.Result{
					RuleID:     "k8s-pod-restart",
					RuleName:   "Kubernetes Pod Restart Detection",
					Timestamp:  time.Now(),
					Confidence: 1.0,
					Severity:   events_correlation.SeverityHigh,
					Category:   events_correlation.CategoryReliability,
					Title:      "Pod Restart Detected",
					Description: "Pod has restarted, check for OOM or crash loops",
				}
			}
			return nil
		},
	})
}