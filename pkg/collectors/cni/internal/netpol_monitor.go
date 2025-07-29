package internal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/domain"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// NetworkPolicyMonitor monitors network policy enforcement and violations
type NetworkPolicyMonitor struct {
	config        core.Config
	client        kubernetes.Interface
	events        chan<- domain.UnifiedEvent
	logger        Logger
	stopCh        chan struct{}
	wg            sync.WaitGroup
	mu            sync.RWMutex
	policyCache   map[string]*PolicyInfo
	violationData map[string]*ViolationRecord
}

// PolicyInfo tracks network policy details
type PolicyInfo struct {
	Policy         *networkingv1.NetworkPolicy
	AffectedPods   []string
	EnforcementLog []EnforcementEvent
	LastUpdated    time.Time
}

// EnforcementEvent tracks policy enforcement actions
type EnforcementEvent struct {
	Timestamp   time.Time
	Action      string // "allowed", "denied", "modified"
	Source      string
	Destination string
	Port        int32
	Protocol    string
	Reason      string
}

// ViolationRecord tracks policy violations
type ViolationRecord struct {
	PolicyName    string
	Namespace     string
	ViolationTime time.Time
	SourcePod     string
	DestPod       string
	Details       string
	Count         int
}

// NetworkPolicyMetrics provides policy enforcement metrics
type NetworkPolicyMetrics struct {
	TotalPolicies       int                         `json:"total_policies"`
	ActivePolicies      int                         `json:"active_policies"`
	EnforcementRate     float64                     `json:"enforcement_rate"`
	ViolationRate       float64                     `json:"violation_rate"`
	PolicyCoverage      float64                     `json:"policy_coverage"`
	PolicyByNamespace   map[string]int              `json:"policies_by_namespace"`
	ViolationsByPolicy  map[string]int              `json:"violations_by_policy"`
	EnforcementByPlugin map[string]EnforcementStats `json:"enforcement_by_plugin"`
}

// EnforcementStats tracks enforcement statistics
type EnforcementStats struct {
	AllowedConnections int `json:"allowed_connections"`
	DeniedConnections  int `json:"denied_connections"`
	PolicyChanges      int `json:"policy_changes"`
}

// NewNetworkPolicyMonitor creates a new network policy monitor
func NewNetworkPolicyMonitor(config core.Config) (*NetworkPolicyMonitor, error) {
	client, err := createK8sClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	return &NetworkPolicyMonitor{
		config:        config,
		client:        client,
		logger:        &StandardLogger{},
		stopCh:        make(chan struct{}),
		policyCache:   make(map[string]*PolicyInfo),
		violationData: make(map[string]*ViolationRecord),
	}, nil
}

// Start begins monitoring network policies
func (m *NetworkPolicyMonitor) Start(ctx context.Context, events chan<- domain.UnifiedEvent) error {
	m.events = events

	// Start policy watcher
	m.wg.Add(1)
	go m.watchNetworkPolicies(ctx)

	// Start enforcement monitor
	m.wg.Add(1)
	go m.monitorEnforcement(ctx)

	// Start violation detector
	m.wg.Add(1)
	go m.detectViolations(ctx)

	m.logger.Info("Network policy monitor started", nil)
	return nil
}

// Stop stops the network policy monitor
func (m *NetworkPolicyMonitor) Stop() error {
	close(m.stopCh)
	m.wg.Wait()
	m.logger.Info("Network policy monitor stopped", nil)
	return nil
}

// watchNetworkPolicies watches for network policy changes
func (m *NetworkPolicyMonitor) watchNetworkPolicies(ctx context.Context) {
	defer m.wg.Done()

	// Create informer for network policies
	listWatch := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			if m.config.Namespace != "" {
				return m.client.NetworkingV1().NetworkPolicies(m.config.Namespace).List(ctx, options)
			}
			return m.client.NetworkingV1().NetworkPolicies("").List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			if m.config.Namespace != "" {
				return m.client.NetworkingV1().NetworkPolicies(m.config.Namespace).Watch(ctx, options)
			}
			return m.client.NetworkingV1().NetworkPolicies("").Watch(ctx, options)
		},
	}

	_, controller := cache.NewInformer(
		listWatch,
		&networkingv1.NetworkPolicy{},
		30*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    m.handlePolicyAdd,
			UpdateFunc: m.handlePolicyUpdate,
			DeleteFunc: m.handlePolicyDelete,
		},
	)

	go controller.Run(m.stopCh)
	<-m.stopCh
}

// handlePolicyAdd handles new network policy
func (m *NetworkPolicyMonitor) handlePolicyAdd(obj interface{}) {
	policy, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		return
	}

	// Cache policy info
	policyKey := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	policyInfo := &PolicyInfo{
		Policy:       policy,
		AffectedPods: m.getAffectedPods(policy),
		LastUpdated:  time.Now(),
	}

	m.mu.Lock()
	m.policyCache[policyKey] = policyInfo
	m.mu.Unlock()

	// Emit policy creation event
	m.emitPolicyEvent("network_policy_created", policy, "")
}

// handlePolicyUpdate handles network policy updates
func (m *NetworkPolicyMonitor) handlePolicyUpdate(oldObj, newObj interface{}) {
	oldPolicy, ok1 := oldObj.(*networkingv1.NetworkPolicy)
	newPolicy, ok2 := newObj.(*networkingv1.NetworkPolicy)
	if !ok1 || !ok2 {
		return
	}

	// Check for significant changes
	changes := m.detectPolicyChanges(oldPolicy, newPolicy)
	if len(changes) > 0 {
		policyKey := fmt.Sprintf("%s/%s", newPolicy.Namespace, newPolicy.Name)

		m.mu.Lock()
		if info, exists := m.policyCache[policyKey]; exists {
			info.Policy = newPolicy
			info.AffectedPods = m.getAffectedPods(newPolicy)
			info.LastUpdated = time.Now()

			// Log enforcement change
			for _, change := range changes {
				info.EnforcementLog = append(info.EnforcementLog, EnforcementEvent{
					Timestamp: time.Now(),
					Action:    "modified",
					Reason:    change,
				})
			}
		}
		m.mu.Unlock()

		// Emit policy update event
		message := fmt.Sprintf("Policy updated: %s", changes[0])
		if len(changes) > 1 {
			message += fmt.Sprintf(" and %d more changes", len(changes)-1)
		}
		m.emitPolicyEvent("network_policy_updated", newPolicy, message)
	}
}

// handlePolicyDelete handles network policy deletion
func (m *NetworkPolicyMonitor) handlePolicyDelete(obj interface{}) {
	policy, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		return
	}

	policyKey := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)

	m.mu.Lock()
	delete(m.policyCache, policyKey)
	m.mu.Unlock()

	// Emit policy deletion event
	m.emitPolicyEvent("network_policy_deleted", policy,
		"Network policy removed - affected pods now unrestricted")
}

// monitorEnforcement monitors policy enforcement by CNI plugins
func (m *NetworkPolicyMonitor) monitorEnforcement(ctx context.Context) {
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
			m.checkEnforcementStatus()
		}
	}
}

// checkEnforcementStatus checks if policies are being enforced
func (m *NetworkPolicyMonitor) checkEnforcementStatus() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for policyKey, info := range m.policyCache {
		// Check if policy is being enforced
		enforced, plugin := m.isPolicyEnforced(info.Policy)

		if !enforced {
			m.emitPolicyEvent("network_policy_not_enforced", info.Policy,
				fmt.Sprintf("Policy %s not enforced - CNI plugin may not support NetworkPolicy", policyKey))
		} else {
			m.logger.Debug("Policy enforced", map[string]interface{}{
				"policy": policyKey,
				"plugin": plugin,
			})
		}
	}
}

// detectViolations monitors for policy violations
func (m *NetworkPolicyMonitor) detectViolations(ctx context.Context) {
	defer m.wg.Done()

	// This would integrate with CNI plugin logs or eBPF to detect denied connections
	// For now, we'll simulate violation detection
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkForViolations()
		}
	}
}

// checkForViolations checks for policy violations
func (m *NetworkPolicyMonitor) checkForViolations() {
	// In a real implementation, this would:
	// 1. Parse CNI plugin logs for denied connections
	// 2. Use eBPF to track dropped packets
	// 3. Correlate with network policies

	// For now, we emit a placeholder metric
	m.logger.Debug("Checking for policy violations", nil)
}

// getAffectedPods returns pods affected by a network policy
func (m *NetworkPolicyMonitor) getAffectedPods(policy *networkingv1.NetworkPolicy) []string {
	ctx := context.Background()
	affectedPods := []string{}

	// Get pods matching the policy selector
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		return affectedPods
	}

	pods, err := m.client.CoreV1().Pods(policy.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return affectedPods
	}

	for _, pod := range pods.Items {
		affectedPods = append(affectedPods, pod.Name)
	}

	return affectedPods
}

// detectPolicyChanges detects changes between policies
func (m *NetworkPolicyMonitor) detectPolicyChanges(old, new *networkingv1.NetworkPolicy) []string {
	changes := []string{}

	// Check ingress rules
	if len(old.Spec.Ingress) != len(new.Spec.Ingress) {
		changes = append(changes, fmt.Sprintf("ingress rules changed from %d to %d",
			len(old.Spec.Ingress), len(new.Spec.Ingress)))
	}

	// Check egress rules
	if len(old.Spec.Egress) != len(new.Spec.Egress) {
		changes = append(changes, fmt.Sprintf("egress rules changed from %d to %d",
			len(old.Spec.Egress), len(new.Spec.Egress)))
	}

	// Check policy types
	oldTypes := fmt.Sprintf("%v", old.Spec.PolicyTypes)
	newTypes := fmt.Sprintf("%v", new.Spec.PolicyTypes)
	if oldTypes != newTypes {
		changes = append(changes, "policy types changed")
	}

	return changes
}

// isPolicyEnforced checks if a policy is being enforced
func (m *NetworkPolicyMonitor) isPolicyEnforced(policy *networkingv1.NetworkPolicy) (bool, string) {
	// Check which CNI plugin is active
	// Different plugins have different NetworkPolicy support

	// This would check for:
	// - Calico: Full support
	// - Cilium: Full support
	// - Weave: Full support
	// - Flannel: No support (requires additional components)

	// For now, assume it's enforced if we have a supported plugin
	for _, plugin := range m.config.MonitoredPlugins {
		switch plugin {
		case "calico", "cilium", "weave", "canal", "antrea":
			return true, plugin
		}
	}

	return false, ""
}

// emitPolicyEvent emits a network policy event
func (m *NetworkPolicyMonitor) emitPolicyEvent(eventType string, policy *networkingv1.NetworkPolicy, message string) {
	if m.events == nil {
		return
	}

	affectedPods := len(m.getAffectedPods(policy))

	event := domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      domain.EventType("cni.netpol." + eventType),
		Source:    "cni-netpol-monitor",
		Category:  "cni",
		Severity:  domain.EventSeverityInfo,
		Message:   message,
		Semantic: &domain.SemanticContext{
			Intent:   "network-policy-monitoring",
			Category: "security",
			Tags:     []string{"network-policy", policy.Name, policy.Namespace},
			Narrative: fmt.Sprintf("Network policy %s/%s affects %d pods",
				policy.Namespace, policy.Name, affectedPods),
		},
	}

	// Adjust severity based on event type
	if eventType == "network_policy_not_enforced" || eventType == "network_policy_violation" {
		event.Severity = domain.EventSeverityWarning
	}

	select {
	case m.events <- event:
	default:
		m.logger.Warn("Event channel full, dropping network policy event", nil)
	}
}

// GetMetrics returns network policy metrics
func (m *NetworkPolicyMonitor) GetMetrics() NetworkPolicyMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := NetworkPolicyMetrics{
		TotalPolicies:       len(m.policyCache),
		PolicyByNamespace:   make(map[string]int),
		ViolationsByPolicy:  make(map[string]int),
		EnforcementByPlugin: make(map[string]EnforcementStats),
	}

	// Count policies by namespace
	for _, info := range m.policyCache {
		ns := info.Policy.Namespace
		metrics.PolicyByNamespace[ns]++

		// Check if actively enforced
		if enforced, _ := m.isPolicyEnforced(info.Policy); enforced {
			metrics.ActivePolicies++
		}
	}

	// Count violations
	for _, violation := range m.violationData {
		key := fmt.Sprintf("%s/%s", violation.Namespace, violation.PolicyName)
		metrics.ViolationsByPolicy[key] = violation.Count
	}

	// Calculate rates
	if metrics.TotalPolicies > 0 {
		metrics.EnforcementRate = float64(metrics.ActivePolicies) / float64(metrics.TotalPolicies) * 100
	}

	// Calculate policy coverage (pods with policies vs total pods)
	metrics.PolicyCoverage = m.calculatePolicyCoverage()

	return metrics
}

// calculatePolicyCoverage calculates percentage of pods covered by policies
func (m *NetworkPolicyMonitor) calculatePolicyCoverage() float64 {
	ctx := context.Background()

	// Get all pods
	allPods, err := m.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil || len(allPods.Items) == 0 {
		return 0.0
	}

	coveredPods := make(map[string]bool)

	// Check which pods are covered by policies
	for _, info := range m.policyCache {
		for _, podName := range info.AffectedPods {
			key := fmt.Sprintf("%s/%s", info.Policy.Namespace, podName)
			coveredPods[key] = true
		}
	}

	return float64(len(coveredPods)) / float64(len(allPods.Items)) * 100
}
