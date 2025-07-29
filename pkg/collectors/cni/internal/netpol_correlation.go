package internal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/domain"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// NetworkPolicyCorrelator enhances network policy monitoring with CNI event correlation
type NetworkPolicyCorrelator struct {
	monitor *NetworkPolicyMonitor
	mu      sync.RWMutex

	// Track CNI operations per pod
	podCNIOperations map[string]*PodCNIHistory

	// Track policy enforcement timeline
	enforcementTimeline map[string]*PolicyEnforcementTimeline

	// Track connection attempts
	connectionAttempts map[string]*ConnectionAttempt
}

// PodCNIHistory tracks CNI operations for a pod
type PodCNIHistory struct {
	PodName      string
	Namespace    string
	CNIPlugin    string
	IPAddress    string
	CreatedAt    time.Time
	LastCNIEvent time.Time
	Operations   []CNIOperation
	Policies     []AppliedPolicy
}

// CNIOperation represents a CNI operation on a pod
type CNIOperation struct {
	Timestamp time.Time
	Operation string // ADD, DEL, CHECK
	Success   bool
	Duration  time.Duration
	Error     string
}

// AppliedPolicy tracks when a policy was applied to a pod
type AppliedPolicy struct {
	PolicyName string
	AppliedAt  time.Time
	RuleCount  int
	PolicyType []string // Ingress, Egress
}

// PolicyEnforcementTimeline tracks enforcement events over time
type PolicyEnforcementTimeline struct {
	PolicyName    string
	Namespace     string
	CreatedAt     time.Time
	Events        []EnforcementTimelineEvent
	CNIPlugin     string
	Effectiveness float64 // Percentage of successful enforcements
}

// EnforcementTimelineEvent represents a single enforcement action
type EnforcementTimelineEvent struct {
	Timestamp   time.Time
	EventType   string // "allowed", "denied", "error"
	SourcePod   string
	DestPod     string
	Port        int32
	Protocol    string
	RuleMatched string
	CNILatency  time.Duration // Time taken by CNI to enforce
}

// ConnectionAttempt tracks network connection attempts
type ConnectionAttempt struct {
	ID           string
	Timestamp    time.Time
	SourcePod    string
	SourceIP     string
	DestPod      string
	DestIP       string
	Port         int32
	Protocol     string
	PolicyResult string // "allowed", "denied", "no_policy"
	CNIPlugin    string
	Latency      time.Duration
}

// NewNetworkPolicyCorrelator creates a correlator that enhances the base monitor
func NewNetworkPolicyCorrelator(monitor *NetworkPolicyMonitor) *NetworkPolicyCorrelator {
	return &NetworkPolicyCorrelator{
		monitor:             monitor,
		podCNIOperations:    make(map[string]*PodCNIHistory),
		enforcementTimeline: make(map[string]*PolicyEnforcementTimeline),
		connectionAttempts:  make(map[string]*ConnectionAttempt),
	}
}

// CorrelateWithCNIEvent correlates a CNI event with network policies
func (c *NetworkPolicyCorrelator) CorrelateWithCNIEvent(event core.CNIRawEvent) *PolicyCorrelationResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := &PolicyCorrelationResult{
		Timestamp: time.Now(),
		PodName:   event.PodName,
		Namespace: event.PodNamespace,
		CNIPlugin: event.PluginName,
	}

	// Track CNI operation
	podKey := fmt.Sprintf("%s/%s", event.PodNamespace, event.PodName)
	history, exists := c.podCNIOperations[podKey]
	if !exists {
		history = &PodCNIHistory{
			PodName:    event.PodName,
			Namespace:  event.PodNamespace,
			CNIPlugin:  event.PluginName,
			CreatedAt:  event.Timestamp,
			Operations: []CNIOperation{},
			Policies:   []AppliedPolicy{},
		}
		c.podCNIOperations[podKey] = history
	}

	// Record the CNI operation
	history.LastCNIEvent = event.Timestamp
	if event.AssignedIP != "" {
		history.IPAddress = event.AssignedIP
	}

	history.Operations = append(history.Operations, CNIOperation{
		Timestamp: event.Timestamp,
		Operation: string(event.Operation),
		Success:   event.Success,
		Duration:  event.Duration,
		Error:     event.ErrorMessage,
	})

	// Find applicable network policies
	policies := c.findApplicablePolicies(event.PodNamespace, event.PodName)
	result.ApplicablePolicies = len(policies)

	// Check if this is an ADD operation
	if event.Operation == core.CNIOperationAdd && event.Success {
		// Record when policies would be applied
		for _, policy := range policies {
			history.Policies = append(history.Policies, AppliedPolicy{
				PolicyName: policy.Name,
				AppliedAt:  event.Timestamp,
				RuleCount:  len(policy.Spec.Ingress) + len(policy.Spec.Egress),
				PolicyType: getPolicyTypes(policy),
			})

			// Track in enforcement timeline
			c.trackPolicyEnforcement(policy, event)
		}

		result.PoliciesApplied = len(policies)
		result.Success = true

		if len(policies) > 0 {
			result.Message = fmt.Sprintf("CNI operation completed with %d network policies applied", len(policies))
		} else {
			result.Message = "CNI operation completed - no network policies apply to this pod"
			result.Warning = "Pod has no network policy protection"
		}
	}

	// Check for policy enforcement issues
	if event.Operation == core.CNIOperationAdd && !event.Success {
		result.Success = false
		result.Error = event.ErrorMessage

		// Check if the CNI plugin supports network policies
		if !c.cniSupportsNetworkPolicy(event.PluginName) {
			result.Warning = fmt.Sprintf("CNI plugin '%s' does not support NetworkPolicy enforcement", event.PluginName)
		}
	}

	return result
}

// AnalyzeConnectionAttempt analyzes a connection attempt against policies
func (c *NetworkPolicyCorrelator) AnalyzeConnectionAttempt(
	sourcePod, sourceNS, destPod, destNS string,
	port int32, protocol string) *ConnectionAnalysis {

	c.mu.Lock()
	defer c.mu.Unlock()

	analysis := &ConnectionAnalysis{
		Timestamp: time.Now(),
		SourcePod: fmt.Sprintf("%s/%s", sourceNS, sourcePod),
		DestPod:   fmt.Sprintf("%s/%s", destNS, destPod),
		Port:      port,
		Protocol:  protocol,
	}

	// Check source pod's egress policies
	egressAllowed, egressPolicy := c.checkEgressPolicy(sourceNS, sourcePod, destNS, destPod, port, protocol)
	analysis.EgressAllowed = egressAllowed
	if egressPolicy != nil {
		analysis.EgressPolicy = fmt.Sprintf("%s/%s", egressPolicy.Namespace, egressPolicy.Name)
	}

	// Check destination pod's ingress policies
	ingressAllowed, ingressPolicy := c.checkIngressPolicy(destNS, destPod, sourceNS, sourcePod, port, protocol)
	analysis.IngressAllowed = ingressAllowed
	if ingressPolicy != nil {
		analysis.IngressPolicy = fmt.Sprintf("%s/%s", ingressPolicy.Namespace, ingressPolicy.Name)
	}

	// Overall result
	analysis.ConnectionAllowed = egressAllowed && ingressAllowed

	if !analysis.ConnectionAllowed {
		if !egressAllowed {
			analysis.DeniedReason = "Blocked by egress policy"
		} else if !ingressAllowed {
			analysis.DeniedReason = "Blocked by ingress policy"
		}
	}

	// Track the attempt
	attemptID := fmt.Sprintf("%s-%s-%d-%s-%d",
		analysis.SourcePod, analysis.DestPod, port, protocol, time.Now().Unix())
	c.connectionAttempts[attemptID] = &ConnectionAttempt{
		ID:           attemptID,
		Timestamp:    time.Now(),
		SourcePod:    sourcePod,
		DestPod:      destPod,
		Port:         port,
		Protocol:     protocol,
		PolicyResult: c.getPolicyResult(analysis.ConnectionAllowed),
	}

	return analysis
}

// GetPodPolicyHistory returns the policy history for a pod
func (c *NetworkPolicyCorrelator) GetPodPolicyHistory(namespace, podName string) *PodPolicyHistory {
	c.mu.RLock()
	defer c.mu.RUnlock()

	podKey := fmt.Sprintf("%s/%s", namespace, podName)
	cniHistory, exists := c.podCNIOperations[podKey]
	if !exists {
		return nil
	}

	history := &PodPolicyHistory{
		PodName:       podName,
		Namespace:     namespace,
		CNIPlugin:     cniHistory.CNIPlugin,
		IPAddress:     cniHistory.IPAddress,
		CreatedAt:     cniHistory.CreatedAt,
		LastActivity:  cniHistory.LastCNIEvent,
		Policies:      cniHistory.Policies,
		CNIOperations: cniHistory.Operations,
	}

	// Add connection attempts
	for _, attempt := range c.connectionAttempts {
		if attempt.SourcePod == podName || attempt.DestPod == podName {
			history.ConnectionAttempts = append(history.ConnectionAttempts, ConnectionSummary{
				Timestamp:    attempt.Timestamp,
				Direction:    c.getConnectionDirection(podName, attempt),
				RemotePod:    c.getRemotePod(podName, attempt),
				Port:         attempt.Port,
				Protocol:     attempt.Protocol,
				PolicyResult: attempt.PolicyResult,
			})
		}
	}

	return history
}

// Private helper methods

func (c *NetworkPolicyCorrelator) findApplicablePolicies(namespace, podName string) []*networkingv1.NetworkPolicy {
	c.monitor.mu.RLock()
	defer c.monitor.mu.RUnlock()

	var policies []*networkingv1.NetworkPolicy

	// Get pod labels (in real implementation, would query k8s API)
	// For now, we check all policies in the namespace
	for _, info := range c.monitor.policyCache {
		if info.Policy.Namespace != namespace {
			continue
		}

		// Check if pod matches selector
		for _, affectedPod := range info.AffectedPods {
			if affectedPod == podName {
				policies = append(policies, info.Policy)
				break
			}
		}
	}

	return policies
}

func (c *NetworkPolicyCorrelator) trackPolicyEnforcement(policy *networkingv1.NetworkPolicy, event core.CNIRawEvent) {
	policyKey := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)

	timeline, exists := c.enforcementTimeline[policyKey]
	if !exists {
		timeline = &PolicyEnforcementTimeline{
			PolicyName: policy.Name,
			Namespace:  policy.Namespace,
			CreatedAt:  time.Now(),
			CNIPlugin:  event.PluginName,
			Events:     []EnforcementTimelineEvent{},
		}
		c.enforcementTimeline[policyKey] = timeline
	}

	// Record that policy was applied during CNI ADD
	timeline.Events = append(timeline.Events, EnforcementTimelineEvent{
		Timestamp:  event.Timestamp,
		EventType:  "policy_applied",
		SourcePod:  event.PodName,
		CNILatency: event.Duration,
	})
}

func (c *NetworkPolicyCorrelator) cniSupportsNetworkPolicy(pluginName string) bool {
	supportedPlugins := map[string]bool{
		"calico":  true,
		"cilium":  true,
		"weave":   true,
		"canal":   true,
		"antrea":  true,
		"flannel": false, // Requires additional components
		"bridge":  false,
		"macvlan": false,
	}

	supported, exists := supportedPlugins[pluginName]
	return exists && supported
}

func (c *NetworkPolicyCorrelator) checkEgressPolicy(
	sourceNS, sourcePod, destNS, destPod string,
	port int32, protocol string) (bool, *networkingv1.NetworkPolicy) {

	// In real implementation, would check actual policy rules
	// For now, return true if no egress policies exist
	policies := c.findApplicablePolicies(sourceNS, sourcePod)

	for _, policy := range policies {
		// Check if policy has egress rules
		if len(policy.Spec.Egress) > 0 {
			// Would check specific rules here
			return true, policy
		}
	}

	// No egress policies = allowed
	return true, nil
}

func (c *NetworkPolicyCorrelator) checkIngressPolicy(
	destNS, destPod, sourceNS, sourcePod string,
	port int32, protocol string) (bool, *networkingv1.NetworkPolicy) {

	// In real implementation, would check actual policy rules
	policies := c.findApplicablePolicies(destNS, destPod)

	for _, policy := range policies {
		// Check if policy has ingress rules
		if len(policy.Spec.Ingress) > 0 {
			// Would check specific rules here
			return true, policy
		}
	}

	// No ingress policies = allowed
	return true, nil
}

func (c *NetworkPolicyCorrelator) getPolicyResult(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "denied"
}

func (c *NetworkPolicyCorrelator) getConnectionDirection(podName string, attempt *ConnectionAttempt) string {
	if attempt.SourcePod == podName {
		return "egress"
	}
	return "ingress"
}

func (c *NetworkPolicyCorrelator) getRemotePod(podName string, attempt *ConnectionAttempt) string {
	if attempt.SourcePod == podName {
		return attempt.DestPod
	}
	return attempt.SourcePod
}

// Helper functions

func getPolicyTypes(policy *networkingv1.NetworkPolicy) []string {
	types := []string{}
	for _, ptype := range policy.Spec.PolicyTypes {
		types = append(types, string(ptype))
	}
	return types
}

// Result types

// PolicyCorrelationResult represents the result of correlating CNI events with policies
type PolicyCorrelationResult struct {
	Timestamp          time.Time
	PodName            string
	Namespace          string
	CNIPlugin          string
	ApplicablePolicies int
	PoliciesApplied    int
	Success            bool
	Message            string
	Warning            string
	Error              string
}

// ConnectionAnalysis represents the analysis of a connection attempt
type ConnectionAnalysis struct {
	Timestamp         time.Time
	SourcePod         string
	DestPod           string
	Port              int32
	Protocol          string
	EgressAllowed     bool
	EgressPolicy      string
	IngressAllowed    bool
	IngressPolicy     string
	ConnectionAllowed bool
	DeniedReason      string
}

// PodPolicyHistory represents the complete policy history for a pod
type PodPolicyHistory struct {
	PodName            string
	Namespace          string
	CNIPlugin          string
	IPAddress          string
	CreatedAt          time.Time
	LastActivity       time.Time
	Policies           []AppliedPolicy
	CNIOperations      []CNIOperation
	ConnectionAttempts []ConnectionSummary
}

// ConnectionSummary summarizes a connection attempt
type ConnectionSummary struct {
	Timestamp    time.Time
	Direction    string // "ingress" or "egress"
	RemotePod    string
	Port         int32
	Protocol     string
	PolicyResult string // "allowed", "denied", "no_policy"
}
