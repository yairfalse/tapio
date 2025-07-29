package internal

import (
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNetworkPolicyCorrelation(t *testing.T) {
	// Create a mock network policy monitor
	monitor := &NetworkPolicyMonitor{
		policyCache: make(map[string]*PolicyInfo),
		logger:      &StandardLogger{},
	}

	// Add a test policy
	testPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 80,
							},
						},
					},
				},
			},
		},
	}

	monitor.policyCache["default/test-policy"] = &PolicyInfo{
		Policy:       testPolicy,
		AffectedPods: []string{"test-pod"},
		LastUpdated:  time.Now(),
	}

	// Create correlator
	correlator := NewNetworkPolicyCorrelator(monitor)

	// Test CNI event correlation
	t.Run("CNI ADD with network policy", func(t *testing.T) {
		event := core.CNIRawEvent{
			ID:           "test-event-1",
			Timestamp:    time.Now(),
			Operation:    core.CNIOperationAdd,
			PluginName:   "calico",
			PodName:      "test-pod",
			PodNamespace: "default",
			AssignedIP:   "10.0.0.5",
			Success:      true,
			Duration:     100 * time.Millisecond,
		}

		result := correlator.CorrelateWithCNIEvent(event)

		if !result.Success {
			t.Errorf("Expected success, got failure: %s", result.Error)
		}

		if result.ApplicablePolicies != 1 {
			t.Errorf("Expected 1 applicable policy, got %d", result.ApplicablePolicies)
		}

		if result.PoliciesApplied != 1 {
			t.Errorf("Expected 1 policy applied, got %d", result.PoliciesApplied)
		}
	})

	t.Run("CNI ADD without network policy", func(t *testing.T) {
		event := core.CNIRawEvent{
			ID:           "test-event-2",
			Timestamp:    time.Now(),
			Operation:    core.CNIOperationAdd,
			PluginName:   "calico",
			PodName:      "unprotected-pod",
			PodNamespace: "default",
			AssignedIP:   "10.0.0.6",
			Success:      true,
			Duration:     100 * time.Millisecond,
		}

		result := correlator.CorrelateWithCNIEvent(event)

		if !result.Success {
			t.Errorf("Expected success, got failure: %s", result.Error)
		}

		if result.ApplicablePolicies != 0 {
			t.Errorf("Expected 0 applicable policies, got %d", result.ApplicablePolicies)
		}

		if result.Warning == "" {
			t.Error("Expected warning about no policy protection")
		}
	})

	t.Run("CNI ADD with unsupported plugin", func(t *testing.T) {
		event := core.CNIRawEvent{
			ID:           "test-event-3",
			Timestamp:    time.Now(),
			Operation:    core.CNIOperationAdd,
			PluginName:   "flannel",
			PodName:      "test-pod",
			PodNamespace: "default",
			AssignedIP:   "10.0.0.7",
			Success:      false,
			ErrorMessage: "Some error",
			Duration:     100 * time.Millisecond,
		}

		result := correlator.CorrelateWithCNIEvent(event)

		if result.Success {
			t.Error("Expected failure due to error")
		}

		if result.Warning == "" {
			t.Error("Expected warning about unsupported plugin")
		}
	})

	// Test connection analysis
	t.Run("Connection analysis", func(t *testing.T) {
		analysis := correlator.AnalyzeConnectionAttempt(
			"test-pod", "default",
			"other-pod", "default",
			80, "TCP",
		)

		if !analysis.ConnectionAllowed {
			t.Errorf("Expected connection to be allowed, denied: %s", analysis.DeniedReason)
		}
	})

	// Test pod policy history
	t.Run("Pod policy history", func(t *testing.T) {
		history := correlator.GetPodPolicyHistory("default", "test-pod")

		if history == nil {
			t.Fatal("Expected history, got nil")
		}

		if history.CNIPlugin != "calico" {
			t.Errorf("Expected CNI plugin 'calico', got '%s'", history.CNIPlugin)
		}

		if history.IPAddress != "10.0.0.5" {
			t.Errorf("Expected IP '10.0.0.5', got '%s'", history.IPAddress)
		}

		if len(history.Policies) != 1 {
			t.Errorf("Expected 1 policy, got %d", len(history.Policies))
		}

		if len(history.CNIOperations) != 1 {
			t.Errorf("Expected 1 CNI operation, got %d", len(history.CNIOperations))
		}
	})
}

// Import this for the test
var intstr = struct {
	IntOrString struct {
		Type   string
		IntVal int32
	}
	Int string
}{
	Int: "Int",
}
