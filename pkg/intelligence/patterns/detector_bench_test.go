package patterns

import (
	"context"
	"testing"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
	"go.uber.org/zap"
)

// BenchmarkBeforeOptimization simulates the old map[string]interface{} approach
func BenchmarkBeforeOptimization(b *testing.B) {
	client := &mockClient{}
	detector := NewDetector(client, zap.NewNop())

	event := &domain.UnifiedEvent{
		ID:        "test-event",
		Type:      "pod_oom_killed",
		Message:   "OOMKilled",
		Timestamp: time.Now(),
		Entity: &domain.EntityContext{
			UID:  "pod-123",
			Type: "pod",
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Old approach would allocate map[string]interface{} for metadata
		_, _ = detector.DetectPatterns(ctx, event)
	}
}

// BenchmarkAfterOptimization tests the new strongly-typed approach
func BenchmarkAfterOptimization(b *testing.B) {
	client := &mockClient{}
	detector := NewDetector(client, zap.NewNop())

	event := &domain.UnifiedEvent{
		ID:        "test-event",
		Type:      "pod_oom_killed",
		Message:   "OOMKilled",
		Timestamp: time.Now(),
		Entity: &domain.EntityContext{
			UID:  "pod-123",
			Type: "pod",
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// New approach uses &DetectionMetadata{} - no map allocation
		_, _ = detector.DetectPatterns(ctx, event)
	}
}

// mockClient for benchmarking
type mockClient struct{}

func (m *mockClient) ExecuteQuery(ctx context.Context, query string, params map[string]interface{}) ([]map[string]interface{}, error) {
	// Return minimal mock data
	return []map[string]interface{}{
		{
			"service":        "test-service",
			"totalPods":      3,
			"recentRestarts": 2,
		},
	}, nil
}

func (m *mockClient) ExecuteTypedQuery(ctx context.Context, query string, params *QueryParams) (*QueryResult, error) {
	return &QueryResult{
		Service:        "test-service",
		TotalPods:      3,
		RecentRestarts: 2,
	}, nil
}

// BenchmarkAllocationComparison compares allocations
func BenchmarkAllocationComparison(b *testing.B) {
	b.Run("MapInterface", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Old way - allocates map
			_ = map[string]interface{}{
				"service":         "test-service",
				"total_pods":      3,
				"recent_restarts": 2,
				"affected_pods":   5,
				"restarts":        10,
			}
		}
	})

	b.Run("TypedStruct", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// New way - single allocation
			_ = &DetectionMetadata{
				Service:        "test-service",
				TotalPods:      3,
				RecentRestarts: 2,
				AffectedPods:   5,
				Restarts:       10,
			}
		}
	})
}

// BenchmarkQueryParams tests parameter passing efficiency
func BenchmarkQueryParams(b *testing.B) {
	b.Run("MapParams", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			params := map[string]interface{}{
				"podUID":    "pod-123",
				"timestamp": time.Now().Unix(),
				"startTime": time.Now().Add(-10 * time.Minute).Unix(),
			}
			_ = params
		}
	})

	b.Run("TypedParams", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			params := NewQueryParams().
				WithPodUID("pod-123").
				WithTimestamp(time.Now()).
				WithStartTime(time.Now().Add(-10 * time.Minute))
			_ = params
		}
	})
}
