package analysis

import (
	"sync"
	"time"
)

// HistoryStore stores historical analysis results for pattern matching
type HistoryStore interface {
	// Store a finding for future pattern matching
	StoreFinding(finding Finding) error

	// Get similar past findings
	GetSimilarFindings(finding Finding, limit int) ([]Finding, error)

	// Get findings within a time range
	GetFindingsInRange(start, end time.Time) ([]Finding, error)

	// Store a pattern occurrence
	StorePattern(pattern Pattern) error

	// Get pattern history
	GetPatternHistory(patternType PatternType, limit int) ([]Pattern, error)

	// Clean old data
	Cleanup(olderThan time.Duration) error
}

// MemoryHistoryStore is a simple in-memory implementation
type MemoryHistoryStore struct {
	mu       sync.RWMutex
	findings []Finding
	patterns []Pattern
	maxSize  int
}

// NewMemoryHistoryStore creates an in-memory history store
func NewMemoryHistoryStore() *MemoryHistoryStore {
	return &MemoryHistoryStore{
		findings: make([]Finding, 0, 1000),
		patterns: make([]Pattern, 0, 100),
		maxSize:  1000,
	}
}

// StoreFinding stores a finding
func (s *MemoryHistoryStore) StoreFinding(finding Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Add to front
	s.findings = append([]Finding{finding}, s.findings...)

	// Trim if too large
	if len(s.findings) > s.maxSize {
		s.findings = s.findings[:s.maxSize]
	}

	return nil
}

// GetSimilarFindings finds similar past findings
func (s *MemoryHistoryStore) GetSimilarFindings(finding Finding, limit int) ([]Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var similar []Finding

	for _, f := range s.findings {
		// Simple similarity: same type and overlapping events
		if f.Type == finding.Type {
			if hasOverlap(f.Sources, finding.Sources) {
				similar = append(similar, f)
				if len(similar) >= limit {
					break
				}
			}
		}
	}

	return similar, nil
}

// GetFindingsInRange gets findings in a time range
func (s *MemoryHistoryStore) GetFindingsInRange(start, end time.Time) ([]Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Finding

	for _, f := range s.findings {
		if f.FirstSeen.After(start) && f.LastSeen.Before(end) {
			results = append(results, f)
		}
	}

	return results, nil
}

// StorePattern stores a pattern
func (s *MemoryHistoryStore) StorePattern(pattern Pattern) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if pattern already exists and update it
	for i, p := range s.patterns {
		if p.Type == pattern.Type && p.Name == pattern.Name {
			// Update existing pattern
			s.patterns[i].Occurrences++
			s.patterns[i].LastSeen = pattern.LastSeen
			if pattern.Confidence > s.patterns[i].Confidence {
				s.patterns[i].Confidence = pattern.Confidence
			}
			return nil
		}
	}

	// Add new pattern
	s.patterns = append(s.patterns, pattern)

	return nil
}

// GetPatternHistory gets pattern history
func (s *MemoryHistoryStore) GetPatternHistory(patternType PatternType, limit int) ([]Pattern, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Pattern

	for _, p := range s.patterns {
		if p.Type == patternType {
			results = append(results, p)
			if len(results) >= limit {
				break
			}
		}
	}

	return results, nil
}

// Cleanup removes old data
func (s *MemoryHistoryStore) Cleanup(olderThan time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)

	// Clean findings
	newFindings := []Finding{}
	for _, f := range s.findings {
		if f.LastSeen.After(cutoff) {
			newFindings = append(newFindings, f)
		}
	}
	s.findings = newFindings

	// Clean patterns
	newPatterns := []Pattern{}
	for _, p := range s.patterns {
		if p.LastSeen.After(cutoff) {
			newPatterns = append(newPatterns, p)
		}
	}
	s.patterns = newPatterns

	return nil
}

// Helper function to check slice overlap
func hasOverlap(a, b []string) bool {
	aMap := make(map[string]bool)
	for _, item := range a {
		aMap[item] = true
	}

	for _, item := range b {
		if aMap[item] {
			return true
		}
	}

	return false
}
