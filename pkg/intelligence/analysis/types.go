package analysis

import (
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
)

// Finding represents an aggregated finding from multiple correlations
type Finding struct {
	ID             string               `json:"id"`
	Type           FindingType          `json:"type"`
	Severity       domain.EventSeverity `json:"severity"`
	Confidence     float64              `json:"confidence"` // 0.0 to 1.0
	Title          string               `json:"title"`
	Summary        string               `json:"summary"`
	Evidence       []Evidence           `json:"evidence"`
	Impacts        []Impact             `json:"impacts"`
	RootCause      *RootCause           `json:"root_cause,omitempty"`
	Pattern        *Pattern             `json:"pattern,omitempty"`
	FirstSeen      time.Time            `json:"first_seen"`
	LastSeen       time.Time            `json:"last_seen"`
	EventCount     int                  `json:"event_count"`
	Sources        []string             `json:"sources"`         // Which correlators contributed
	CorrelationIDs []string             `json:"correlation_ids"` // IDs of correlations that contributed
}

// FindingType categorizes findings
type FindingType string

const (
	FindingTypeIncident      FindingType = "incident"
	FindingTypePerformance   FindingType = "performance"
	FindingTypeConfiguration FindingType = "configuration"
	FindingTypeSecurity      FindingType = "security"
	FindingTypeCapacity      FindingType = "capacity"
	FindingTypeAvailability  FindingType = "availability"
)

// Evidence supports a finding
type Evidence struct {
	Type        EvidenceType `json:"type"`
	Source      string       `json:"source"`
	Description string       `json:"description"`
	Confidence  float64      `json:"confidence"`
	Timestamp   time.Time    `json:"timestamp"`
	Data        interface{}  `json:"data,omitempty"`
}

// EvidenceType categorizes evidence
type EvidenceType string

const (
	EvidenceTypeDirect     EvidenceType = "direct"     // Directly observed
	EvidenceTypeCorrelated EvidenceType = "correlated" // From correlation
	EvidenceTypeInferred   EvidenceType = "inferred"   // Deduced from patterns
	EvidenceTypeHistorical EvidenceType = "historical" // From past incidents
)

// Impact describes what's affected
type Impact struct {
	Type        ImpactType           `json:"type"`
	Severity    domain.EventSeverity `json:"severity"`
	Description string               `json:"description"`
	Resources   []ResourceRef        `json:"resources"`
	Services    []string             `json:"services,omitempty"`
	Users       int                  `json:"users,omitempty"`
	Duration    time.Duration        `json:"duration,omitempty"`
}

// ImpactType categorizes impacts
type ImpactType string

const (
	ImpactTypeService      ImpactType = "service"
	ImpactTypePerformance  ImpactType = "performance"
	ImpactTypeAvailability ImpactType = "availability"
	ImpactTypeData         ImpactType = "data"
	ImpactTypeUser         ImpactType = "user"
)

// ResourceRef identifies a resource
type ResourceRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`
}

// RootCause identifies the source of an issue
type RootCause struct {
	EventID     string       `json:"event_id"`
	Type        string       `json:"type"`
	Description string       `json:"description"`
	Confidence  float64      `json:"confidence"`
	Evidence    []Evidence   `json:"evidence"`
	Resource    *ResourceRef `json:"resource,omitempty"`
}

// Pattern represents a detected pattern
type Pattern struct {
	ID          string      `json:"id"`
	Type        PatternType `json:"type"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Confidence  float64     `json:"confidence"`
	Occurrences int         `json:"occurrences"`
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
	Signature   []string    `json:"signature"` // Event sequence that defines pattern
}

// PatternType categorizes patterns
type PatternType string

const (
	PatternTypeCascading   PatternType = "cascading"   // Cascading failures
	PatternTypePeriodic    PatternType = "periodic"    // Recurring issues
	PatternTypeProgressive PatternType = "progressive" // Gradually worsening
	PatternTypeCorrelated  PatternType = "correlated"  // Co-occurring events
	PatternTypeSequential  PatternType = "sequential"  // Specific sequence
)

// Insight provides human-readable understanding
type Insight struct {
	ID          string      `json:"id"`
	Type        InsightType `json:"type"`
	Priority    Priority    `json:"priority"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Explanation string      `json:"explanation"` // Why this matters
	Evidence    []string    `json:"evidence"`    // Supporting facts
	Confidence  float64     `json:"confidence"`
	GeneratedAt time.Time   `json:"generated_at"`
}

// InsightType categorizes insights
type InsightType string

const (
	InsightTypeTrend        InsightType = "trend"
	InsightTypeAnomaly      InsightType = "anomaly"
	InsightTypeRisk         InsightType = "risk"
	InsightTypeOptimization InsightType = "optimization"
	InsightTypePrediction   InsightType = "prediction"
)

// Priority for insights and recommendations
type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityMedium   Priority = "medium"
	PriorityLow      Priority = "low"
)

// Recommendation suggests actions
type Recommendation struct {
	ID          string      `json:"id"`
	Type        ActionType  `json:"type"`
	Priority    Priority    `json:"priority"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Rationale   string      `json:"rationale"` // Why do this
	Impact      string      `json:"impact"`    // What will improve
	Risk        string      `json:"risk"`      // Potential downsides
	Steps       []string    `json:"steps"`     // How to implement
	Automation  *Automation `json:"automation,omitempty"`
	Confidence  float64     `json:"confidence"`
}

// ActionType categorizes recommendations
type ActionType string

const (
	ActionTypeRemediate   ActionType = "remediate"
	ActionTypeMitigate    ActionType = "mitigate"
	ActionTypeInvestigate ActionType = "investigate"
	ActionTypeOptimize    ActionType = "optimize"
	ActionTypePrevent     ActionType = "prevent"
)

// Automation describes automated remediation
type Automation struct {
	Available         bool          `json:"available"`
	Script            string        `json:"script,omitempty"`
	Commands          []string      `json:"commands,omitempty"`
	RequiresApproval  bool          `json:"requires_approval"`
	EstimatedDuration time.Duration `json:"estimated_duration,omitempty"`
}

// AnalysisReport is the complete output of analysis
type AnalysisReport struct {
	ID                string           `json:"id"`
	Timestamp         time.Time        `json:"timestamp"`
	TimeWindow        time.Duration    `json:"time_window"`
	Findings          []Finding        `json:"findings"`
	Patterns          []Pattern        `json:"patterns"`
	Insights          []Insight        `json:"insights"`
	Recommendations   []Recommendation `json:"recommendations"`
	Summary           string           `json:"summary"`
	OverallConfidence float64          `json:"overall_confidence"`
	Quality           QualityMetrics   `json:"quality"`
	Statistics        AnalysisStats    `json:"statistics"`
}

// QualityMetrics measures analysis quality
type QualityMetrics struct {
	DataCompleteness    float64 `json:"data_completeness"` // 0.0 to 1.0
	EvidenceStrength    float64 `json:"evidence_strength"`
	CorrelatorAgreement float64 `json:"correlator_agreement"`
	PatternClarity      float64 `json:"pattern_clarity"`
}

// AnalysisStats provides statistics
type AnalysisStats struct {
	EventsAnalyzed    int           `json:"events_analyzed"`
	CorrelationsFound int           `json:"correlations_found"`
	PatternsDetected  int           `json:"patterns_detected"`
	ProcessingTime    time.Duration `json:"processing_time"`
	CorrelatorsUsed   []string      `json:"correlators_used"`
	TimeRange         TimeRange     `json:"time_range"`
}

// TimeRange represents a time period
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ScoreContext provides context for scoring
type ScoreContext struct {
	CorrelatorAgreement int     // How many correlators agree
	TotalCorrelators    int     // Total correlators that processed
	EvidenceCount       int     // Number of evidence pieces
	DirectEvidence      int     // Direct vs indirect evidence
	TimeProximity       float64 // How close events are in time (0.0 to 1.0)
	PatternMatch        bool    // Matches known pattern
	HistoricalMatch     bool    // Similar to past incidents
	DataQuality         float64 // Quality of input data (0.0 to 1.0)
}
