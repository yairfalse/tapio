package hybrid

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ProgressiveRollout manages gradual rollout of V2 engine
type ProgressiveRollout struct {
	hybrid      *HybridCorrelationEngine
	stages      []RolloutStage
	currentStage int
	startTime   time.Time
	
	// State management
	mu          sync.RWMutex
	active      bool
	paused      bool
	
	// Monitoring
	stageMetrics map[int]*StageMetrics
	
	// Configuration
	config      ProgressiveConfig
	
	// Lifecycle
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// ProgressiveConfig configures progressive rollout
type ProgressiveConfig struct {
	// Stage configuration
	AutoAdvance        bool          `json:"auto_advance"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	
	// Safety thresholds
	MaxErrorRate       float64       `json:"max_error_rate"`
	MaxLatencyIncrease float64       `json:"max_latency_increase"`
	MinStageEvents     int64         `json:"min_stage_events"`
	
	// Rollback settings
	AutoRollback       bool          `json:"auto_rollback"`
	RollbackThreshold  float64       `json:"rollback_threshold"`
	
	// Notification settings
	NotifyOnAdvance    bool          `json:"notify_on_advance"`
	NotifyOnRollback   bool          `json:"notify_on_rollback"`
}

// RolloutStage defines a stage in the progressive rollout
type RolloutStage struct {
	Name         string        `json:"name"`
	Percentage   int32         `json:"percentage"`
	MinDuration  time.Duration `json:"min_duration"`
	MaxDuration  time.Duration `json:"max_duration"`
	MinEvents    int64         `json:"min_events"`
	
	// Success criteria
	MaxErrorRate     float64   `json:"max_error_rate"`
	MaxP99Latency    time.Duration `json:"max_p99_latency"`
	
	// Safety checks
	RequireManualAdvance bool     `json:"require_manual_advance"`
	CanSkip             bool     `json:"can_skip"`
}

// StageMetrics tracks metrics for a rollout stage
type StageMetrics struct {
	StartTime       time.Time     `json:"start_time"`
	Duration        time.Duration `json:"duration"`
	EventsProcessed int64         `json:"events_processed"`
	ErrorRate       float64       `json:"error_rate"`
	P99Latency      time.Duration `json:"p99_latency"`
	HealthChecks    int           `json:"health_checks"`
	HealthFailures  int           `json:"health_failures"`
	Successful      bool          `json:"successful"`
}

// DefaultRolloutStages returns a conservative rollout plan
func DefaultRolloutStages() []RolloutStage {
	return []RolloutStage{
		{
			Name:            "Canary",
			Percentage:      1,
			MinDuration:     15 * time.Minute,
			MaxDuration:     1 * time.Hour,
			MinEvents:       1000,
			MaxErrorRate:    0.01,
			MaxP99Latency:   200 * time.Millisecond,
		},
		{
			Name:            "Small",
			Percentage:      5,
			MinDuration:     30 * time.Minute,
			MaxDuration:     2 * time.Hour,
			MinEvents:       10000,
			MaxErrorRate:    0.005,
			MaxP99Latency:   150 * time.Millisecond,
		},
		{
			Name:            "Medium",
			Percentage:      15,
			MinDuration:     1 * time.Hour,
			MaxDuration:     4 * time.Hour,
			MinEvents:       50000,
			MaxErrorRate:    0.003,
			MaxP99Latency:   120 * time.Millisecond,
		},
		{
			Name:            "Large",
			Percentage:      35,
			MinDuration:     2 * time.Hour,
			MaxDuration:     8 * time.Hour,
			MinEvents:       200000,
			MaxErrorRate:    0.002,
			MaxP99Latency:   100 * time.Millisecond,
		},
		{
			Name:            "Majority",
			Percentage:      60,
			MinDuration:     4 * time.Hour,
			MaxDuration:     12 * time.Hour,
			MinEvents:       500000,
			MaxErrorRate:    0.001,
			MaxP99Latency:   90 * time.Millisecond,
		},
		{
			Name:            "Full",
			Percentage:      100,
			MinDuration:     0,
			MaxDuration:     0,
			MinEvents:       0,
			MaxErrorRate:    0.001,
			MaxP99Latency:   80 * time.Millisecond,
		},
	}
}

// NewProgressiveRollout creates a new progressive rollout manager
func NewProgressiveRollout(hybrid *HybridCorrelationEngine, config ProgressiveConfig) *ProgressiveRollout {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ProgressiveRollout{
		hybrid:       hybrid,
		stages:       DefaultRolloutStages(),
		stageMetrics: make(map[int]*StageMetrics),
		config:       config,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start begins the progressive rollout
func (p *ProgressiveRollout) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.active {
		return fmt.Errorf("progressive rollout already active")
	}
	
	p.active = true
	p.startTime = time.Now()
	p.currentStage = 0
	
	// Initialize first stage
	if err := p.advanceToStage(0); err != nil {
		p.active = false
		return fmt.Errorf("failed to start first stage: %w", err)
	}
	
	// Start monitoring
	p.wg.Add(1)
	go p.monitor()
	
	if p.config.NotifyOnAdvance {
		fmt.Printf("Progressive rollout started - Stage 0: %s (%d%%)\n", 
			p.stages[0].Name, p.stages[0].Percentage)
	}
	
	return nil
}

// Stop stops the progressive rollout
func (p *ProgressiveRollout) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if !p.active {
		return nil
	}
	
	p.cancel()
	p.active = false
	
	// Wait for monitoring to stop
	p.wg.Wait()
	
	return nil
}

// Pause pauses the rollout at the current stage
func (p *ProgressiveRollout) Pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.paused = true
	fmt.Println("Progressive rollout paused")
}

// Resume resumes the rollout
func (p *ProgressiveRollout) Resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.paused = false
	fmt.Println("Progressive rollout resumed")
}

// AdvanceStage manually advances to the next stage
func (p *ProgressiveRollout) AdvanceStage() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if !p.active {
		return fmt.Errorf("rollout not active")
	}
	
	if p.currentStage >= len(p.stages)-1 {
		return fmt.Errorf("already at final stage")
	}
	
	return p.advanceToStage(p.currentStage + 1)
}

// RollbackToPrevious rolls back to the previous stage
func (p *ProgressiveRollout) RollbackToPrevious() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if !p.active {
		return fmt.Errorf("rollout not active")
	}
	
	if p.currentStage <= 0 {
		// Roll back to V1 only
		p.hybrid.UpdateV2Percentage(0)
		p.hybrid.performRollback("Manual rollback during progressive rollout")
		return nil
	}
	
	prevStage := p.currentStage - 1
	return p.advanceToStage(prevStage)
}

// RollbackToV1 completely rolls back to V1-only
func (p *ProgressiveRollout) RollbackToV1(reason string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Stop rollout
	p.active = false
	p.cancel()
	
	// Roll back to V1
	p.hybrid.UpdateV2Percentage(0)
	p.hybrid.performRollback(fmt.Sprintf("Progressive rollout rollback: %s", reason))
	
	if p.config.NotifyOnRollback {
		fmt.Printf("Progressive rollout rolled back to V1: %s\n", reason)
	}
	
	return nil
}

// GetStatus returns the current rollout status
func (p *ProgressiveRollout) GetStatus() RolloutStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	status := RolloutStatus{
		Active:       p.active,
		Paused:       p.paused,
		CurrentStage: p.currentStage,
		StartTime:    p.startTime,
		TotalStages:  len(p.stages),
	}
	
	if p.active && p.currentStage < len(p.stages) {
		stage := p.stages[p.currentStage]
		status.StageName = stage.Name
		status.StagePercentage = stage.Percentage
		
		if metrics, exists := p.stageMetrics[p.currentStage]; exists {
			status.StageStartTime = metrics.StartTime
			status.StageDuration = time.Since(metrics.StartTime)
			status.StageEvents = metrics.EventsProcessed
			status.StageErrorRate = metrics.ErrorRate
		}
	}
	
	return status
}

// monitor continuously monitors the rollout progress
func (p *ProgressiveRollout) monitor() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.checkAndAdvance(); err != nil {
				fmt.Printf("Rollout monitoring error: %v\n", err)
			}
		}
	}
}

// checkAndAdvance checks if we should advance to the next stage
func (p *ProgressiveRollout) checkAndAdvance() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if !p.active || p.paused {
		return nil
	}
	
	if p.currentStage >= len(p.stages)-1 {
		// Already at final stage
		return nil
	}
	
	stage := p.stages[p.currentStage]
	metrics := p.stageMetrics[p.currentStage]
	
	// Update metrics
	p.updateStageMetrics()
	
	// Check if we should rollback
	if p.shouldRollback(stage, metrics) {
		return p.RollbackToV1("Health check failed")
	}
	
	// Check if we can advance
	if p.canAdvanceStage(stage, metrics) && p.config.AutoAdvance && !stage.RequireManualAdvance {
		return p.advanceToStage(p.currentStage + 1)
	}
	
	return nil
}

// shouldRollback determines if we should rollback based on current metrics
func (p *ProgressiveRollout) shouldRollback(stage RolloutStage, metrics *StageMetrics) bool {
	if !p.config.AutoRollback {
		return false
	}
	
	// Check error rate
	if metrics.ErrorRate > stage.MaxErrorRate {
		return true
	}
	
	// Check latency
	if metrics.P99Latency > stage.MaxP99Latency {
		return true
	}
	
	// Check health check failures
	if metrics.HealthChecks > 10 && float64(metrics.HealthFailures)/float64(metrics.HealthChecks) > p.config.RollbackThreshold {
		return true
	}
	
	return false
}

// canAdvanceStage determines if we can advance to the next stage
func (p *ProgressiveRollout) canAdvanceStage(stage RolloutStage, metrics *StageMetrics) bool {
	// Check minimum duration
	if metrics.Duration < stage.MinDuration {
		return false
	}
	
	// Check minimum events
	if metrics.EventsProcessed < stage.MinEvents {
		return false
	}
	
	// Check success criteria
	if metrics.ErrorRate > stage.MaxErrorRate {
		return false
	}
	
	if metrics.P99Latency > stage.MaxP99Latency {
		return false
	}
	
	// Check maximum duration (force advance)
	if stage.MaxDuration > 0 && metrics.Duration >= stage.MaxDuration {
		return true
	}
	
	return true
}

// advanceToStage advances to a specific stage
func (p *ProgressiveRollout) advanceToStage(stageIndex int) error {
	if stageIndex >= len(p.stages) {
		return fmt.Errorf("stage index %d out of range", stageIndex)
	}
	
	stage := p.stages[stageIndex]
	
	// Update traffic percentage
	p.hybrid.UpdateV2Percentage(stage.Percentage)
	
	// Initialize stage metrics
	p.stageMetrics[stageIndex] = &StageMetrics{
		StartTime: time.Now(),
	}
	
	p.currentStage = stageIndex
	
	if p.config.NotifyOnAdvance {
		fmt.Printf("Advanced to stage %d: %s (%d%%)\n", 
			stageIndex, stage.Name, stage.Percentage)
	}
	
	return nil
}

// updateStageMetrics updates metrics for the current stage
func (p *ProgressiveRollout) updateStageMetrics() {
	if p.currentStage >= len(p.stages) {
		return
	}
	
	metrics := p.stageMetrics[p.currentStage]
	if metrics == nil {
		return
	}
	
	// Update duration
	metrics.Duration = time.Since(metrics.StartTime)
	
	// Get hybrid engine stats
	stats := p.hybrid.GetStats()
	hybridStats := stats.HybridStats.(map[string]interface{})
	hybridMetrics := hybridStats["metrics"].(map[string]interface{})
	
	// Update error rate
	if errors, ok := hybridMetrics["errors"].(map[string]interface{}); ok {
		if errorRateStr, ok := errors["v2_error_rate"].(string); ok {
			// Parse error rate string (format: "0.0123")
			var errorRate float64
			fmt.Sscanf(errorRateStr, "%f", &errorRate)
			metrics.ErrorRate = errorRate
		}
	}
	
	// Update latency
	if latency, ok := hybridMetrics["latency"].(map[string]interface{}); ok {
		if p99, ok := latency["v2_p99"].(time.Duration); ok {
			metrics.P99Latency = p99
		}
	}
	
	// Update events processed
	if usage, ok := hybridMetrics["usage"].(map[string]interface{}); ok {
		if v2Count, ok := usage["v2_count"].(uint64); ok {
			metrics.EventsProcessed = int64(v2Count)
		}
	}
	
	// Health check
	metrics.HealthChecks++
	if err := p.hybrid.Health(); err != nil {
		metrics.HealthFailures++
	}
}

// RolloutStatus represents the current status of the rollout
type RolloutStatus struct {
	Active           bool          `json:"active"`
	Paused           bool          `json:"paused"`
	CurrentStage     int           `json:"current_stage"`
	TotalStages      int           `json:"total_stages"`
	StageName        string        `json:"stage_name"`
	StagePercentage  int32         `json:"stage_percentage"`
	StartTime        time.Time     `json:"start_time"`
	StageStartTime   time.Time     `json:"stage_start_time"`
	StageDuration    time.Duration `json:"stage_duration"`
	StageEvents      int64         `json:"stage_events"`
	StageErrorRate   float64       `json:"stage_error_rate"`
}

// GetStageMetrics returns metrics for a specific stage
func (p *ProgressiveRollout) GetStageMetrics(stageIndex int) (*StageMetrics, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	metrics, exists := p.stageMetrics[stageIndex]
	return metrics, exists
}

// GetAllStageMetrics returns metrics for all stages
func (p *ProgressiveRollout) GetAllStageMetrics() map[int]*StageMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	result := make(map[int]*StageMetrics)
	for k, v := range p.stageMetrics {
		result[k] = v
	}
	
	return result
}

// SetStages updates the rollout stages (only when not active)
func (p *ProgressiveRollout) SetStages(stages []RolloutStage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.active {
		return fmt.Errorf("cannot update stages while rollout is active")
	}
	
	p.stages = stages
	return nil
}