package cni

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
)

// CorrelationEngine correlates CNI events with pod lifecycle and network policies
type CorrelationEngine struct {
	config         Config
	mu             sync.RWMutex
	correlations   map[string]*CorrelationSession
	events         chan<- domain.UnifiedEvent
	logger         Logger
	stopCh         chan struct{}
	wg             sync.WaitGroup
	incomingEvents chan domain.UnifiedEvent
}

// Config for correlation engine
type Config struct {
	CorrelationTimeout time.Duration
	EventBufferSize    int
}

// CorrelationSession tracks related events for a specific pod/container
type CorrelationSession struct {
	mu             sync.RWMutex
	SessionID      string
	PodName        string
	PodNamespace   string
	ContainerID    string
	NodeName       string
	StartTime      time.Time
	LastActivity   time.Time
	Status         SessionStatus
	Timeline       []CorrelatedEvent
	IPAllocation   *IPAllocationInfo
	NetworkPolicy  *NetworkPolicyInfo
	ChainExecution *ChainExecutionInfo
	Metrics        SessionMetrics
}

// SessionStatus represents the current state of a correlation session
type SessionStatus string

const (
	SessionStatusActive    SessionStatus = "active"
	SessionStatusCompleted SessionStatus = "completed"
	SessionStatusFailed    SessionStatus = "failed"
	SessionStatusTimeout   SessionStatus = "timeout"
)

// CorrelatedEvent represents an event in the correlation timeline
type CorrelatedEvent struct {
	Timestamp     time.Time
	EventType     string
	Source        string
	Message       string
	Success       bool
	Duration      time.Duration
	Metadata      map[string]string
	RelatedEvents []string // IDs of related events
}

// IPAllocationInfo tracks IP allocation for the session
type IPAllocationInfo struct {
	RequestedAt time.Time
	AllocatedAt time.Time
	IPAddress   string
	Subnet      string
	Pool        string
	IPAM        string
	Gateway     string
	DNS         []string
	Success     bool
	Error       string
	Duration    time.Duration
}

// NetworkPolicyInfo tracks network policy application
type NetworkPolicyInfo struct {
	AppliedPolicies []AppliedPolicy
	Violations      []PolicyViolation
	EnforcementOK   bool
	LastChecked     time.Time
}

// AppliedPolicy represents a policy applied to the pod
type AppliedPolicy struct {
	Name       string
	Namespace  string
	AppliedAt  time.Time
	Rules      PolicyRules
	EnforcedBy string // CNI plugin that enforced it
	Success    bool
}

// PolicyRules summarizes the policy rules
type PolicyRules struct {
	IngressRules int
	EgressRules  int
	DefaultDeny  bool
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	Timestamp     time.Time
	PolicyName    string
	ViolationType string
	Source        string
	Destination   string
	Port          int32
	Protocol      string
	Blocked       bool
}

// ChainExecutionInfo tracks CNI plugin chain execution
type ChainExecutionInfo struct {
	ChainName     string
	StartTime     time.Time
	EndTime       time.Time
	TotalDuration time.Duration
	PluginSteps   []PluginExecutionStep
	Success       bool
	FailedAt      string
	Error         string
}

// PluginExecutionStep tracks individual plugin execution
type PluginExecutionStep struct {
	PluginName string
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Success    bool
	Result     interface{}
	Error      string
	Order      int
}

// SessionMetrics provides metrics for a correlation session
type SessionMetrics struct {
	TotalEvents         int
	EventsByType        map[string]int
	EventsBySource      map[string]int
	TotalDuration       time.Duration
	TimeToIP            time.Duration // Time from pod creation to IP allocation
	TimeToPolicyApply   time.Duration // Time from pod creation to policy application
	TimeToChainComplete time.Duration // Time from start to chain completion
	ErrorRate           float64
	SuccessRate         float64
}

// NewCorrelationEngine creates a new correlation engine
func NewCorrelationEngine(config Config) (*CorrelationEngine, error) {
	if config.EventBufferSize <= 0 {
		config.EventBufferSize = 10000
	}
	if config.CorrelationTimeout <= 0 {
		config.CorrelationTimeout = 30 * time.Second
	}

	return &CorrelationEngine{
		config:         config,
		correlations:   make(map[string]*CorrelationSession),
		logger:         &StandardLogger{},
		stopCh:         make(chan struct{}),
		incomingEvents: make(chan domain.UnifiedEvent, config.EventBufferSize),
	}, nil
}

// Start begins the correlation engine
func (e *CorrelationEngine) Start(ctx context.Context, events chan<- domain.UnifiedEvent) error {
	e.events = events

	// Start correlation processing
	e.wg.Add(3)
	go e.processEvents(ctx)
	go e.timeoutSessions(ctx)
	go e.generateInsights(ctx)

	e.logger.Info("Correlation engine started", nil)
	return nil
}

// Stop stops the correlation engine
func (e *CorrelationEngine) Stop() error {
	close(e.stopCh)
	close(e.incomingEvents)
	e.wg.Wait()
	e.logger.Info("Correlation engine stopped", nil)
	return nil
}

// ProcessEvent processes incoming events for correlation
func (e *CorrelationEngine) ProcessEvent(event domain.UnifiedEvent) {
	select {
	case e.incomingEvents <- event:
	default:
		e.logger.Warn("Event buffer full, dropping event", map[string]interface{}{
			"event_id": event.ID,
		})
	}
}

// processEvents processes incoming events and correlates them
func (e *CorrelationEngine) processEvents(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case event, ok := <-e.incomingEvents:
			if !ok {
				return
			}
			e.correlateEvent(event)
		}
	}
}

// correlateEvent correlates an event with existing sessions
func (e *CorrelationEngine) correlateEvent(event domain.UnifiedEvent) {
	// Extract correlation keys from the event
	sessionKey := e.extractSessionKey(event)
	if sessionKey == "" {
		return // Cannot correlate this event
	}

	e.mu.Lock()
	session, exists := e.correlations[sessionKey]
	if !exists {
		session = e.createSession(sessionKey, event)
		e.correlations[sessionKey] = session
	}
	e.mu.Unlock()

	// Add event to session timeline
	e.addEventToSession(session, event)

	// Update session based on event type
	e.updateSessionState(session, event)

	// Check if session is complete
	if e.isSessionComplete(session) {
		e.completeSession(session)
	}
}

// extractSessionKey extracts a correlation key from the event
func (e *CorrelationEngine) extractSessionKey(event domain.UnifiedEvent) string {
	// Try to extract pod information
	if event.Entity != nil && event.Entity.Type == "pod" {
		return fmt.Sprintf("pod:%s:%s", event.Entity.Namespace, event.Entity.Name)
	}

	// Try to extract from semantic context
	if event.Semantic != nil && len(event.Semantic.Tags) > 0 {
		for _, tag := range event.Semantic.Tags {
			if podInfo := e.extractPodFromTag(tag); podInfo != "" {
				return podInfo
			}
		}
	}

	// Try to extract from network context (IP-based correlation)
	if event.Network != nil && event.Network.SourceIP != "" {
		return fmt.Sprintf("ip:%s", event.Network.SourceIP)
	}

	// Try to extract container ID from message or metadata
	if containerID := e.extractContainerID(event); containerID != "" {
		return fmt.Sprintf("container:%s", containerID)
	}

	return ""
}

// extractPodFromTag attempts to extract pod information from tags
func (e *CorrelationEngine) extractPodFromTag(tag string) string {
	// Look for patterns like "pod:namespace:name" or "podname"
	// This would be customized based on your tagging strategy
	return ""
}

// extractContainerID attempts to extract container ID from event
func (e *CorrelationEngine) extractContainerID(event domain.UnifiedEvent) string {
	// Look in message for container ID patterns
	// This would use regex to find container IDs
	return ""
}

// createSession creates a new correlation session
func (e *CorrelationEngine) createSession(sessionKey string, firstEvent domain.UnifiedEvent) *CorrelationSession {
	session := &CorrelationSession{
		SessionID:    generateEventID(),
		StartTime:    firstEvent.Timestamp,
		LastActivity: firstEvent.Timestamp,
		Status:       SessionStatusActive,
		Timeline:     []CorrelatedEvent{},
		Metrics: SessionMetrics{
			EventsByType:   make(map[string]int),
			EventsBySource: make(map[string]int),
		},
	}

	// Extract pod information if available
	if firstEvent.Entity != nil && firstEvent.Entity.Type == "pod" {
		session.PodName = firstEvent.Entity.Name
		session.PodNamespace = firstEvent.Entity.Namespace
	}

	return session
}

// addEventToSession adds an event to the session timeline
func (e *CorrelationEngine) addEventToSession(session *CorrelationSession, event domain.UnifiedEvent) {
	correlatedEvent := CorrelatedEvent{
		Timestamp: event.Timestamp,
		EventType: string(event.Type),
		Source:    event.Source,
		Message:   event.Message,
		Success:   !e.isErrorEvent(event),
		Metadata:  make(map[string]string),
	}

	// Calculate duration since last event
	if len(session.Timeline) > 0 {
		lastEvent := session.Timeline[len(session.Timeline)-1]
		correlatedEvent.Duration = event.Timestamp.Sub(lastEvent.Timestamp)
	}

	// Add metadata
	if event.Semantic != nil {
		correlatedEvent.Metadata["intent"] = event.Semantic.Intent
		correlatedEvent.Metadata["category"] = event.Semantic.Category
	}

	session.mu.Lock()
	session.Timeline = append(session.Timeline, correlatedEvent)
	session.LastActivity = event.Timestamp
	session.Metrics.TotalEvents++
	session.Metrics.EventsByType[string(event.Type)]++
	session.Metrics.EventsBySource[event.Source]++
	session.mu.Unlock()
}

// updateSessionState updates session state based on the event
func (e *CorrelationEngine) updateSessionState(session *CorrelationSession, event domain.UnifiedEvent) {
	session.mu.Lock()
	defer session.mu.Unlock()

	switch {
	case e.isIPAllocationEvent(event):
		e.updateIPAllocation(session, event)
	case e.isNetworkPolicyEvent(event):
		e.updateNetworkPolicy(session, event)
	case e.isChainExecutionEvent(event):
		e.updateChainExecution(session, event)
	}
}

// isIPAllocationEvent checks if event is related to IP allocation
func (e *CorrelationEngine) isIPAllocationEvent(event domain.UnifiedEvent) bool {
	eventType := string(event.Type)
	return contains(eventType, []string{"ipam", "ip_allocation", "ip_assigned"}) ||
		(event.Network != nil && event.Network.SourceIP != "")
}

// isNetworkPolicyEvent checks if event is related to network policies
func (e *CorrelationEngine) isNetworkPolicyEvent(event domain.UnifiedEvent) bool {
	eventType := string(event.Type)
	return contains(eventType, []string{"netpol", "network_policy", "policy"})
}

// isChainExecutionEvent checks if event is related to plugin chain execution
func (e *CorrelationEngine) isChainExecutionEvent(event domain.UnifiedEvent) bool {
	eventType := string(event.Type)
	return contains(eventType, []string{"chain", "plugin", "cni_execution"})
}

// updateIPAllocation updates IP allocation information
func (e *CorrelationEngine) updateIPAllocation(session *CorrelationSession, event domain.UnifiedEvent) {
	if session.IPAllocation == nil {
		session.IPAllocation = &IPAllocationInfo{
			RequestedAt: event.Timestamp,
		}
	}

	// Update based on event details
	if event.Network != nil {
		session.IPAllocation.IPAddress = event.Network.SourceIP
		session.IPAllocation.AllocatedAt = event.Timestamp
		session.IPAllocation.Success = true
		session.IPAllocation.Duration = event.Timestamp.Sub(session.IPAllocation.RequestedAt)
	}

	// Calculate time to IP
	session.Metrics.TimeToIP = session.IPAllocation.Duration
}

// updateNetworkPolicy updates network policy information
func (e *CorrelationEngine) updateNetworkPolicy(session *CorrelationSession, event domain.UnifiedEvent) {
	if session.NetworkPolicy == nil {
		session.NetworkPolicy = &NetworkPolicyInfo{
			AppliedPolicies: []AppliedPolicy{},
			Violations:      []PolicyViolation{},
		}
	}

	// Add policy application
	policy := AppliedPolicy{
		AppliedAt: event.Timestamp,
		Success:   !e.isErrorEvent(event),
	}

	session.NetworkPolicy.AppliedPolicies = append(session.NetworkPolicy.AppliedPolicies, policy)
	session.NetworkPolicy.LastChecked = event.Timestamp

	// Calculate time to policy application
	session.Metrics.TimeToPolicyApply = event.Timestamp.Sub(session.StartTime)
}

// updateChainExecution updates chain execution information
func (e *CorrelationEngine) updateChainExecution(session *CorrelationSession, event domain.UnifiedEvent) {
	if session.ChainExecution == nil {
		session.ChainExecution = &ChainExecutionInfo{
			StartTime:   event.Timestamp,
			PluginSteps: []PluginExecutionStep{},
		}
	}

	// Update end time and duration
	session.ChainExecution.EndTime = event.Timestamp
	session.ChainExecution.TotalDuration = event.Timestamp.Sub(session.ChainExecution.StartTime)
	session.ChainExecution.Success = !e.isErrorEvent(event)

	// Calculate time to chain completion
	session.Metrics.TimeToChainComplete = session.ChainExecution.TotalDuration
}

// isSessionComplete checks if a session is complete
func (e *CorrelationEngine) isSessionComplete(session *CorrelationSession) bool {
	// Session is complete if:
	// 1. We have IP allocation AND
	// 2. Network policies are applied AND
	// 3. Chain execution is done AND
	// 4. No activity for timeout period

	hasIP := session.IPAllocation != nil && session.IPAllocation.Success
	hasPolicyCheck := session.NetworkPolicy != nil
	hasChainExecution := session.ChainExecution != nil && session.ChainExecution.Success

	timeSinceActivity := time.Since(session.LastActivity)
	isTimedOut := timeSinceActivity > e.config.CorrelationTimeout

	return (hasIP && hasPolicyCheck && hasChainExecution) || isTimedOut
}

// completeSession marks a session as complete and emits insights
func (e *CorrelationEngine) completeSession(session *CorrelationSession) {
	session.mu.Lock()
	session.Status = SessionStatusCompleted
	session.Metrics.TotalDuration = time.Since(session.StartTime)

	// Calculate success/error rates
	errorEvents := 0
	for _, event := range session.Timeline {
		if !event.Success {
			errorEvents++
		}
	}

	if session.Metrics.TotalEvents > 0 {
		session.Metrics.ErrorRate = float64(errorEvents) / float64(session.Metrics.TotalEvents) * 100
		session.Metrics.SuccessRate = 100 - session.Metrics.ErrorRate
	}
	session.mu.Unlock()

	// Emit correlation insight
	e.emitCorrelationInsight(session)

	// Remove completed session after some time
	go func() {
		time.Sleep(5 * time.Minute)
		e.mu.Lock()
		delete(e.correlations, session.SessionID)
		e.mu.Unlock()
	}()
}

// emitCorrelationInsight emits a correlated insight event
func (e *CorrelationEngine) emitCorrelationInsight(session *CorrelationSession) {
	if e.events == nil {
		return
	}

	narrative := e.buildSessionNarrative(session)
	severity := e.calculateSessionSeverity(session)

	event := domain.UnifiedEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      domain.EventType("cni.correlation.session_complete"),
		Source:    "cni-correlation-engine",
		Category:  "insight",
		Severity:  severity,
		Message:   fmt.Sprintf("CNI session completed for %s/%s", session.PodNamespace, session.PodName),
		Semantic: &domain.SemanticContext{
			Intent:    "correlation-insight",
			Category:  "performance",
			Tags:      []string{"correlation", "pod-lifecycle", session.PodName},
			Narrative: narrative,
		},
	}

	select {
	case e.events <- event:
	default:
		e.logger.Warn("Event channel full, dropping correlation insight", nil)
	}
}

// buildSessionNarrative creates a human-readable narrative of what happened
func (e *CorrelationEngine) buildSessionNarrative(session *CorrelationSession) string {
	narrative := fmt.Sprintf("Pod %s/%s lifecycle completed in %v with %d events. ",
		session.PodNamespace, session.PodName, session.Metrics.TotalDuration, session.Metrics.TotalEvents)

	if session.IPAllocation != nil {
		narrative += fmt.Sprintf("IP %s allocated in %v. ",
			session.IPAllocation.IPAddress, session.Metrics.TimeToIP)
	}

	if session.NetworkPolicy != nil && len(session.NetworkPolicy.AppliedPolicies) > 0 {
		narrative += fmt.Sprintf("Network policies applied in %v. ",
			session.Metrics.TimeToPolicyApply)
	}

	if session.ChainExecution != nil {
		narrative += fmt.Sprintf("CNI chain executed in %v. ",
			session.Metrics.TimeToChainComplete)
	}

	if session.Metrics.ErrorRate > 0 {
		narrative += fmt.Sprintf("Error rate: %.1f%%. ", session.Metrics.ErrorRate)
	}

	return narrative
}

// calculateSessionSeverity determines the severity based on session metrics
func (e *CorrelationEngine) calculateSessionSeverity(session *CorrelationSession) domain.EventSeverity {
	// High error rate or long duration = warning
	if session.Metrics.ErrorRate > 20 || session.Metrics.TotalDuration > 30*time.Second {
		return domain.EventSeverityWarning
	}

	// Any errors = info
	if session.Metrics.ErrorRate > 0 {
		return domain.EventSeverityInfo
	}

	// Success = debug
	return domain.EventSeverityInfo
}

// timeoutSessions handles session timeouts
func (e *CorrelationEngine) timeoutSessions(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.cleanupTimedOutSessions()
		}
	}
}

// cleanupTimedOutSessions removes timed out sessions
func (e *CorrelationEngine) cleanupTimedOutSessions() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	for sessionID, session := range e.correlations {
		if now.Sub(session.LastActivity) > e.config.CorrelationTimeout {
			session.Status = SessionStatusTimeout
			e.completeSession(session)
			delete(e.correlations, sessionID)
		}
	}
}

// generateInsights generates periodic insights about correlation patterns
func (e *CorrelationEngine) generateInsights(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.analyzeCorrelationPatterns()
		}
	}
}

// analyzeCorrelationPatterns analyzes patterns across sessions
func (e *CorrelationEngine) analyzeCorrelationPatterns() {
	e.mu.RLock()
	sessions := make([]*CorrelationSession, 0, len(e.correlations))
	for _, session := range e.correlations {
		sessions = append(sessions, session)
	}
	e.mu.RUnlock()

	if len(sessions) == 0 {
		return
	}

	// Analyze patterns
	avgDuration := e.calculateAverageDuration(sessions)
	slowSessions := e.findSlowSessions(sessions, avgDuration*2)

	if len(slowSessions) > 0 {
		e.logger.Warn("Detected slow CNI sessions", map[string]interface{}{
			"slow_sessions": len(slowSessions),
			"avg_duration":  avgDuration,
		})
	}
}

// Utility functions
func (e *CorrelationEngine) isErrorEvent(event domain.UnifiedEvent) bool {
	return event.Severity == domain.EventSeverityError ||
		event.Severity == domain.EventSeverityCritical
}

func (e *CorrelationEngine) calculateAverageDuration(sessions []*CorrelationSession) time.Duration {
	if len(sessions) == 0 {
		return 0
	}

	var total time.Duration
	for _, session := range sessions {
		total += session.Metrics.TotalDuration
	}

	return total / time.Duration(len(sessions))
}

func (e *CorrelationEngine) findSlowSessions(sessions []*CorrelationSession, threshold time.Duration) []*CorrelationSession {
	slow := []*CorrelationSession{}
	for _, session := range sessions {
		if session.Metrics.TotalDuration > threshold {
			slow = append(slow, session)
		}
	}
	return slow
}

func contains(item string, slice []string) bool {
	for _, s := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// GetActiveSessions returns currently active correlation sessions
func (e *CorrelationEngine) GetActiveSession() map[string]*CorrelationSession {
	e.mu.RLock()
	defer e.mu.RUnlock()

	active := make(map[string]*CorrelationSession)
	for id, session := range e.correlations {
		if session.Status == SessionStatusActive {
			active[id] = session
		}
	}

	return active
}
