package rules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yairfalse/tapio/pkg/events_correlation"
)

// EnhancedCrashLoopDetection provides intelligent crash loop analysis with exit code analysis and change correlation
func EnhancedCrashLoopDetection() *events_correlation.Rule {
	return &events_correlation.Rule{
		ID:          "enhanced-crash-loop-detection",
		Name:        "Enhanced Crash Loop Detection",
		Description: "Detects crash loops with context including exit codes, recent changes, and specific failure patterns",
		Category:    events_correlation.CategoryReliability,
		Version:     "2.0.0",
		Author:      "Tapio Team",
		Tags:        []string{"crash", "loop", "restart", "exit-code", "intelligent"},

		MinConfidence: 0.7,
		Cooldown:      2 * time.Minute, // Shorter cooldown for crash loops
		TTL:           30 * time.Minute,

		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceKubernetes,
		},
		OptionalSources: []events_correlation.EventSource{
			events_correlation.SourceEBPF,
			events_correlation.SourceSystemd,
		},

		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			// Get pod restart events
			restartEvents := ctx.GetEvents(events_correlation.Filter{
				Source: events_correlation.SourceKubernetes,
				Type:   "pod.restart",
				Since:  ctx.Window.Start,
			})

			if len(restartEvents) < 3 {
				return nil // Need at least 3 restarts to consider it a loop
			}

			// Group restarts by pod to find crash loops
			podRestarts := make(map[string][]events_correlation.Event)
			for _, event := range restartEvents {
				podKey := fmt.Sprintf("%s/%s", event.Entity.Namespace, event.Entity.Pod)
				podRestarts[podKey] = append(podRestarts[podKey], event)
			}

			// Find pods in crash loops
			crashLoopPods := make(map[string][]events_correlation.Event)
			for podKey, restarts := range podRestarts {
				if len(restarts) >= 3 {
					// Sort by timestamp
					sort.Slice(restarts, func(i, j int) bool {
						return restarts[i].Timestamp.Before(restarts[j].Timestamp)
					})

					// Check if restarts are within a reasonable crash loop timeframe
					timespan := restarts[len(restarts)-1].Timestamp.Sub(restarts[0].Timestamp)
					if timespan <= 15*time.Minute { // Crash loops typically happen quickly
						crashLoopPods[podKey] = restarts
					}
				}
			}

			if len(crashLoopPods) == 0 {
				return nil // No crash loops detected
			}

			// Analyze the most problematic pod (most restarts)
			var primaryPod string
			var primaryRestarts []events_correlation.Event
			maxRestarts := 0

			for podKey, restarts := range crashLoopPods {
				if len(restarts) > maxRestarts {
					maxRestarts = len(restarts)
					primaryPod = podKey
					primaryRestarts = restarts
				}
			}

			// Get exit code information from eBPF events
			exitCodeAnalysis := analyzeExitCodes(ctx, primaryRestarts)

			// Look for recent configuration changes that might be causing the crashes
			changeAnalysis := analyzeRecentChanges(ctx, primaryRestarts[0])

			// Analyze restart pattern (frequency, timing)
			patternAnalysis := analyzeRestartPattern(primaryRestarts)

			// Get additional context from logs/systemd if available
			errorContext := getErrorContext(ctx, primaryRestarts)

			// Calculate confidence based on multiple factors
			confidence := calculateCrashLoopConfidence(
				len(primaryRestarts),
				patternAnalysis,
				exitCodeAnalysis,
				changeAnalysis,
			)

			// Determine severity based on impact and restart frequency
			severity := determineCrashLoopSeverity(
				len(crashLoopPods),
				len(primaryRestarts),
				patternAnalysis,
			)

			// Generate intelligent root cause analysis
			rootCause, recommendations := generateRootCauseAnalysis(
				exitCodeAnalysis,
				changeAnalysis,
				patternAnalysis,
				errorContext,
			)

			// Build comprehensive timeline
			timeline := buildCrashLoopTimeline(primaryRestarts, changeAnalysis)

			// Collect all evidence
			evidence := events_correlation.Evidence{
				Events:   primaryRestarts,
				Timeline: timeline,
				Entities: []events_correlation.Entity{primaryRestarts[0].Entity},
				Metrics: map[string]float64{
					"total_restarts":     float64(len(primaryRestarts)),
					"affected_pods":      float64(len(crashLoopPods)),
					"avg_restart_interval": patternAnalysis.AvgInterval.Seconds(),
					"confidence_score":   confidence,
				},
				Patterns: []string{
					fmt.Sprintf("Restart pattern: %s", patternAnalysis.Pattern),
					fmt.Sprintf("Exit code pattern: %s", exitCodeAnalysis.Pattern),
				},
			}

			if changeAnalysis.HasRecentChanges {
				evidence.Patterns = append(evidence.Patterns, 
					fmt.Sprintf("Recent change detected: %s", changeAnalysis.ChangeType))
			}

			return &events_correlation.Result{
				Confidence:  confidence,
				Severity:    severity,
				Title:       generateCrashLoopTitle(primaryPod, len(primaryRestarts), rootCause),
				Description: generateCrashLoopDescription(primaryPod, primaryRestarts, rootCause, exitCodeAnalysis),
				Impact:      generateImpactAssessment(crashLoopPods, patternAnalysis),
				Evidence:    evidence,
				Recommendations: recommendations,
				Actions: generateCrashLoopActions(primaryPod, severity, exitCodeAnalysis, changeAnalysis),
			}
		},
	}
}

// ExitCodeAnalysis contains analysis of exit codes from crashes
type ExitCodeAnalysis struct {
	MostCommonExitCode int
	Pattern           string
	Confidence        float64
	RootCause         string
	FixSuggestion     string
}

// ChangeAnalysis contains information about recent changes that might cause crashes  
type ChangeAnalysis struct {
	HasRecentChanges bool
	ChangeType       string
	TimeAgo          time.Duration
	ChangeDetails    string
	Confidence       float64
}

// PatternAnalysis contains restart timing pattern analysis
type PatternAnalysis struct {
	Pattern       string
	AvgInterval   time.Duration
	IsAccelerating bool
	Confidence    float64
}

// ErrorContext contains additional error information from logs/systemd
type ErrorContext struct {
	HasErrorLogs  bool
	ErrorPattern  string
	ErrorMessages []string
}

// analyzeExitCodes analyzes exit codes to determine likely crash causes
func analyzeExitCodes(ctx *events_correlation.Context, restarts []events_correlation.Event) ExitCodeAnalysis {
	exitCodes := make(map[int]int)
	
	// Extract exit codes from event attributes
	for _, event := range restarts {
		if exitCodeStr, ok := event.Attributes["exit_code"].(string); ok {
			if exitCode, err := strconv.Atoi(exitCodeStr); err == nil {
				exitCodes[exitCode]++
			}
		}
	}

	if len(exitCodes) == 0 {
		return ExitCodeAnalysis{
			Pattern:    "unknown",
			Confidence: 0.1,
			RootCause:  "Exit codes not available",
			FixSuggestion: "Check container logs for error details",
		}
	}

	// Find most common exit code
	var mostCommon int
	var maxCount int
	for code, count := range exitCodes {
		if count > maxCount {
			maxCount = count
			mostCommon = code
		}
	}

	// Analyze exit code meaning
	confidence := float64(maxCount) / float64(len(restarts))
	return analyzeExitCodeMeaning(mostCommon, confidence)
}

// analyzeExitCodeMeaning provides detailed analysis of exit code meanings
func analyzeExitCodeMeaning(exitCode int, confidence float64) ExitCodeAnalysis {
	switch exitCode {
	case 0:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "clean_exit",
			Confidence:        confidence,
			RootCause:         "Application exiting normally but restarting (possible configuration issue)",
			FixSuggestion:     "Check application startup configuration and health checks",
		}
	case 1:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "general_error",
			Confidence:        confidence,
			RootCause:         "General application error (likely configuration or dependency issue)",
			FixSuggestion:     "Check application logs, environment variables, and external dependencies",
		}
	case 125:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "container_run_error",
			Confidence:        confidence,
			RootCause:         "Container failed to run (image or runtime issue)",
			FixSuggestion:     "Verify container image exists and is pullable, check resource requirements",
		}
	case 126:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "permission_error",
			Confidence:        confidence,
			RootCause:         "Permission denied or file not executable",
			FixSuggestion:     "Check file permissions, SecurityContext, and user/group settings",
		}
	case 127:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "command_not_found",
			Confidence:        confidence,
			RootCause:         "Command not found in container",
			FixSuggestion:     "Verify command path in container image and fix container CMD/ENTRYPOINT",
		}
	case 137:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "sigkill",
			Confidence:        confidence,
			RootCause:         "Container killed by SIGKILL (likely OOM or resource limits)",
			FixSuggestion:     "Increase memory limits or investigate memory usage patterns",
		}
	case 143:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "sigterm",
			Confidence:        confidence,
			RootCause:         "Container terminated by SIGTERM (graceful shutdown)",
			FixSuggestion:     "Check if application handles SIGTERM properly or if shutdown takes too long",
		}
	default:
		return ExitCodeAnalysis{
			MostCommonExitCode: exitCode,
			Pattern:           "custom_error",
			Confidence:        confidence,
			RootCause:         fmt.Sprintf("Application-specific error (exit code %d)", exitCode),
			FixSuggestion:     "Check application documentation for exit code meaning and review logs",
		}
	}
}

// analyzeRecentChanges looks for recent configuration changes that might cause crashes
func analyzeRecentChanges(ctx *events_correlation.Context, firstRestart events_correlation.Event) ChangeAnalysis {
	// Look for deployment/config changes in the last hour before first restart
	lookbackTime := firstRestart.Timestamp.Add(-1 * time.Hour)
	
	// Check for deployment events
	deploymentEvents := ctx.GetEvents(events_correlation.Filter{
		Source: events_correlation.SourceKubernetes,
		Type:   "deployment.updated",
		Since:  lookbackTime,
		Until:  firstRestart.Timestamp,
	})

	// Check for configmap/secret changes
	configEvents := ctx.GetEvents(events_correlation.Filter{
		Source: events_correlation.SourceKubernetes,
		Type:   "configmap.updated",
		Since:  lookbackTime,
		Until:  firstRestart.Timestamp,
	})

	secretEvents := ctx.GetEvents(events_correlation.Filter{
		Source: events_correlation.SourceKubernetes,
		Type:   "secret.updated",
		Since:  lookbackTime,
		Until:  firstRestart.Timestamp,
	})

	// Analyze most recent relevant change
	allChanges := append(deploymentEvents, append(configEvents, secretEvents...)...)
	if len(allChanges) == 0 {
		return ChangeAnalysis{
			HasRecentChanges: false,
			Confidence:       0.0,
		}
	}

	// Find most recent change
	var mostRecent events_correlation.Event
	for _, change := range allChanges {
		if change.Timestamp.After(mostRecent.Timestamp) {
			mostRecent = change
		}
	}

	timeAgo := firstRestart.Timestamp.Sub(mostRecent.Timestamp)
	changeType := determineChangeType(mostRecent.Type)
	
	// Higher confidence if change was very recent
	confidence := 0.3
	if timeAgo < 5*time.Minute {
		confidence = 0.9
	} else if timeAgo < 15*time.Minute {
		confidence = 0.7
	} else if timeAgo < 30*time.Minute {
		confidence = 0.5
	}

	return ChangeAnalysis{
		HasRecentChanges: true,
		ChangeType:       changeType,
		TimeAgo:          timeAgo,
		ChangeDetails:    fmt.Sprintf("%s updated %v ago", changeType, timeAgo.Round(time.Minute)),
		Confidence:       confidence,
	}
}

// determineChangeType converts event type to human-readable change type
func determineChangeType(eventType string) string {
	switch {
	case strings.Contains(eventType, "deployment"):
		return "Deployment"
	case strings.Contains(eventType, "configmap"):
		return "ConfigMap"
	case strings.Contains(eventType, "secret"):
		return "Secret"
	default:
		return "Configuration"
	}
}

// analyzeRestartPattern analyzes timing patterns in restarts
func analyzeRestartPattern(restarts []events_correlation.Event) PatternAnalysis {
	if len(restarts) < 2 {
		return PatternAnalysis{
			Pattern:    "insufficient_data",
			Confidence: 0.1,
		}
	}

	// Calculate intervals between restarts
	intervals := make([]time.Duration, len(restarts)-1)
	for i := 1; i < len(restarts); i++ {
		intervals[i-1] = restarts[i].Timestamp.Sub(restarts[i-1].Timestamp)
	}

	// Calculate average interval
	var totalDuration time.Duration
	for _, interval := range intervals {
		totalDuration += interval
	}
	avgInterval := totalDuration / time.Duration(len(intervals))

	// Analyze if restarts are accelerating (intervals getting shorter)
	isAccelerating := false
	if len(intervals) >= 3 {
		firstHalf := intervals[:len(intervals)/2]
		secondHalf := intervals[len(intervals)/2:]
		
		var firstAvg, secondAvg time.Duration
		for _, d := range firstHalf {
			firstAvg += d
		}
		firstAvg /= time.Duration(len(firstHalf))
		
		for _, d := range secondHalf {
			secondAvg += d
		}
		secondAvg /= time.Duration(len(secondHalf))
		
		isAccelerating = secondAvg < firstAvg*8/10 // 20% faster
	}

	// Determine pattern type
	pattern := "regular"
	if avgInterval < 30*time.Second {
		pattern = "rapid_fire"
	} else if avgInterval > 5*time.Minute {
		pattern = "sporadic"
	}

	if isAccelerating {
		pattern = "accelerating_" + pattern
	}

	return PatternAnalysis{
		Pattern:        pattern,
		AvgInterval:    avgInterval,
		IsAccelerating: isAccelerating,
		Confidence:     0.8,
	}
}

// getErrorContext gets additional error context from logs and systemd
func getErrorContext(ctx *events_correlation.Context, restarts []events_correlation.Event) ErrorContext {
	// Look for error events from systemd around restart times
	errorEvents := ctx.GetEvents(events_correlation.Filter{
		Source: events_correlation.SourceSystemd,
		Type:   "service.failed",
		Since:  restarts[0].Timestamp.Add(-1 * time.Minute),
		Until:  restarts[len(restarts)-1].Timestamp.Add(1 * time.Minute),
	})

	if len(errorEvents) == 0 {
		return ErrorContext{
			HasErrorLogs: false,
		}
	}

	// Extract error patterns
	errorMessages := make([]string, 0)
	for _, event := range errorEvents {
		if msg, ok := event.Attributes["message"].(string); ok {
			errorMessages = append(errorMessages, msg)
		}
	}

	return ErrorContext{
		HasErrorLogs:  true,
		ErrorPattern:  "systemd_failures",
		ErrorMessages: errorMessages,
	}
}

// Additional helper functions for calculations and formatting...

// calculateCrashLoopConfidence calculates overall confidence in crash loop detection
func calculateCrashLoopConfidence(restartCount int, pattern PatternAnalysis, exitCode ExitCodeAnalysis, changes ChangeAnalysis) float64 {
	confidence := 0.5 // Base confidence
	
	// More restarts = higher confidence
	if restartCount >= 5 {
		confidence += 0.2
	} else if restartCount >= 3 {
		confidence += 0.1
	}
	
	// Pattern analysis
	confidence += pattern.Confidence * 0.2
	
	// Exit code analysis
	confidence += exitCode.Confidence * 0.2
	
	// Recent changes increase confidence
	if changes.HasRecentChanges {
		confidence += changes.Confidence * 0.2
	}
	
	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

// determineCrashLoopSeverity determines severity based on impact
func determineCrashLoopSeverity(affectedPods, restartCount int, pattern PatternAnalysis) events_correlation.Severity {
	if pattern.Pattern == "rapid_fire" || restartCount > 10 {
		return events_correlation.SeverityCritical
	}
	
	if affectedPods > 1 || restartCount > 5 {
		return events_correlation.SeverityHigh
	}
	
	return events_correlation.SeverityMedium
}

// generateRootCauseAnalysis creates intelligent root cause analysis and recommendations
func generateRootCauseAnalysis(exitCode ExitCodeAnalysis, changes ChangeAnalysis, pattern PatternAnalysis, errors ErrorContext) (string, []string) {
	rootCause := exitCode.RootCause
	
	if changes.HasRecentChanges && changes.Confidence > 0.7 {
		rootCause = fmt.Sprintf("%s likely caused by recent %s (%v ago)", 
			exitCode.RootCause, changes.ChangeType, changes.TimeAgo.Round(time.Minute))
	}
	
	recommendations := []string{exitCode.FixSuggestion}
	
	if changes.HasRecentChanges {
		recommendations = append(recommendations, 
			fmt.Sprintf("Review and potentially rollback recent %s changes", changes.ChangeType))
	}
	
	if pattern.IsAccelerating {
		recommendations = append(recommendations, 
			"Issue is escalating - prioritize immediate resolution")
	}
	
	if errors.HasErrorLogs {
		recommendations = append(recommendations, 
			"Check systemd logs for additional error details")
	}
	
	return rootCause, recommendations
}

// generateCrashLoopTitle creates a descriptive title
func generateCrashLoopTitle(podName string, restartCount int, rootCause string) string {
	return fmt.Sprintf("Crash loop detected: %s restarted %d times - %s", 
		podName, restartCount, rootCause)
}

// generateCrashLoopDescription creates detailed description
func generateCrashLoopDescription(podName string, restarts []events_correlation.Event, rootCause string, exitCode ExitCodeAnalysis) string {
	timespan := restarts[len(restarts)-1].Timestamp.Sub(restarts[0].Timestamp)
	
	return fmt.Sprintf(
		"Pod %s has restarted %d times in %v (avg interval: %v). "+
		"Most common exit code: %d (%s). "+
		"Root cause: %s",
		podName,
		len(restarts),
		timespan.Round(time.Second),
		timespan/time.Duration(len(restarts)-1),
		exitCode.MostCommonExitCode,
		exitCode.Pattern,
		rootCause,
	)
}

// generateImpactAssessment creates impact assessment
func generateImpactAssessment(crashLoopPods map[string][]events_correlation.Event, pattern PatternAnalysis) string {
	totalRestarts := 0
	for _, restarts := range crashLoopPods {
		totalRestarts += len(restarts)
	}
	
	impact := fmt.Sprintf("Impact: %d pods in crash loops with %d total restarts", 
		len(crashLoopPods), totalRestarts)
	
	if pattern.IsAccelerating {
		impact += ". Issue is escalating rapidly."
	}
	
	return impact
}

// buildCrashLoopTimeline creates detailed timeline
func buildCrashLoopTimeline(restarts []events_correlation.Event, changes ChangeAnalysis) []events_correlation.TimelineEntry {
	timeline := make([]events_correlation.TimelineEntry, 0)
	
	// Add change event if recent
	if changes.HasRecentChanges {
		timeline = append(timeline, events_correlation.TimelineEntry{
			Timestamp:   restarts[0].Timestamp.Add(-changes.TimeAgo),
			Description: changes.ChangeDetails,
			EventID:     "change-event",
			Source:      "kubernetes",
		})
	}
	
	// Add restart events
	for i, restart := range restarts {
		timeline = append(timeline, events_correlation.TimelineEntry{
			Timestamp:   restart.Timestamp,
			Description: fmt.Sprintf("Restart #%d: %s", i+1, restart.Entity.Pod),
			EventID:     restart.ID,
			Source:      string(restart.Source),
		})
	}
	
	return timeline
}

// generateCrashLoopActions creates appropriate actions
func generateCrashLoopActions(podName string, severity events_correlation.Severity, exitCode ExitCodeAnalysis, changes ChangeAnalysis) []events_correlation.Action {
	actions := []events_correlation.Action{
		{
			Type:     "alert",
			Target:   "dev-team",
			Priority: string(severity),
			Parameters: map[string]string{
				"pod":        podName,
				"exit_code":  fmt.Sprintf("%d", exitCode.MostCommonExitCode),
				"root_cause": exitCode.RootCause,
			},
		},
	}
	
	if changes.HasRecentChanges && changes.Confidence > 0.8 {
		actions = append(actions, events_correlation.Action{
			Type:   "annotate",
			Target: podName,
			Parameters: map[string]string{
				"recent-change-detected": "true",
				"change-type":           changes.ChangeType,
				"rollback-candidate":    "true",
			},
		})
	}
	
	if severity == events_correlation.SeverityCritical {
		actions = append(actions, events_correlation.Action{
			Type:     "webhook",
			Target:   "incident-management",
			Priority: "critical",
			Parameters: map[string]string{
				"incident_type": "crash_loop",
				"affected_pod":  podName,
			},
		})
	}
	
	return actions
}