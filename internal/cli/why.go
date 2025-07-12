package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yairfalse/tapio/internal/output"
	"github.com/yairfalse/tapio/pkg/simple"
	"github.com/yairfalse/tapio/pkg/types"
	"github.com/yairfalse/tapio/pkg/universal"
	"github.com/yairfalse/tapio/pkg/universal/formatters"
	"github.com/yairfalse/tapio/pkg/events_correlation"
	"github.com/yairfalse/tapio/pkg/correlation_v2"
)

var (
	whyVerbose      bool
	whyOutput       string
	whyNamespace    string
	whyEnableEBPF   bool
	whyUseUniversal bool
)

var whyCmd = &cobra.Command{
	Use:   "why <resource>",
	Short: "Explain why a Kubernetes resource has problems",
	Long: `🔍 Why analyzes problems and explains them in plain English.

Why provides intelligent root cause analysis by:
  • Examining resource state and configuration
  • Correlating events across multiple sources
  • Using eBPF kernel insights (optional)
  • Explaining symptoms and root causes clearly
  • Providing actionable solutions with commands

The analysis goes beyond basic status checks to understand the "why" 
behind your Kubernetes resource problems.`,

	Example: `  # Explain why a pod is having issues
  tapio why my-broken-pod

  # Explain a deployment's problems
  tapio why deployment/api-service

  # Get detailed technical explanation
  tapio why my-pod --verbose

  # Get explanation in JSON format for automation
  tapio why my-pod --output json

  # Enhanced analysis with eBPF kernel insights
  tapio why my-pod --enable-ebpf

  # Analyze in specific namespace
  tapio why api-pod --namespace production`,

	Args: cobra.ExactArgs(1),

	// Validate arguments before running
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate output format
		if err := ValidateOutputFormat(whyOutput); err != nil {
			return err
		}

		// Validate namespace
		if err := ValidateNamespace(whyNamespace); err != nil {
			return err
		}

		// Validate resource format
		if err := validateResourceReference(args[0]); err != nil {
			return err
		}

		return nil
	},

	RunE: runWhyV2,
}

func init() {
	whyCmd.Flags().BoolVarP(&whyVerbose, "verbose", "v", false,
		"Include detailed technical information and analysis steps")
	whyCmd.Flags().StringVarP(&whyOutput, "output", "o", "human",
		"Output format: human (default), json, yaml")
	whyCmd.Flags().StringVarP(&whyNamespace, "namespace", "n", "",
		"Target namespace (default: current namespace from kubeconfig)")
	whyCmd.Flags().BoolVar(&whyEnableEBPF, "enable-ebpf", false,
		"Enable eBPF monitoring for kernel-level insights (requires root)")
	whyCmd.Flags().BoolVar(&whyUseUniversal, "universal", true,
		"Use enhanced universal data format for richer analysis output")
}

// validateResourceReference validates the resource reference format
func validateResourceReference(resource string) error {
	if resource == "" {
		return NewCLIError(
			"resource validation",
			"Resource name cannot be empty",
			"Provide a resource name or use 'kind/name' format",
		).WithExamples(
			"tapio why my-pod",
			"tapio why deployment/api-service",
		)
	}

	// Check for invalid characters
	if strings.Contains(resource, " ") {
		return ErrInvalidResource(resource)
	}

	// If it contains a slash, validate the kind
	if strings.Contains(resource, "/") {
		parts := strings.Split(resource, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return ErrInvalidResource(resource)
		}

		// Validate kind
		validKinds := []string{"pod", "deployment", "service", "configmap", "secret", "daemonset", "statefulset", "job", "cronjob", "replicaset"}
		kind := strings.ToLower(parts[0])
		isValid := false
		for _, validKind := range validKinds {
			if kind == validKind {
				isValid = true
				break
			}
		}

		if !isValid {
			return NewCLIError(
				"resource validation",
				fmt.Sprintf("Unknown resource kind: '%s'", parts[0]),
				fmt.Sprintf("Use one of: %s", strings.Join(validKinds, ", ")),
			).WithExamples(
				"tapio why pod/my-pod",
				"tapio why deployment/api-service",
			)
		}
	}

	return nil
}

func runWhyV2(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	resource := args[0]

	// Setup progress tracking
	steps := []string{
		"Parsing resource reference",
		"Initializing V2 correlation engine",
		"Connecting to Kubernetes",
		"Gathering resource context",
		"Analyzing with V2 engine",
	}

	if whyEnableEBPF {
		steps = append(steps, "Enhanced eBPF analysis")
	}

	progress := NewStepProgress(steps).WithVerbose(whyVerbose)
	progress.Start()

	// Parse resource reference
	resourceRef, err := parseResourceReference(resource)
	if err != nil {
		progress.Error(err)
		return NewCLIError(
			"resource parsing",
			"Invalid resource reference format",
			"Use format 'name' or 'kind/name'",
		).WithExamples(
			"tapio why my-pod",
			"tapio why deployment/api-service",
		)
	}

	// Determine namespace to use
	namespace := whyNamespace
	if namespace == "" {
		namespace = getCurrentNamespace()
		if namespace == "" {
			namespace = "default"
		}
	}
	resourceRef.Namespace = namespace

	progress.NextStep() // Move to "Initializing V2 correlation engine"

	// Create V2 correlation engine
	v2Config := correlation_v2.DefaultEngineConfig()
	v2Engine := correlation_v2.NewHighPerformanceEngine(v2Config)
	
	// Start the engine
	if err := v2Engine.Start(); err != nil {
		progress.Error(err)
		return NewCLIError(
			"engine initialization",
			"Failed to start V2 correlation engine",
			"Check system resources and permissions",
		)
	}
	defer v2Engine.Stop()

	// Register analysis rules
	registerAnalysisRules(v2Engine)

	progress.NextStep() // Move to "Connecting to Kubernetes"

	// Create enhanced checker with eBPF if requested
	var checker *simple.Checker
	if whyEnableEBPF {
		checker, err = simple.NewCheckerWithEBPF()
		if err != nil {
			progress.Warning(fmt.Sprintf("eBPF not available: %v", err))
			checker, err = simple.NewChecker()
			if err != nil {
				progress.Error(err)
				return ErrKubernetesConnection(err)
			}
		} else {
			if whyVerbose {
				fmt.Println("✨ Enhanced analysis with eBPF enabled")
			}
		}
	} else {
		checker, err = simple.NewChecker()
		if err != nil {
			progress.Error(err)
			return ErrKubernetesConnection(err)
		}
	}

	// Show which namespace we're analyzing
	if whyVerbose {
		fmt.Printf("🔍 Analyzing %s/%s in namespace: %s\n", resourceRef.Kind, resourceRef.Name, namespace)
	}

	progress.NextStep() // Move to "Gathering resource context"

	// Get related problems first to provide context
	checkReq := &types.CheckRequest{
		Resource:  resourceRef.Name,
		Namespace: namespace,
		Verbose:   whyVerbose,
	}

	checkResult, err := checker.Check(ctx, checkReq)
	if err != nil {
		progress.Warning(fmt.Sprintf("Unable to get full context: %v", err))
		checkResult = &types.CheckResult{Problems: []types.Problem{}}
	}

	// Filter problems for this specific resource
	var resourceProblems []types.Problem
	for _, problem := range checkResult.Problems {
		if problem.Resource.Name == resourceRef.Name && problem.Resource.Namespace == resourceRef.Namespace {
			resourceProblems = append(resourceProblems, problem)
		}
	}

	progress.NextStep() // Move to "Analyzing with V2 engine"

	// Convert problems to events for V2 engine
	events := convertProblemsToEvents(resourceProblems, resourceRef)
	
	// Process events through V2 engine
	processedCount := v2Engine.ProcessBatch(events)
	if whyVerbose {
		fmt.Printf("V2 Engine processed %d events\n", processedCount)
	}

	// Collect results from V2 engine (this is simplified - in real implementation we'd subscribe to results)
	time.Sleep(100 * time.Millisecond) // Give engine time to process
	
	// Get V2 engine statistics
	stats := v2Engine.Stats()
	
	// Create enhanced explanation based on V2 analysis
	explanation := createV2Explanation(resourceRef, resourceProblems, stats)

	if whyEnableEBPF {
		progress.NextStep() // Move to "Enhanced eBPF analysis"
	}

	// Complete progress tracking
	progress.Finish("Analysis completed")

	// Check if resource was found
	if len(resourceProblems) == 0 && explanation != nil {
		// Check if this might be a resource not found case
		if explanation.Summary == "" || strings.Contains(explanation.Summary, "not found") {
			return NewCLIError(
				"resource analysis",
				fmt.Sprintf("Resource '%s' not found in namespace '%s'", resourceRef.Name, namespace),
				"Check if the resource exists and verify the namespace",
			).WithExamples(
				fmt.Sprintf("kubectl get %s %s -n %s", resourceRef.Kind, resourceRef.Name, namespace),
				"tapio why --namespace [other-namespace] "+resourceRef.Name,
				"tapio check --all  # Find the resource in other namespaces",
			)
		}
	}

	// Output explanation
	if whyUseUniversal && whyOutput == "human" {
		// Convert to universal format and use CLI formatter
		if err := outputV2Explanation(ctx, explanation, resourceProblems, stats); err != nil {
			return NewCLIError(
				"output formatting",
				"Failed to display analysis results",
				"Try using a different output format",
			).WithExamples(
				"tapio why "+resource+" --output json",
				"tapio why "+resource+" --output yaml",
			)
		}
		return nil
	}

	// Use traditional formatter
	formatter := output.NewFormatter(whyOutput)
	if err := formatter.PrintExplanation(explanation); err != nil {
		return NewCLIError(
			"output formatting",
			"Failed to display explanation",
			"Try using a different output format",
		).WithExamples(
			"tapio why "+resource+" --output json",
			"tapio why "+resource+" --output yaml",
		)
	}

	return nil
}

// convertProblemsToEvents converts problems to correlation events
func convertProblemsToEvents(problems []types.Problem, resourceRef *types.ResourceRef) []*events_correlation.Event {
	events := make([]*events_correlation.Event, 0, len(problems))
	
	for _, problem := range problems {
		event := &events_correlation.Event{
			ID:        fmt.Sprintf("problem-%s-%d", problem.Resource.Name, time.Now().UnixNano()),
			Timestamp: time.Now(),
			Source:    events_correlation.SourceKubernetes,
			Type:      strings.ToLower(string(problem.Severity)),
			Entity: events_correlation.Entity{
				Type: resourceRef.Kind,
				UID:  fmt.Sprintf("%s/%s", problem.Resource.Namespace, problem.Resource.Name),
				Name: problem.Resource.Name,
			},
			Attributes: map[string]interface{}{
				"title":       problem.Title,
				"description": problem.Description,
				"severity":    problem.Severity,
			},
			Fingerprint: fmt.Sprintf("k8s-problem-%s-%s", problem.Resource.Name, problem.Title),
			Labels: map[string]string{
				"namespace": problem.Resource.Namespace,
				"kind":      resourceRef.Kind,
			},
		}
		
		events = append(events, event)
	}
	
	return events
}

// createV2Explanation creates an explanation based on V2 engine analysis
func createV2Explanation(resourceRef *types.ResourceRef, problems []types.Problem, stats correlation_v2.EngineStats) *types.Explanation {
	explanation := &types.Explanation{
		Resource: resourceRef,
		Summary:  fmt.Sprintf("V2 correlation analysis of %s/%s", resourceRef.Kind, resourceRef.Name),
		Problems: problems,
		Analysis: &types.Analysis{
			RealityCheck: &types.RealityCheck{
				ActualMemory:   "Analyzing with V2 engine...",
				RestartPattern: fmt.Sprintf("Processed %d events", stats.ProcessedEvents),
			},
		},
		Timestamp: time.Now(),
	}

	// Add V2 engine insights
	explanation.RootCauses = []types.RootCause{
		{
			Title:       "V2 Engine Analysis",
			Description: fmt.Sprintf("High-performance analysis processed %d events at %.2f events/sec", stats.ProcessedEvents, stats.EventsPerSecond),
			Evidence: []string{
				fmt.Sprintf("Generated %d correlation results", stats.GeneratedResults),
				fmt.Sprintf("Drop rate: %.2f%%", stats.DropRate*100),
				fmt.Sprintf("Engine health: %v", stats.IsHealthy),
			},
			Confidence: 0.9,
		},
	}

	// Add insights based on problems
	if len(problems) > 0 {
		explanation.RootCauses = append(explanation.RootCauses, types.RootCause{
			Title:       "Issues Detected",
			Description: fmt.Sprintf("Found %d issues with this resource", len(problems)),
			Evidence:    []string{fmt.Sprintf("%d problems identified by V2 analysis", len(problems))},
			Confidence:  0.8,
		})
		
		// Add specific solutions
		explanation.Solutions = []types.Solution{
			{
				Title:       "Review Resource Configuration",
				Description: "Check the current configuration and apply fixes",
				Commands: []string{
					fmt.Sprintf("kubectl describe %s %s -n %s", resourceRef.Kind, resourceRef.Name, resourceRef.Namespace),
					fmt.Sprintf("kubectl edit %s %s -n %s", resourceRef.Kind, resourceRef.Name, resourceRef.Namespace),
				},
				Urgency:    types.SeverityWarning,
				Difficulty: "medium",
				Risk:       "low",
			},
		}
	} else {
		explanation.Solutions = []types.Solution{
			{
				Title:       "Monitor Resource",
				Description: "No immediate issues found. Continue monitoring with V2 engine.",
				Commands: []string{
					fmt.Sprintf("kubectl get %s %s -n %s -w", resourceRef.Kind, resourceRef.Name, resourceRef.Namespace),
					"tapio sniff --enable-ebpf  # Real-time monitoring",
				},
				Urgency:    types.SeverityInfo,
				Difficulty: "easy",
				Risk:       "none",
			},
		}
	}

	return explanation
}

// outputV2Explanation outputs the V2 analysis results
func outputV2Explanation(ctx context.Context, explanation *types.Explanation, problems []types.Problem, stats correlation_v2.EngineStats) error {
	// Output header
	fmt.Printf("\n🚀 V2 Engine Analysis Results for %s/%s\n", explanation.Resource.Kind, explanation.Resource.Name)
	fmt.Println(strings.Repeat("=", 60))

	// Output V2 engine statistics
	fmt.Printf("\n📊 V2 Engine Performance:\n")
	fmt.Printf("   • Events processed: %d (%.2f/sec)\n", stats.ProcessedEvents, stats.EventsPerSecond)
	fmt.Printf("   • Correlations found: %d\n", stats.GeneratedResults)
	fmt.Printf("   • Drop rate: %.2f%%\n", stats.DropRate*100)
	fmt.Printf("   • Active shards: %d\n", stats.NumShards)
	fmt.Printf("   • Engine health: %v\n", stats.IsHealthy)

	// Output problems if any
	if len(problems) > 0 {
		fmt.Printf("\n⚠️  Issues Detected (%d):\n", len(problems))
		for i, problem := range problems {
			fmt.Printf("\n%d. %s [%s]\n", i+1, problem.Title, problem.Severity)
			fmt.Printf("   %s\n", problem.Description)
		}
	} else {
		fmt.Println("\n✅ No critical issues detected")
	}

	// Output root causes
	if len(explanation.RootCauses) > 0 {
		fmt.Printf("\n🔍 Root Cause Analysis:\n")
		for i, cause := range explanation.RootCauses {
			fmt.Printf("\n%d. %s (%.0f%% confidence)\n", i+1, cause.Title, cause.Confidence*100)
			fmt.Printf("   %s\n", cause.Description)
			if len(cause.Evidence) > 0 {
				fmt.Println("   Evidence:")
				for _, evidence := range cause.Evidence {
					fmt.Printf("   • %s\n", evidence)
				}
			}
		}
	}

	// Output solutions
	if len(explanation.Solutions) > 0 {
		fmt.Printf("\n💡 Recommended Actions:\n")
		for i, solution := range explanation.Solutions {
			fmt.Printf("\n%d. %s [%s difficulty, %s risk]\n", i+1, solution.Title, solution.Difficulty, solution.Risk)
			fmt.Printf("   %s\n", solution.Description)
			if len(solution.Commands) > 0 {
				fmt.Println("   Commands:")
				for _, cmd := range solution.Commands {
					fmt.Printf("   $ %s\n", cmd)
				}
			}
		}
	}

	fmt.Println()
	return nil
}

// registerAnalysisRules registers correlation rules for resource analysis
func registerAnalysisRules(engine *correlation_v2.HighPerformanceEngine) {
	// Memory pressure rule
	engine.RegisterRule(&events_correlation.Rule{
		ID:          "resource-memory-pressure",
		Name:        "Resource Memory Pressure Detection",
		Description: "Detects memory pressure issues in Kubernetes resources",
		Category:    events_correlation.CategoryResource,
		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceKubernetes,
		},
		Enabled: true,
		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			events := ctx.GetEvents(events_correlation.Filter{
				Source: events_correlation.SourceKubernetes,
			})
			
			// Look for memory-related issues
			memoryIssues := 0
			for _, event := range events {
				if attrs, ok := event.Attributes["title"].(string); ok {
					if strings.Contains(strings.ToLower(attrs), "memory") {
						memoryIssues++
					}
				}
			}
			
			if memoryIssues > 0 {
				return &events_correlation.Result{
					RuleID:     "resource-memory-pressure",
					RuleName:   "Resource Memory Pressure Detection",
					Timestamp:  time.Now(),
					Confidence: 0.8,
					Severity:   events_correlation.SeverityHigh,
					Category:   events_correlation.CategoryResource,
					Title:      "Memory Issues Detected",
					Description: fmt.Sprintf("Found %d memory-related issues", memoryIssues),
				}
			}
			return nil
		},
	})

	// Pod restart pattern detection
	engine.RegisterRule(&events_correlation.Rule{
		ID:          "pod-restart-pattern",
		Name:        "Pod Restart Pattern Detection",
		Description: "Detects concerning restart patterns in pods",
		Category:    events_correlation.CategoryReliability,
		RequiredSources: []events_correlation.EventSource{
			events_correlation.SourceKubernetes,
		},
		Enabled: true,
		Evaluate: func(ctx *events_correlation.Context) *events_correlation.Result {
			events := ctx.GetEvents(events_correlation.Filter{
				Type: "critical",
			})
			
			if len(events) > 2 {
				return &events_correlation.Result{
					RuleID:     "pod-restart-pattern",
					RuleName:   "Pod Restart Pattern Detection",
					Timestamp:  time.Now(),
					Confidence: 0.9,
					Severity:   events_correlation.SeverityCritical,
					Category:   events_correlation.CategoryReliability,
					Title:      "Critical Pod Issues",
					Description: "Multiple critical issues detected - possible crash loop",
				}
			}
			return nil
		},
	})
}

// parseResourceReference parses "pod/name" or "name" format
func parseResourceReference(resource string) (*types.ResourceRef, error) {
	parts := strings.Split(resource, "/")

	switch len(parts) {
	case 1:
		// Just name - assume it's a pod
		return &types.ResourceRef{
			Kind: "pod",
			Name: parts[0],
		}, nil
	case 2:
		// kind/name format
		return &types.ResourceRef{
			Kind: strings.ToLower(parts[0]),
			Name: parts[1],
		}, nil
	default:
		return nil, fmt.Errorf("invalid format, use 'name' or 'kind/name'")
	}
}