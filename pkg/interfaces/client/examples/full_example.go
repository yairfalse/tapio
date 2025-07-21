package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/yairfalse/tapio/pkg/interfaces/client"
)

func main() {
	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Configure client
	config := client.DefaultConfig()
	config.RESTAddress = getEnv("TAPIO_REST_URL", "http://localhost:8081")
	config.GRPCAddress = getEnv("TAPIO_GRPC_URL", "localhost:8080")
	config.APIKey = os.Getenv("TAPIO_API_KEY")

	// Create client
	tapioClient, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer tapioClient.Close()

	// Check system status
	if err := checkSystemStatus(ctx, tapioClient); err != nil {
		log.Printf("Warning: System status check failed: %v", err)
	}

	// Start event generator
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		generateEvents(ctx, tapioClient)
	}()

	// Start event stream consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		consumeEventStream(ctx, tapioClient)
	}()

	// Start periodic analytics
	wg.Add(1)
	go func() {
		defer wg.Done()
		periodicAnalytics(ctx, tapioClient)
	}()

	// Wait for interrupt signal
	<-sigChan
	log.Println("Shutting down...")
	cancel()

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("Shutdown complete")
}

func checkSystemStatus(ctx context.Context, client *client.TapioClient) error {
	log.Println("Checking system status...")

	status, err := client.GetStatus(ctx)
	if err != nil {
		return err
	}

	log.Printf("System Status: %s", status.Status)
	log.Printf("Version: %s", status.Version)
	log.Printf("Uptime: %s", status.Uptime)

	// Get detailed system info
	info, err := client.GetSystemInfo(ctx)
	if err != nil {
		return err
	}

	log.Printf("Platform: %s", info.Platform)
	log.Printf("Environment: %s", info.Environment)
	log.Printf("Features enabled: %v", info.Features)

	// Check collectors
	collectors, err := client.GetCollectorStatus(ctx)
	if err != nil {
		return err
	}

	log.Printf("\nActive Collectors:")
	for _, collector := range collectors.Collectors {
		log.Printf("- %s: %s (%.2f events/sec)",
			collector.Name,
			collector.Status,
			collector.EventsPerSecond,
		)
	}

	return nil
}

func generateEvents(ctx context.Context, client *client.TapioClient) {
	log.Println("Starting event generator...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	eventTypes := []string{"network", "kubernetes", "system", "application"}
	severities := []string{"info", "warning", "error"}
	services := []string{"api-gateway", "payment-service", "user-service", "notification-service"}

	eventCount := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("Event generator stopped. Total events sent: %d", eventCount)
			return

		case <-ticker.C:
			// Generate batch of events
			events := make([]*client.Event, 0, 5)

			for i := 0; i < 5; i++ {
				event := &client.Event{
					ID:        fmt.Sprintf("example_%d_%d", time.Now().Unix(), i),
					Type:      eventTypes[i%len(eventTypes)],
					Severity:  severities[i%len(severities)],
					Timestamp: time.Now(),
					Message:   generateMessage(eventTypes[i%len(eventTypes)]),
					Service:   services[i%len(services)],
					Data: map[string]interface{}{
						"iteration": eventCount,
						"batch":     i,
					},
				}
				events = append(events, event)
			}

			// Submit batch
			resp, err := client.SubmitBulkEvents(ctx, events)
			if err != nil {
				log.Printf("Failed to submit events: %v", err)
			} else {
				log.Printf("Submitted %d events (success: %d, failed: %d)",
					resp.Total, resp.Success, resp.Failed)
				eventCount += resp.Success
			}

			// Occasionally trigger correlation analysis
			if eventCount > 0 && eventCount%20 == 0 {
				go performCorrelationAnalysis(ctx, client, events)
			}
		}
	}
}

func consumeEventStream(ctx context.Context, client *client.TapioClient) {
	log.Println("Starting event stream consumer...")

	// Stream error events
	eventStream, err := client.StreamEvents(ctx, "severity:error")
	if err != nil {
		log.Printf("Failed to start event stream: %v", err)
		return
	}

	errorCount := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("Event stream consumer stopped. Total errors processed: %d", errorCount)
			return

		case event, ok := <-eventStream:
			if !ok {
				log.Println("Event stream closed")
				return
			}

			errorCount++
			log.Printf("ERROR EVENT: [%s] %s - %s (service: %s)",
				event.ID, event.Type, event.Message, event.Service)

			// Could trigger alerts, create tickets, etc.
		}
	}
}

func periodicAnalytics(ctx context.Context, client *client.TapioClient) {
	log.Println("Starting periodic analytics...")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Periodic analytics stopped")
			return

		case <-ticker.C:
			// Get analytics for last 5 minutes
			end := time.Now()
			start := end.Add(-5 * time.Minute)

			summary, err := client.GetAnalyticsSummary(ctx, start, end)
			if err != nil {
				log.Printf("Failed to get analytics: %v", err)
				continue
			}

			log.Println("\n=== Analytics Summary ===")
			log.Printf("Time range: %s to %s", start.Format(time.RFC3339), end.Format(time.RFC3339))
			log.Printf("Total events: %d", summary.EventStatistics.Total)

			log.Println("\nEvents by type:")
			for eventType, count := range summary.EventStatistics.ByType {
				log.Printf("  %s: %d", eventType, count)
			}

			log.Println("\nEvents by severity:")
			for severity, count := range summary.EventStatistics.BySeverity {
				log.Printf("  %s: %d", severity, count)
			}

			if len(summary.TopIssues) > 0 {
				log.Println("\nTop issues:")
				for _, issue := range summary.TopIssues {
					log.Printf("  - %s (%s): %d occurrences (%s)",
						issue.Description, issue.Severity, issue.Count, issue.Trend)
				}
			}

			log.Println("========================\n")
		}
	}
}

func performCorrelationAnalysis(ctx context.Context, client *client.TapioClient, events []*client.Event) {
	eventIDs := make([]string, len(events))
	for i, event := range events {
		eventIDs[i] = event.ID
	}

	log.Printf("Performing correlation analysis on %d events...", len(eventIDs))

	analysis, err := client.AnalyzeCorrelations(ctx, eventIDs)
	if err != nil {
		log.Printf("Correlation analysis failed: %v", err)
		return
	}

	if len(analysis.Findings) > 0 {
		log.Printf("Correlation analysis %s found %d patterns:", analysis.AnalysisID, len(analysis.Findings))
		for _, finding := range analysis.Findings {
			log.Printf("  - %s (confidence: %.2f): %s",
				finding.Pattern, finding.Confidence, finding.Description)
		}
	}
}

func generateMessage(eventType string) string {
	messages := map[string][]string{
		"network": {
			"Connection established to database server",
			"Network latency spike detected",
			"DNS resolution timeout",
			"Load balancer health check passed",
		},
		"kubernetes": {
			"Pod started successfully",
			"Deployment scaled to 3 replicas",
			"Service endpoint updated",
			"ConfigMap reloaded",
		},
		"system": {
			"CPU usage at 75%",
			"Memory usage normal",
			"Disk space warning: 85% full",
			"System backup completed",
		},
		"application": {
			"User login successful",
			"Payment processed",
			"Cache invalidated",
			"Background job completed",
		},
	}

	typeMessages, ok := messages[eventType]
	if !ok {
		return "Generic event occurred"
	}

	return typeMessages[time.Now().Unix()%int64(len(typeMessages))]
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
