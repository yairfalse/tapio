package correlation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
	"github.com/yairfalse/tapio/pkg/intelligence/aggregator"
	"go.uber.org/zap"
)

// AffectedPodData represents a pod affected by config changes
type AffectedPodData struct {
	Pod      GraphNode
	Name     string
	Restart  time.Time
	Ready    bool
	Phase    string
	Services []string
}

// ConfigChangeInfo represents a configuration change info for impact analysis
type ConfigChangeInfo struct {
	Type     string // ConfigMap or Secret
	Name     string
	Modified time.Time
}

// ConfigImpactCorrelator analyzes the impact of configuration changes on pods and services
// It tracks: ConfigMap/Secret changes → Pod restarts → Service disruptions
type ConfigImpactCorrelator struct {
	*BaseCorrelator
	graphStore  GraphStore
	logger      *zap.Logger
	queryConfig QueryConfig
}

// NewConfigImpactCorrelator creates a new config impact correlator
func NewConfigImpactCorrelator(graphStore GraphStore, logger *zap.Logger) (*ConfigImpactCorrelator, error) {
	if graphStore == nil {
		return nil, fmt.Errorf("graphStore is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	capabilities := CorrelatorCapabilities{
		EventTypes: []string{
			"config_changed",
			"secret_changed",
			"pod_restart",
			"pod_crash",
			"container_restart",
			"deployment_rollout",
		},
		RequiredData: []string{"namespace", "cluster"},
		OptionalData: []string{"configmap", "secret", "pod", "deployment"},
		Dependencies: []Dependency{
			{
				Name:     "neo4j",
				Type:     "database",
				Required: true,
				HealthCheck: func(ctx context.Context) error {
					return graphStore.HealthCheck(ctx)
				},
			},
		},
		MaxEventAge:  MaxEventAge,
		BatchSupport: false,
	}

	base := NewBaseCorrelator("config-impact-correlator", DefaultCorrelatorVersion, capabilities)

	return &ConfigImpactCorrelator{
		BaseCorrelator: base,
		graphStore:     graphStore,
		logger:         logger,
		queryConfig:    DefaultQueryConfig(),
	}, nil
}

// Correlate analyzes config change impacts
func (c *ConfigImpactCorrelator) Correlate(ctx context.Context, event *domain.UnifiedEvent) (*aggregator.CorrelatorOutput, error) {
	startTime := time.Now()

	// Validate event can be processed
	if err := c.ValidateEvent(event); err != nil {
		return nil, err
	}

	c.logger.Debug("Processing config impact correlation",
		zap.String("event_id", event.ID),
		zap.String("event_type", string(event.Type)),
		zap.String("namespace", c.getNamespace(event)),
		zap.String("entity", c.getEntityName(event)))

	// Route to appropriate analysis
	var findings []aggregator.Finding
	var err error

	switch event.Type {
	case "config_changed", "secret_changed":
		findings, err = c.analyzeConfigChange(ctx, event)
	case "pod_restart", "pod_crash", "container_restart":
		findings, err = c.analyzePodRestartCause(ctx, event)
	case "deployment_rollout":
		findings, err = c.analyzeDeploymentConfig(ctx, event)
	default:
		findings = []aggregator.Finding{}
	}

	if err != nil {
		c.logger.Error("Config impact correlation failed",
			zap.String("event_id", event.ID),
			zap.Error(err))
		return nil, fmt.Errorf("config impact correlation failed: %w", err)
	}

	// Calculate overall confidence
	confidence := c.calculateConfidence(findings)

	// Build context
	context_map := map[string]string{
		"namespace":        c.getNamespace(event),
		"cluster":          c.getCluster(event),
		"correlation_type": "config_impact",
		"event_type":       string(event.Type),
	}

	if entity := c.getEntityName(event); entity != "" {
		context_map["entity"] = entity
	}

	return &aggregator.CorrelatorOutput{
		CorrelatorName:    c.Name(),
		CorrelatorVersion: c.Version(),
		Findings:          findings,
		Context:           context_map,
		Confidence:        confidence,
		ProcessingTime:    time.Since(startTime),
		Timestamp:         time.Now(),
	}, nil
}

// analyzeConfigChange checks what pods/services are affected by a config change
func (c *ConfigImpactCorrelator) analyzeConfigChange(ctx context.Context, event *domain.UnifiedEvent) ([]aggregator.Finding, error) {
	namespace := c.getNamespace(event)
	configName := c.getEntityName(event)
	configType := "ConfigMap"
	if event.Type == "secret_changed" {
		configType = "Secret"
	}

	if configName == "" {
		return nil, fmt.Errorf("%s name not found in event", configType)
	}

	c.logger.Debug("Analyzing config change impact",
		zap.String("config", configName),
		zap.String("type", configType),
		zap.String("namespace", namespace))

	result, err := c.queryConfigImpact(ctx, namespace, configName, configType)
	if err != nil {
		return nil, err
	}
	defer result.Close(ctx)

	findings := c.processConfigImpactResults(ctx, result, configName, configType, event)
	return c.addImmediateImpactFinding(findings, configName, configType, event), nil
}

// queryConfigImpact queries for pods affected by config change
func (c *ConfigImpactCorrelator) queryConfigImpact(ctx context.Context, namespace, configName, configType string) (ResultIterator, error) {
	limit := c.queryConfig.GetLimit("config")
	query := fmt.Sprintf(`
		MATCH (cfg:%s {name: $configName, namespace: $namespace})
		OPTIONAL MATCH (p:Pod)-[:MOUNTS|USES_SECRET]->(cfg)
		WHERE p.namespace = $namespace
		OPTIONAL MATCH (svc:Service)-[:SELECTS]->(p)
		WITH cfg, p, svc, 
		     p.lastRestart as podRestart,
		     p.ready as podReady,
		     p.phase as podPhase
		LIMIT %d
		RETURN cfg,
		       collect(DISTINCT {
		           pod: p,
		           restart: podRestart,
		           ready: podReady,
		           phase: podPhase,
		           services: collect(DISTINCT svc.name)[0..%d]
		       })[0..%d] as affectedPods
	`, configType, limit*2, limit, limit)

	params := &ConfigQueryParams{
		BaseQueryParams: BaseQueryParams{
			Namespace: namespace,
		},
		ConfigName: configName,
		ConfigType: configType,
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}

	result, err := c.graphStore.ExecuteQuery(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query config impact: %w", err)
	}
	return result, nil
}

// processConfigImpactResults processes query results for config impact
func (c *ConfigImpactCorrelator) processConfigImpactResults(ctx context.Context, result ResultIterator, configName, configType string, event *domain.UnifiedEvent) []aggregator.Finding {
	var findings []aggregator.Finding

	for result.Next(ctx) {
		record := result.Record()

		// Analyze affected pods
		if affectedPodsValue, found := record.Get("affectedPods"); found {
			affectedPods := c.parseAffectedPodsFromValue(affectedPodsValue)
			if len(affectedPods) > 0 {
				findings = append(findings, c.analyzeAffectedPods(configName, configType, affectedPods, event)...)
			}
		}
	}

	return findings
}

// addImmediateImpactFinding adds immediate config change impact finding if needed
func (c *ConfigImpactCorrelator) addImmediateImpactFinding(findings []aggregator.Finding, configName, configType string, event *domain.UnifiedEvent) []aggregator.Finding {
	if len(findings) == 0 {
		return findings
	}

	impactFinding := aggregator.Finding{
		ID:         fmt.Sprintf("config-change-impact-%s", configName),
		Type:       "config_change_detected",
		Severity:   aggregator.SeverityMedium,
		Confidence: HighTestConfidence,
		Message:    fmt.Sprintf("%s %s was changed, analyzing impact on %d findings", configType, configName, len(findings)),
		Evidence: aggregator.Evidence{
			Events: []domain.UnifiedEvent{*event},
		},
		Impact: aggregator.Impact{
			Scope:       "config",
			Resources:   []string{configName},
			UserImpact:  "Configuration change may cause pod restarts",
			Degradation: "Temporary during rollout",
		},
		Timestamp: time.Now(),
	}

	return append([]aggregator.Finding{impactFinding}, findings...)
}

// analyzePodRestartCause checks if a pod restart was caused by config changes
func (c *ConfigImpactCorrelator) analyzePodRestartCause(ctx context.Context, event *domain.UnifiedEvent) ([]aggregator.Finding, error) {
	namespace := c.getNamespace(event)
	podName := c.getEntityName(event)

	if podName == "" {
		return nil, fmt.Errorf("pod name not found in event")
	}

	c.logger.Debug("Analyzing pod restart cause",
		zap.String("pod", podName),
		zap.String("namespace", namespace))

	// Query for recent config changes that might have caused the restart
	limit := c.queryConfig.GetLimit("config")
	query := fmt.Sprintf(`
		MATCH (p:Pod {name: $podName, namespace: $namespace})
		OPTIONAL MATCH (p)-[:MOUNTS]->(cm:ConfigMap)
		WHERE cm.lastModified > datetime() - duration({minutes: 30})
		OPTIONAL MATCH (p)-[:USES_SECRET]->(s:Secret)
		WHERE s.lastModified > datetime() - duration({minutes: 30})
		RETURN p,
		       (collect(DISTINCT {type: 'ConfigMap', name: cm.name, modified: cm.lastModified})[0..%d] +
		        collect(DISTINCT {type: 'Secret', name: s.name, modified: s.lastModified})[0..%d]) as recentChanges
		LIMIT 1
	`, limit, limit)

	params := &PodQueryParams{
		BaseQueryParams: BaseQueryParams{
			Namespace: namespace,
		},
		PodName: podName,
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}

	result, err := c.graphStore.ExecuteQuery(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query pod restart cause: %w", err)
	}
	defer result.Close(ctx)

	var findings []aggregator.Finding

	for result.Next(ctx) {
		record := result.Record()

		if changesValue, found := record.Get("recentChanges"); found {
			changes := c.parseConfigChangesFromValue(changesValue)
			if len(changes) > 0 {
				findings = append(findings, c.createRestartCauseFindings(podName, changes, event)...)
			}
		}
	}

	if err = result.Err(); err != nil {
		return nil, fmt.Errorf("error iterating pod restart cause results: %w", err)
	}

	return findings, nil
}

// analyzeDeploymentConfig checks deployment configuration issues
func (c *ConfigImpactCorrelator) analyzeDeploymentConfig(ctx context.Context, event *domain.UnifiedEvent) ([]aggregator.Finding, error) {
	namespace := c.getNamespace(event)
	deploymentName := c.getEntityName(event)

	if deploymentName == "" {
		return nil, fmt.Errorf("deployment name not found in event")
	}

	result, err := c.queryDeploymentConfig(ctx, namespace, deploymentName)
	if err != nil {
		return nil, err
	}
	defer result.Close(ctx)

	return c.processDeploymentConfigResults(ctx, result, deploymentName, event)
}

// queryDeploymentConfig queries for deployment config dependencies
func (c *ConfigImpactCorrelator) queryDeploymentConfig(ctx context.Context, namespace, deploymentName string) (ResultIterator, error) {
	limit := c.queryConfig.GetLimit("config")
	query := fmt.Sprintf(`
		MATCH (d:Deployment {name: $deploymentName, namespace: $namespace})
		OPTIONAL MATCH (d)-[:OWNS]->(rs:ReplicaSet)-[:OWNS]->(p:Pod)
		OPTIONAL MATCH (p)-[:MOUNTS]->(cm:ConfigMap)
		OPTIONAL MATCH (p)-[:USES_SECRET]->(s:Secret)
		WITH d, 
		     count(DISTINCT p) as podCount,
		     count(DISTINCT CASE WHEN p.ready = true THEN p END) as readyPods,
		     collect(DISTINCT cm.name)[0..%d] as configMaps,
		     collect(DISTINCT s.name)[0..%d] as secrets
		RETURN d, podCount, readyPods, configMaps, secrets
		LIMIT 1
	`, limit, limit)

	params := &DeploymentQueryParams{
		BaseQueryParams: BaseQueryParams{
			Namespace: namespace,
		},
		DeploymentName: deploymentName,
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}

	result, err := c.graphStore.ExecuteQuery(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query deployment config: %w", err)
	}
	return result, nil
}

// processDeploymentConfigResults processes deployment config query results
func (c *ConfigImpactCorrelator) processDeploymentConfigResults(ctx context.Context, result ResultIterator, deploymentName string, event *domain.UnifiedEvent) ([]aggregator.Finding, error) {
	var findings []aggregator.Finding

	for result.Next(ctx) {
		record := result.Record()
		if finding := c.analyzeDeploymentRollout(record, deploymentName, event); finding != nil {
			findings = append(findings, *finding)
		}
	}

	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("error iterating deployment config results: %w", err)
	}

	return findings, nil
}

// analyzeDeploymentRollout analyzes deployment rollout status
func (c *ConfigImpactCorrelator) analyzeDeploymentRollout(record *GraphRecord, deploymentName string, event *domain.UnifiedEvent) *aggregator.Finding {
	podCountValue, _ := record.Get("podCount")
	readyPodsValue, _ := record.Get("readyPods")

	podCount, _ := podCountValue.(int64)
	readyPods, _ := readyPodsValue.(int64)

	if podCount > 0 && readyPods < podCount {
		return c.createDeploymentRolloutFinding(record, deploymentName, podCount, readyPods, event)
	}

	return nil
}

// createDeploymentRolloutFinding creates finding for deployment rollout issues
func (c *ConfigImpactCorrelator) createDeploymentRolloutFinding(record *GraphRecord, deploymentName string, podCount, readyPods int64, event *domain.UnifiedEvent) *aggregator.Finding {
	configMapsValue, _ := record.Get("configMaps")
	secretsValue, _ := record.Get("secrets")

	configMaps := c.parseStringSliceFromValue(configMapsValue)
	secrets := c.parseStringSliceFromValue(secretsValue)

	return &aggregator.Finding{
		ID:         fmt.Sprintf("deployment-config-rollout-%s", deploymentName),
		Type:       "deployment_config_rollout",
		Severity:   aggregator.SeverityMedium,
		Confidence: MediumConfidence,
		Message:    fmt.Sprintf("Deployment %s has %d/%d ready pods during rollout", deploymentName, readyPods, podCount),
		Evidence: aggregator.Evidence{
			Events: []domain.UnifiedEvent{*event},
			Attributes: map[string]string{
				"configMaps": strings.Join(configMaps, ","),
				"secrets":    strings.Join(secrets, ","),
			},
		},
		Impact: aggregator.Impact{
			Scope:       "deployment",
			Resources:   append([]string{deploymentName}, append(configMaps, secrets...)...),
			UserImpact:  "Service may be degraded during rollout",
			Degradation: fmt.Sprintf("%d%% capacity", (readyPods*100)/podCount),
		},
		Timestamp: time.Now(),
	}
}

// analyzeAffectedPods creates findings for pods affected by config changes
func (c *ConfigImpactCorrelator) analyzeAffectedPods(configName, configType string, affectedPods []AffectedPodData, event *domain.UnifiedEvent) []aggregator.Finding {
	impact := c.calculatePodImpact(affectedPods, event)
	return c.generateImpactFindings(configName, configType, impact, event)
}

// PodImpactInfo holds information about pod impact from config changes
type PodImpactInfo struct {
	RestartedPods    []string
	NotReadyPods     []string
	AffectedServices map[string]bool
}

// calculatePodImpact analyzes the impact of config changes on pods
func (c *ConfigImpactCorrelator) calculatePodImpact(affectedPods []AffectedPodData, event *domain.UnifiedEvent) PodImpactInfo {
	impact := PodImpactInfo{
		RestartedPods:    []string{},
		NotReadyPods:     []string{},
		AffectedServices: map[string]bool{},
	}

	for _, pod := range affectedPods {
		c.analyzeSinglePodImpact(pod, event, &impact)
	}

	return impact
}

// analyzeSinglePodImpact analyzes impact of config change on a single pod
func (c *ConfigImpactCorrelator) analyzeSinglePodImpact(pod AffectedPodData, event *domain.UnifiedEvent, impact *PodImpactInfo) {
	// Check if pod restarted after config change
	if pod.Restart.After(event.Timestamp.Add(-10 * time.Minute)) {
		impact.RestartedPods = append(impact.RestartedPods, pod.Name)
	}

	// Check if pod is not ready
	if !pod.Ready {
		impact.NotReadyPods = append(impact.NotReadyPods, pod.Name)
	}

	// Track affected services
	for _, svcName := range pod.Services {
		impact.AffectedServices[svcName] = true
	}
}

// generateImpactFindings generates findings based on pod impact analysis
func (c *ConfigImpactCorrelator) generateImpactFindings(configName, configType string, impact PodImpactInfo, event *domain.UnifiedEvent) []aggregator.Finding {
	var findings []aggregator.Finding

	if finding := c.createRestartsFinding(configName, configType, impact.RestartedPods, event); finding != nil {
		findings = append(findings, *finding)
	}

	if finding := c.createNotReadyFinding(configName, configType, impact.NotReadyPods, event); finding != nil {
		findings = append(findings, *finding)
	}

	if finding := c.createServiceImpactFinding(configName, configType, impact.AffectedServices, event); finding != nil {
		findings = append(findings, *finding)
	}

	return findings
}

// createRestartsFinding creates finding for pod restarts caused by config change
func (c *ConfigImpactCorrelator) createRestartsFinding(configName, configType string, restartedPods []string, event *domain.UnifiedEvent) *aggregator.Finding {
	if len(restartedPods) == 0 {
		return nil
	}

	return &aggregator.Finding{
		ID:         fmt.Sprintf("config-caused-restarts-%s", configName),
		Type:       "config_change_pod_restarts",
		Severity:   aggregator.SeverityHigh,
		Confidence: MediumHighConfidence,
		Message:    fmt.Sprintf("%s %s change caused %d pod restarts: %s", configType, configName, len(restartedPods), strings.Join(restartedPods, ", ")),
		Evidence: aggregator.Evidence{
			Events: []domain.UnifiedEvent{*event},
		},
		Impact: aggregator.Impact{
			Scope:       "pods",
			Resources:   append([]string{configName}, restartedPods...),
			UserImpact:  "Service disruption during pod restarts",
			Degradation: fmt.Sprintf("%d pods restarted", len(restartedPods)),
		},
		Timestamp: time.Now(),
	}
}

// createNotReadyFinding creates finding for pods not ready after config change
func (c *ConfigImpactCorrelator) createNotReadyFinding(configName, configType string, notReadyPods []string, event *domain.UnifiedEvent) *aggregator.Finding {
	if len(notReadyPods) == 0 {
		return nil
	}

	return &aggregator.Finding{
		ID:         fmt.Sprintf("config-pods-not-ready-%s", configName),
		Type:       "config_change_pods_not_ready",
		Severity:   aggregator.SeverityMedium,
		Confidence: MediumLowConfidence,
		Message:    fmt.Sprintf("%d pods not ready after %s %s change", len(notReadyPods), configType, configName),
		Evidence: aggregator.Evidence{
			Events: []domain.UnifiedEvent{*event},
		},
		Impact: aggregator.Impact{
			Scope:       "pods",
			Resources:   append([]string{configName}, notReadyPods...),
			UserImpact:  "Pods still initializing with new configuration",
			Degradation: fmt.Sprintf("%d pods not ready", len(notReadyPods)),
		},
		Timestamp: time.Now(),
	}
}

// createServiceImpactFinding creates finding for services impacted by config change
func (c *ConfigImpactCorrelator) createServiceImpactFinding(configName, configType string, affectedServices map[string]bool, event *domain.UnifiedEvent) *aggregator.Finding {
	if len(affectedServices) == 0 {
		return nil
	}

	svcList := []string{}
	for svc := range affectedServices {
		svcList = append(svcList, svc)
	}

	return &aggregator.Finding{
		ID:         fmt.Sprintf("config-service-impact-%s", configName),
		Type:       "config_change_service_impact",
		Severity:   aggregator.SeverityMedium,
		Confidence: LowConfidence,
		Message:    fmt.Sprintf("Services affected by %s %s change: %s", configType, configName, strings.Join(svcList, ", ")),
		Evidence: aggregator.Evidence{
			Events: []domain.UnifiedEvent{*event},
		},
		Impact: aggregator.Impact{
			Scope:       "services",
			Resources:   append([]string{configName}, svcList...),
			UserImpact:  "Service endpoints changing due to pod restarts",
			Degradation: "Temporary - rolling update",
		},
		Timestamp: time.Now(),
	}
}

// createRestartCauseFindings creates findings for pod restarts caused by config changes
func (c *ConfigImpactCorrelator) createRestartCauseFindings(podName string, changes []ConfigChangeInfo, event *domain.UnifiedEvent) []aggregator.Finding {
	var findings []aggregator.Finding
	configChanges := []string{}

	for _, change := range changes {
		configChanges = append(configChanges, fmt.Sprintf("%s/%s", change.Type, change.Name))
	}

	if len(configChanges) > 0 {
		findings = append(findings, aggregator.Finding{
			ID:         fmt.Sprintf("pod-restart-config-cause-%s", podName),
			Type:       "pod_restart_config_cause",
			Severity:   aggregator.SeverityHigh,
			Confidence: HighConfidence,
			Message:    fmt.Sprintf("Pod %s restart likely caused by config changes: %s", podName, strings.Join(configChanges, ", ")),
			Evidence: aggregator.Evidence{
				Events: []domain.UnifiedEvent{*event},
				GraphPaths: []aggregator.GraphPath{{
					Nodes: []aggregator.GraphNode{
						{
							ID:     podName,
							Type:   "Pod",
							Labels: map[string]string{"name": podName},
						},
					},
				}},
			},
			Impact: aggregator.Impact{
				Scope:       "pod",
				Resources:   append([]string{podName}, configChanges...),
				UserImpact:  "Pod restarted due to configuration change",
				Degradation: "100% - pod restart",
			},
			Timestamp: time.Now(),
		})
	}

	return findings
}

// calculateConfidence calculates overall confidence for findings
func (c *ConfigImpactCorrelator) calculateConfidence(findings []aggregator.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}

	totalWeight := 0.0
	weightedSum := 0.0

	for _, finding := range findings {
		var weight float64
		switch finding.Severity {
		case aggregator.SeverityCritical:
			weight = 1.0
		case aggregator.SeverityHigh:
			weight = HighWeight
		case aggregator.SeverityMedium:
			weight = MediumWeight
		case aggregator.SeverityLow:
			weight = LowWeight
		default:
			weight = VeryLowWeight
		}

		weightedSum += finding.Confidence * weight
		totalWeight += weight
	}

	confidence := weightedSum / totalWeight

	// Boost if multiple findings correlate
	if len(findings) > 1 {
		confidence += BoostMultiplier
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// Health checks if the correlator is healthy
func (c *ConfigImpactCorrelator) Health(ctx context.Context) error {
	return c.graphStore.HealthCheck(ctx)
}

// PreloadGraph implements GraphCorrelator interface
func (c *ConfigImpactCorrelator) PreloadGraph(ctx context.Context) error {
	// No preloading needed for now
	return nil
}

// Helper functions
func (c *ConfigImpactCorrelator) getNamespace(event *domain.UnifiedEvent) string {
	if event.K8sContext != nil && event.K8sContext.Namespace != "" {
		return event.K8sContext.Namespace
	}
	if event.Entity != nil && event.Entity.Namespace != "" {
		return event.Entity.Namespace
	}
	return "default"
}

func (c *ConfigImpactCorrelator) getCluster(event *domain.UnifiedEvent) string {
	if event.K8sContext != nil && event.K8sContext.ClusterName != "" {
		return event.K8sContext.ClusterName
	}
	return "unknown"
}

func (c *ConfigImpactCorrelator) getEntityName(event *domain.UnifiedEvent) string {
	if event.K8sContext != nil && event.K8sContext.Name != "" {
		return event.K8sContext.Name
	}
	if event.Entity != nil && event.Entity.Name != "" {
		return event.Entity.Name
	}
	return ""
}

// parseStringSliceFromValue safely parses a string slice from a query result value
func (c *ConfigImpactCorrelator) parseStringSliceFromValue(value interface{}) []string {
	var result []string
	if slice, ok := value.([]string); ok {
		return slice
	}
	// Fallback for interface{} slices from database
	if slice, ok := value.([]interface{}); ok {
		for _, item := range slice {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}
	return result
}

// parseAffectedPodsFromValue safely parses affected pods from a query result value
func (c *ConfigImpactCorrelator) parseAffectedPodsFromValue(value interface{}) []AffectedPodData {
	slice, ok := value.([]interface{})
	if !ok {
		return []AffectedPodData{}
	}

	var result []AffectedPodData
	for _, item := range slice {
		if podData := c.parseSinglePodData(item); podData != nil {
			result = append(result, *podData)
		}
	}

	return result
}

// parseSinglePodData parses a single pod data from interface{}
func (c *ConfigImpactCorrelator) parseSinglePodData(item interface{}) *AffectedPodData {
	podMap, ok := item.(map[string]interface{})
	if !ok {
		return nil
	}

	podData := &AffectedPodData{}
	c.parsePodNode(podData, podMap)
	c.parsePodAttributes(podData, podMap)
	c.parsePodServices(podData, podMap)

	return podData
}

// parsePodNode parses pod node information
func (c *ConfigImpactCorrelator) parsePodNode(podData *AffectedPodData, podMap map[string]interface{}) {
	if podNode, ok := podMap["pod"].(map[string]interface{}); ok {
		if props, ok := podNode["properties"].(map[string]interface{}); ok {
			podData.Pod.Properties = parseNodeProperties(props)
			podData.Name = podData.Pod.Properties.Name
		}
	} else if name, ok := podMap["name"].(string); ok {
		// Fallback to direct name access
		podData.Name = name
	}
}

// parsePodAttributes parses pod attributes like restart time, ready status, and phase
func (c *ConfigImpactCorrelator) parsePodAttributes(podData *AffectedPodData, podMap map[string]interface{}) {
	if restartTime, ok := podMap["restart"].(time.Time); ok {
		podData.Restart = restartTime
	}

	if ready, ok := podMap["ready"].(bool); ok {
		podData.Ready = ready
	}

	if phase, ok := podMap["phase"].(string); ok {
		podData.Phase = phase
	}
}

// parsePodServices parses services associated with the pod
func (c *ConfigImpactCorrelator) parsePodServices(podData *AffectedPodData, podMap map[string]interface{}) {
	services, ok := podMap["services"].([]interface{})
	if !ok {
		return
	}

	for _, svc := range services {
		if svcName, ok := svc.(string); ok {
			podData.Services = append(podData.Services, svcName)
		}
	}
}

// parseConfigChangesFromValue safely parses config changes from a query result value
func (c *ConfigImpactCorrelator) parseConfigChangesFromValue(value interface{}) []ConfigChangeInfo {
	var result []ConfigChangeInfo

	slice, ok := value.([]interface{})
	if !ok {
		return result
	}

	for _, item := range slice {
		changeMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		change := ConfigChangeInfo{}

		if changeType, ok := changeMap["type"].(string); ok {
			change.Type = changeType
		}
		if name, ok := changeMap["name"].(string); ok {
			change.Name = name
		}
		if modified, ok := changeMap["modified"].(time.Time); ok {
			change.Modified = modified
		}

		result = append(result, change)
	}

	return result
}
