package patterns

import "time"

// QueryResult represents a strongly-typed query result from Neo4j
type QueryResult struct {
	Service           string           `json:"service"`
	TotalPods         int              `json:"totalPods"`
	RecentRestarts    int              `json:"recentRestarts"`
	AffectedPods      int              `json:"affectedPods"`
	Restarts          int              `json:"restarts"`
	Deployments       []string         `json:"deployments"`
	NodeName          string           `json:"nodeName"`
	PressureEvents    int              `json:"pressureEvents"`
	Evictions         int              `json:"evictions"`
	PressureReason    string           `json:"pressureReason"`
	RestartCount      int              `json:"restartCount"`
	FirstRestart      int64            `json:"firstRestart"`
	LastRestart       int64            `json:"lastRestart"`
	ServiceName       string           `json:"serviceName"`
	RunningPods       int              `json:"runningPods"`
	PodIssues         int              `json:"podIssues"`
	Endpoints         []string         `json:"endpoints"`
	DeploymentName    string           `json:"deploymentName"`
	DesiredReplicas   int              `json:"desiredReplicas"`
	UpdatedReplicas   int              `json:"updatedReplicas"`
	AvailableReplicas int              `json:"availableReplicas"`
	ReplicaSets       []ReplicaSetInfo `json:"replicaSets"`
}

// ReplicaSetInfo represents replica set information
type ReplicaSetInfo struct {
	Revision   int `json:"revision"`
	PodCount   int `json:"podCount"`
	ReadyPods  int `json:"readyPods"`
	FailedPods int `json:"failedPods"`
}

// OOMKillResult represents the result of an OOM kill query
type OOMKillResult struct {
	Service        string `json:"service"`
	TotalPods      int    `json:"totalPods"`
	RecentRestarts int    `json:"recentRestarts"`
}

// ConfigMapChangeResult represents the result of a ConfigMap change query
type ConfigMapChangeResult struct {
	AffectedPods int      `json:"affectedPods"`
	Restarts     int      `json:"restarts"`
	Deployments  []string `json:"deployments"`
}

// NodePressureResult represents the result of a node pressure query
type NodePressureResult struct {
	NodeName       string `json:"nodeName"`
	PressureEvents int    `json:"pressureEvents"`
	Evictions      int    `json:"evictions"`
	PressureReason string `json:"pressureReason"`
}

// CrashLoopResult represents the result of a crash loop query
type CrashLoopResult struct {
	RestartCount int   `json:"restartCount"`
	FirstRestart int64 `json:"firstRestart"`
	LastRestart  int64 `json:"lastRestart"`
}

// ServiceDisruptionResult represents the result of a service disruption query
type ServiceDisruptionResult struct {
	ServiceName string   `json:"serviceName"`
	TotalPods   int      `json:"totalPods"`
	RunningPods int      `json:"runningPods"`
	PodIssues   int      `json:"podIssues"`
	Endpoints   []string `json:"endpoints"`
}

// RollingUpdateResult represents the result of a rolling update query
type RollingUpdateResult struct {
	DeploymentName    string           `json:"deploymentName"`
	DesiredReplicas   int              `json:"desiredReplicas"`
	UpdatedReplicas   int              `json:"updatedReplicas"`
	AvailableReplicas int              `json:"availableReplicas"`
	ReplicaSets       []ReplicaSetInfo `json:"replicaSets"`
}

// DetectionMetadata represents strongly-typed metadata for detections
type DetectionMetadata struct {
	Service           string  `json:"service,omitempty"`
	TotalPods         int     `json:"total_pods,omitempty"`
	RecentRestarts    int     `json:"recent_restarts,omitempty"`
	AffectedPods      int     `json:"affected_pods,omitempty"`
	Restarts          int     `json:"restarts,omitempty"`
	Node              string  `json:"node,omitempty"`
	PressureEvents    int     `json:"pressure_events,omitempty"`
	Evictions         int     `json:"evictions,omitempty"`
	RestartCount      int     `json:"restart_count,omitempty"`
	RunningPods       int     `json:"running_pods,omitempty"`
	HealthRatio       float64 `json:"health_ratio,omitempty"`
	PodIssues         int     `json:"pod_issues,omitempty"`
	Deployment        string  `json:"deployment,omitempty"`
	DesiredReplicas   int     `json:"desired_replicas,omitempty"`
	UpdatedReplicas   int     `json:"updated_replicas,omitempty"`
	AvailableReplicas int     `json:"available_replicas,omitempty"`
	FailedPods        int     `json:"failed_pods,omitempty"`
	ProgressRatio     float64 `json:"progress_ratio,omitempty"`
}

// QueryParams represents strongly-typed query parameters
type QueryParams struct {
	PodUID        string `json:"podUID,omitempty"`
	Timestamp     int64  `json:"timestamp,omitempty"`
	StartTime     int64  `json:"startTime,omitempty"`
	CMUID         string `json:"cmUID,omitempty"`
	ServiceUID    string `json:"serviceUID,omitempty"`
	DeploymentUID string `json:"deploymentUID,omitempty"`
}

// NewQueryParams creates query parameters with type safety
func NewQueryParams() *QueryParams {
	return &QueryParams{}
}

// WithPodUID sets the pod UID
func (p *QueryParams) WithPodUID(uid string) *QueryParams {
	p.PodUID = uid
	return p
}

// WithTimestamp sets the timestamp
func (p *QueryParams) WithTimestamp(t time.Time) *QueryParams {
	p.Timestamp = t.Unix()
	return p
}

// WithStartTime sets the start time
func (p *QueryParams) WithStartTime(t time.Time) *QueryParams {
	p.StartTime = t.Unix()
	return p
}

// WithCMUID sets the ConfigMap UID
func (p *QueryParams) WithCMUID(uid string) *QueryParams {
	p.CMUID = uid
	return p
}

// WithServiceUID sets the service UID
func (p *QueryParams) WithServiceUID(uid string) *QueryParams {
	p.ServiceUID = uid
	return p
}

// WithDeploymentUID sets the deployment UID
func (p *QueryParams) WithDeploymentUID(uid string) *QueryParams {
	p.DeploymentUID = uid
	return p
}

// ToMap converts params to map for Neo4j driver (temporary bridge)
func (p *QueryParams) ToMap() map[string]interface{} {
	m := make(map[string]interface{})
	if p.PodUID != "" {
		m["podUID"] = p.PodUID
	}
	if p.Timestamp != 0 {
		m["timestamp"] = p.Timestamp
	}
	if p.StartTime != 0 {
		m["startTime"] = p.StartTime
	}
	if p.CMUID != "" {
		m["cmUID"] = p.CMUID
	}
	if p.ServiceUID != "" {
		m["serviceUID"] = p.ServiceUID
	}
	if p.DeploymentUID != "" {
		m["deploymentUID"] = p.DeploymentUID
	}
	return m
}
