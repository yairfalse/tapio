package internal

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CNIPluginDetector detects which CNI plugins are active in the cluster
type CNIPluginDetector struct {
	config core.Config
	client kubernetes.Interface
	logger Logger
}

// PluginInfo contains detected plugin information
type PluginInfo struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Version       string            `json:"version"`
	ConfigPath    string            `json:"config_path"`
	BinaryPath    string            `json:"binary_path"`
	Capabilities  []string          `json:"capabilities"`
	IPAM          string            `json:"ipam"`
	NetworkPolicy bool              `json:"network_policy_support"`
	ServiceMesh   bool              `json:"service_mesh_support"`
	Metadata      map[string]string `json:"metadata"`
}

// DetectionResult contains all detected plugins
type DetectionResult struct {
	PrimaryPlugin          *PluginInfo  `json:"primary_plugin"`
	ChainedPlugins         []PluginInfo `json:"chained_plugins"`
	IPAMPlugin             *PluginInfo  `json:"ipam_plugin"`
	ServiceMeshIntegration *PluginInfo  `json:"service_mesh_integration"`
	DetectionMethod        string       `json:"detection_method"`
	ConfidenceScore        float64      `json:"confidence_score"`
}

// NewCNIPluginDetector creates a new plugin detector
func NewCNIPluginDetector(config core.Config) (*CNIPluginDetector, error) {
	var client kubernetes.Interface
	var err error

	if config.InCluster || config.KubeConfigPath != "" {
		client, err = createK8sClient(config)
		if err != nil {
			// Continue without k8s client for file-based detection
		}
	}

	return &CNIPluginDetector{
		config: config,
		client: client,
		logger: &StandardLogger{},
	}, nil
}

// DetectPlugins detects all CNI plugins in the environment
func (d *CNIPluginDetector) DetectPlugins() (*DetectionResult, error) {
	result := &DetectionResult{
		ChainedPlugins: []PluginInfo{},
		Metadata:       make(map[string]string),
	}

	// Try multiple detection methods
	confidence := 0.0

	// Method 1: Parse CNI configuration files
	if plugins, conf := d.detectFromConfig(); len(plugins) > 0 {
		result.ChainedPlugins = append(result.ChainedPlugins, plugins...)
		result.DetectionMethod = "config-file"
		confidence += 0.4

		// Find primary plugin (usually the first main plugin)
		for _, plugin := range plugins {
			if d.isPrimaryPlugin(plugin.Type) {
				primary := plugin
				result.PrimaryPlugin = &primary
				break
			}
		}

		d.logger.Info("Detected plugins from config", map[string]interface{}{
			"confidence": conf,
			"plugins":    len(plugins),
		})
	}

	// Method 2: Check running pods and daemonsets
	if d.client != nil {
		if k8sPlugins, conf := d.detectFromKubernetes(); len(k8sPlugins) > 0 {
			result.ChainedPlugins = append(result.ChainedPlugins, k8sPlugins...)
			if result.DetectionMethod == "" {
				result.DetectionMethod = "kubernetes"
			} else {
				result.DetectionMethod += "+kubernetes"
			}
			confidence += conf
		}
	}

	// Method 3: Check binary presence
	if binPlugins, conf := d.detectFromBinaries(); len(binPlugins) > 0 {
		result.ChainedPlugins = append(result.ChainedPlugins, binPlugins...)
		if result.DetectionMethod == "" {
			result.DetectionMethod = "binaries"
		}
		confidence += conf
	}

	// Method 4: Check for specific vendor signatures
	if vendorPlugin, conf := d.detectVendorSpecific(); vendorPlugin != nil {
		if result.PrimaryPlugin == nil {
			result.PrimaryPlugin = vendorPlugin
		}
		confidence += conf
	}

	// Analyze IPAM and service mesh
	d.analyzeSpecialPlugins(result)

	result.ConfidenceScore = confidence
	return result, nil
}

// detectFromConfig detects plugins from CNI configuration files
func (d *CNIPluginDetector) detectFromConfig() ([]PluginInfo, float64) {
	plugins := []PluginInfo{}
	confidence := 0.0

	configPaths := []string{
		d.config.CNIConfPath,
		"/etc/cni/net.d",
		"/opt/cni/conf",
		"/etc/kubernetes/cni/net.d",
	}

	for _, path := range configPaths {
		if pluginsFromPath := d.scanConfigPath(path); len(pluginsFromPath) > 0 {
			plugins = append(plugins, pluginsFromPath...)
			confidence += 0.3
		}
	}

	return plugins, confidence
}

// scanConfigPath scans a directory for CNI configurations
func (d *CNIPluginDetector) scanConfigPath(configPath string) []PluginInfo {
	plugins := []PluginInfo{}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return plugins
	}

	filepath.WalkDir(configPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".conf" || ext == ".conflist" {
			if detected := d.parseConfigFile(path); len(detected) > 0 {
				plugins = append(plugins, detected...)
			}
		}

		return nil
	})

	return plugins
}

// parseConfigFile parses a CNI config file
func (d *CNIPluginDetector) parseConfigFile(file string) []PluginInfo {
	plugins := []PluginInfo{}

	data, err := os.ReadFile(file)
	if err != nil {
		return plugins
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return plugins
	}

	// Handle .conflist format (plugin chains)
	if pluginsList, ok := config["plugins"].([]interface{}); ok {
		for _, p := range pluginsList {
			if pluginMap, ok := p.(map[string]interface{}); ok {
				if plugin := d.parsePluginConfig(pluginMap, file); plugin != nil {
					plugins = append(plugins, *plugin)
				}
			}
		}
	} else {
		// Handle .conf format (single plugin)
		if plugin := d.parsePluginConfig(config, file); plugin != nil {
			plugins = append(plugins, *plugin)
		}
	}

	return plugins
}

// parsePluginConfig parses individual plugin configuration
func (d *CNIPluginDetector) parsePluginConfig(config map[string]interface{}, configPath string) *PluginInfo {
	pluginType, ok := config["type"].(string)
	if !ok {
		return nil
	}

	plugin := &PluginInfo{
		Type:       pluginType,
		ConfigPath: configPath,
		Metadata:   make(map[string]string),
	}

	// Extract name
	if name, ok := config["name"].(string); ok {
		plugin.Name = name
	} else {
		plugin.Name = pluginType
	}

	// Extract capabilities
	if caps, ok := config["capabilities"].(map[string]interface{}); ok {
		for cap := range caps {
			plugin.Capabilities = append(plugin.Capabilities, cap)
		}
	}

	// Extract IPAM info
	if ipam, ok := config["ipam"].(map[string]interface{}); ok {
		if ipamType, ok := ipam["type"].(string); ok {
			plugin.IPAM = ipamType
		}
	}

	// Detect specific plugins and their features
	d.enrichPluginInfo(plugin, config)

	return plugin
}

// enrichPluginInfo adds plugin-specific information
func (d *CNIPluginDetector) enrichPluginInfo(plugin *PluginInfo, config map[string]interface{}) {
	switch plugin.Type {
	case "cilium":
		plugin.NetworkPolicy = true
		plugin.ServiceMesh = true
		plugin.Metadata["vendor"] = "Cilium"
		plugin.Metadata["features"] = "eBPF,NetworkPolicy,ServiceMesh,LoadBalancing"

		// Check for Cilium-specific config
		if endpoint, ok := config["cilium-endpoint"].(string); ok {
			plugin.Metadata["endpoint"] = endpoint
		}

	case "calico":
		plugin.NetworkPolicy = true
		plugin.Metadata["vendor"] = "Tigera"
		plugin.Metadata["features"] = "NetworkPolicy,BGP,IPIP,VXLAN"

		// Check for Calico datastore
		if datastore, ok := config["datastore_type"].(string); ok {
			plugin.Metadata["datastore"] = datastore
		}

	case "aws-vpc-cni", "aws-cni":
		plugin.Metadata["vendor"] = "AWS"
		plugin.Metadata["features"] = "VPC,ENI,SecurityGroups"
		plugin.Metadata["cloud"] = "aws"

	case "azure-cni":
		plugin.Metadata["vendor"] = "Microsoft"
		plugin.Metadata["features"] = "VNET,NetworkSecurityGroups"
		plugin.Metadata["cloud"] = "azure"

	case "flannel":
		plugin.Metadata["vendor"] = "CoreOS"
		plugin.Metadata["features"] = "VXLAN,HostGW,UDP"

		if backend, ok := config["backend"].(map[string]interface{}); ok {
			if backendType, ok := backend["type"].(string); ok {
				plugin.Metadata["backend"] = backendType
			}
		}

	case "weave", "weave-net":
		plugin.NetworkPolicy = true
		plugin.Metadata["vendor"] = "Weaveworks"
		plugin.Metadata["features"] = "NetworkPolicy,Encryption,Multicast"

	case "antrea":
		plugin.NetworkPolicy = true
		plugin.Metadata["vendor"] = "VMware"
		plugin.Metadata["features"] = "NetworkPolicy,OVS,Traceflow"

	case "kube-router":
		plugin.NetworkPolicy = true
		plugin.Metadata["vendor"] = "CloudNative"
		plugin.Metadata["features"] = "NetworkPolicy,BGP,IPVS,LVS"

	case "canal":
		plugin.NetworkPolicy = true
		plugin.Metadata["vendor"] = "Tigera"
		plugin.Metadata["features"] = "NetworkPolicy,Flannel+Calico"

	// Service mesh integrations
	case "istio-cni":
		plugin.ServiceMesh = true
		plugin.Metadata["service_mesh"] = "istio"
		plugin.Metadata["vendor"] = "Istio"

	case "linkerd-cni":
		plugin.ServiceMesh = true
		plugin.Metadata["service_mesh"] = "linkerd"
		plugin.Metadata["vendor"] = "Linkerd"

	// Meta-plugins
	case "multus":
		plugin.Metadata["type"] = "meta"
		plugin.Metadata["features"] = "MultiNetwork,SRIOV,MacVLAN"

	case "portmap", "bandwidth", "firewall", "tuning":
		plugin.Metadata["type"] = "chained"
		plugin.Metadata["category"] = "utility"
	}

	// Detect version if available
	if version, ok := config["cniVersion"].(string); ok {
		plugin.Version = version
	}
}

// detectFromKubernetes detects plugins from Kubernetes resources
func (d *CNIPluginDetector) detectFromKubernetes() ([]PluginInfo, float64) {
	if d.client == nil {
		return nil, 0.0
	}

	plugins := []PluginInfo{}
	confidence := 0.0

	// Check for CNI-related daemonsets
	daemonsets, err := d.client.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return plugins, 0.0
	}

	cniDaemonsets := map[string]string{
		"cilium":       "cilium",
		"calico-node":  "calico",
		"aws-node":     "aws-vpc-cni",
		"azure-cni":    "azure-cni",
		"kube-flannel": "flannel",
		"weave-net":    "weave",
		"antrea-agent": "antrea",
		"kube-router":  "kube-router",
		"canal":        "canal",
	}

	for _, ds := range daemonsets.Items {
		for dsName, pluginType := range cniDaemonsets {
			if strings.Contains(strings.ToLower(ds.Name), dsName) {
				plugin := PluginInfo{
					Name: ds.Name,
					Type: pluginType,
					Metadata: map[string]string{
						"namespace":   ds.Namespace,
						"daemonset":   ds.Name,
						"ready_nodes": fmt.Sprintf("%d/%d", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
					},
				}

				// Add image info
				if len(ds.Spec.Template.Spec.Containers) > 0 {
					plugin.Metadata["image"] = ds.Spec.Template.Spec.Containers[0].Image
					plugin.Version = d.extractVersionFromImage(ds.Spec.Template.Spec.Containers[0].Image)
				}

				d.enrichPluginInfo(&plugin, nil)
				plugins = append(plugins, plugin)
				confidence += 0.3
				break
			}
		}
	}

	// Check for ConfigMaps with CNI config
	configMaps, err := d.client.CoreV1().ConfigMaps("").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			if strings.Contains(strings.ToLower(cm.Name), "cni") {
				for key, data := range cm.Data {
					if strings.HasSuffix(key, ".conf") || strings.HasSuffix(key, ".conflist") {
						if detected := d.parseConfigFromString(data, cm.Name); len(detected) > 0 {
							plugins = append(plugins, detected...)
							confidence += 0.2
						}
					}
				}
			}
		}
	}

	return plugins, confidence
}

// detectFromBinaries detects plugins from installed binaries
func (d *CNIPluginDetector) detectFromBinaries() ([]PluginInfo, float64) {
	plugins := []PluginInfo{}
	confidence := 0.0

	binPaths := []string{
		d.config.CNIBinPath,
		"/opt/cni/bin",
		"/usr/local/bin",
		"/usr/bin",
	}

	knownBinaries := map[string]string{
		"cilium-cni":  "cilium",
		"calico":      "calico",
		"aws-cni":     "aws-vpc-cni",
		"azure-cni":   "azure-cni",
		"flannel":     "flannel",
		"weave-net":   "weave",
		"antrea":      "antrea",
		"kube-router": "kube-router",
		"bridge":      "bridge",
		"host-local":  "host-local",
		"portmap":     "portmap",
		"bandwidth":   "bandwidth",
		"firewall":    "firewall",
		"tuning":      "tuning",
		"multus":      "multus",
		"istio-cni":   "istio-cni",
		"linkerd-cni": "linkerd-cni",
	}

	for _, binPath := range binPaths {
		if entries, err := os.ReadDir(binPath); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					name := entry.Name()
					if pluginType, exists := knownBinaries[name]; exists {
						plugin := PluginInfo{
							Name:       name,
							Type:       pluginType,
							BinaryPath: filepath.Join(binPath, name),
							Metadata:   map[string]string{"detection": "binary"},
						}

						// Try to get version
						plugin.Version = d.getBinaryVersion(plugin.BinaryPath)
						d.enrichPluginInfo(&plugin, nil)

						plugins = append(plugins, plugin)
						confidence += 0.1
					}
				}
			}
		}
	}

	return plugins, confidence
}

// detectVendorSpecific detects vendor-specific indicators
func (d *CNIPluginDetector) detectVendorSpecific() (*PluginInfo, float64) {
	// Check for cloud provider specific indicators

	// AWS
	if d.isAWS() {
		return &PluginInfo{
			Name: "aws-vpc-cni",
			Type: "aws-vpc-cni",
			Metadata: map[string]string{
				"vendor":    "AWS",
				"cloud":     "aws",
				"detection": "cloud-metadata",
			},
		}, 0.4
	}

	// Azure
	if d.isAzure() {
		return &PluginInfo{
			Name: "azure-cni",
			Type: "azure-cni",
			Metadata: map[string]string{
				"vendor":    "Microsoft",
				"cloud":     "azure",
				"detection": "cloud-metadata",
			},
		}, 0.4
	}

	// GKE (uses Cilium or Calico)
	if d.isGKE() {
		return &PluginInfo{
			Name: "gke-cni",
			Type: "cilium", // GKE Dataplane v2 uses Cilium
			Metadata: map[string]string{
				"vendor":    "Google",
				"cloud":     "gcp",
				"detection": "cloud-metadata",
			},
		}, 0.4
	}

	return nil, 0.0
}

// Helper functions for cloud detection
func (d *CNIPluginDetector) isAWS() bool {
	// Check for AWS metadata service
	indicators := []string{
		"/sys/hypervisor/uuid",           // EC2 specific
		"/sys/class/dmi/id/product_uuid", // Check for AWS UUID pattern
	}

	for _, path := range indicators {
		if data, err := os.ReadFile(path); err == nil {
			content := strings.ToLower(string(data))
			if strings.HasPrefix(content, "ec2") || strings.Contains(content, "aws") {
				return true
			}
		}
	}
	return false
}

func (d *CNIPluginDetector) isAzure() bool {
	// Check for Azure metadata
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		return strings.Contains(strings.ToLower(string(data)), "microsoft")
	}
	return false
}

func (d *CNIPluginDetector) isGKE() bool {
	// Check for GKE-specific files or environment
	gkeIndicators := []string{
		"/etc/kubernetes/gke",
		"/home/kubernetes/kube-env",
	}

	for _, path := range gkeIndicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// analyzeSpecialPlugins identifies IPAM and service mesh plugins
func (d *CNIPluginDetector) analyzeSpecialPlugins(result *DetectionResult) {
	for _, plugin := range result.ChainedPlugins {
		// Check for IPAM plugins
		if plugin.IPAM != "" || d.isIPAMPlugin(plugin.Type) {
			ipam := plugin
			result.IPAMPlugin = &ipam
		}

		// Check for service mesh integrations
		if plugin.ServiceMesh || d.isServiceMeshPlugin(plugin.Type) {
			sm := plugin
			result.ServiceMeshIntegration = &sm
		}
	}
}

// isPrimaryPlugin checks if a plugin type is a primary CNI plugin
func (d *CNIPluginDetector) isPrimaryPlugin(pluginType string) bool {
	primaryPlugins := []string{
		"cilium", "calico", "flannel", "weave", "antrea", "aws-vpc-cni",
		"azure-cni", "kube-router", "canal", "bridge", "macvlan", "ipvlan",
	}

	for _, primary := range primaryPlugins {
		if pluginType == primary {
			return true
		}
	}
	return false
}

// isIPAMPlugin checks if a plugin is an IPAM plugin
func (d *CNIPluginDetector) isIPAMPlugin(pluginType string) bool {
	ipamPlugins := []string{
		"host-local", "dhcp", "static", "calico-ipam", "cilium-ipam",
		"aws-vpc-ipam", "azure-vnet-ipam", "whereabouts",
	}

	for _, ipam := range ipamPlugins {
		if pluginType == ipam {
			return true
		}
	}
	return false
}

// isServiceMeshPlugin checks if a plugin provides service mesh integration
func (d *CNIPluginDetector) isServiceMeshPlugin(pluginType string) bool {
	meshPlugins := []string{
		"istio-cni", "linkerd-cni", "cilium", // Cilium has service mesh features
	}

	for _, mesh := range meshPlugins {
		if pluginType == mesh {
			return true
		}
	}
	return false
}

// Utility functions
func (d *CNIPluginDetector) parseConfigFromString(data, source string) []PluginInfo {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil
	}

	plugins := []PluginInfo{}
	if pluginsList, ok := config["plugins"].([]interface{}); ok {
		for _, p := range pluginsList {
			if pluginMap, ok := p.(map[string]interface{}); ok {
				if plugin := d.parsePluginConfig(pluginMap, source); plugin != nil {
					plugins = append(plugins, *plugin)
				}
			}
		}
	} else if plugin := d.parsePluginConfig(config, source); plugin != nil {
		plugins = []PluginInfo{*plugin}
	}

	return plugins
}

func (d *CNIPluginDetector) extractVersionFromImage(image string) string {
	// Extract version from container image tag
	if parts := strings.Split(image, ":"); len(parts) > 1 {
		version := parts[len(parts)-1]
		if version != "latest" {
			return version
		}
	}
	return ""
}

func (d *CNIPluginDetector) getBinaryVersion(binaryPath string) string {
	// Try to get version from binary (this would need to be implemented per binary)
	// Most CNI plugins support --version or version commands
	return ""
}

// GetPrimaryPlugin returns the detected primary CNI plugin
func (d *CNIPluginDetector) GetPrimaryPlugin() (*PluginInfo, error) {
	result, err := d.DetectPlugins()
	if err != nil {
		return nil, err
	}

	if result.PrimaryPlugin != nil {
		return result.PrimaryPlugin, nil
	}

	return nil, fmt.Errorf("no primary CNI plugin detected")
}
