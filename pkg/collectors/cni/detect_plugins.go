package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/yairfalse/tapio/pkg/collectors/cni/core"
	"github.com/yairfalse/tapio/pkg/collectors/cni/internal"
)

func main() {
	fmt.Println("🔍 CNI Plugin Detection")
	fmt.Println("=======================")
	fmt.Println()

	// Create config for detection
	config := core.Config{
		CNIConfPath: "/etc/cni/net.d",
		CNIBinPath:  "/opt/cni/bin",
		InCluster:   false,
	}

	// Create detector
	detector, err := internal.NewCNIPluginDetector(config)
	if err != nil {
		log.Fatalf("Failed to create plugin detector: %v", err)
	}

	// Detect plugins
	result, err := detector.DetectPlugins()
	if err != nil {
		log.Fatalf("Failed to detect plugins: %v", err)
	}

	// Display results
	fmt.Printf("🎯 Detection Results (Confidence: %.1f%%)\n", result.ConfidenceScore*100)
	fmt.Printf("📊 Detection Method: %s\n", result.DetectionMethod)
	fmt.Println()

	// Primary Plugin
	if result.PrimaryPlugin != nil {
		fmt.Println("🚀 Primary CNI Plugin:")
		printPlugin(*result.PrimaryPlugin, "  ")
		fmt.Println()
	}

	// IPAM Plugin
	if result.IPAMPlugin != nil {
		fmt.Println("🌐 IPAM Plugin:")
		printPlugin(*result.IPAMPlugin, "  ")
		fmt.Println()
	}

	// Service Mesh Integration
	if result.ServiceMeshIntegration != nil {
		fmt.Println("🕸️  Service Mesh Integration:")
		printPlugin(*result.ServiceMeshIntegration, "  ")
		fmt.Println()
	}

	// Chained Plugins
	if len(result.ChainedPlugins) > 0 {
		fmt.Printf("🔗 Plugin Chain (%d plugins):\n", len(result.ChainedPlugins))
		for i, plugin := range result.ChainedPlugins {
			fmt.Printf("  %d. %s\n", i+1, plugin.Type)
			if plugin.Type != plugin.Name {
				fmt.Printf("     Name: %s\n", plugin.Name)
			}
			if plugin.Version != "" {
				fmt.Printf("     Version: %s\n", plugin.Version)
			}
			if plugin.IPAM != "" {
				fmt.Printf("     IPAM: %s\n", plugin.IPAM)
			}
			if len(plugin.Capabilities) > 0 {
				fmt.Printf("     Capabilities: %v\n", plugin.Capabilities)
			}
			if plugin.NetworkPolicy {
				fmt.Printf("     ✅ NetworkPolicy Support\n")
			}
			if plugin.ServiceMesh {
				fmt.Printf("     ✅ Service Mesh Support\n")
			}
			if vendor, ok := plugin.Metadata["vendor"]; ok {
				fmt.Printf("     Vendor: %s\n", vendor)
			}
			if cloud, ok := plugin.Metadata["cloud"]; ok {
				fmt.Printf("     Cloud: %s\n", cloud)
			}
			fmt.Println()
		}
	}

	// Summary
	fmt.Println("📋 Summary:")
	fmt.Println("============")

	if result.PrimaryPlugin != nil {
		fmt.Printf("Primary Plugin: %s", result.PrimaryPlugin.Type)
		if vendor, ok := result.PrimaryPlugin.Metadata["vendor"]; ok {
			fmt.Printf(" (%s)", vendor)
		}
		fmt.Println()

		// Capabilities summary
		capabilities := []string{}
		if result.PrimaryPlugin.NetworkPolicy {
			capabilities = append(capabilities, "NetworkPolicy")
		}
		if result.PrimaryPlugin.ServiceMesh {
			capabilities = append(capabilities, "ServiceMesh")
		}
		if result.PrimaryPlugin.IPAM != "" {
			capabilities = append(capabilities, "IPAM")
		}

		if len(capabilities) > 0 {
			fmt.Printf("Capabilities: %v\n", capabilities)
		}

		// Cloud detection
		if cloud, ok := result.PrimaryPlugin.Metadata["cloud"]; ok {
			fmt.Printf("Cloud Platform: %s\n", cloud)
		}
	}

	fmt.Printf("Total Plugins Detected: %d\n", len(result.ChainedPlugins))

	// JSON output for debugging
	if len(result.ChainedPlugins) > 0 {
		fmt.Println("\n🔧 Debug Output (JSON):")
		if jsonData, err := json.MarshalIndent(result, "", "  "); err == nil {
			fmt.Println(string(jsonData))
		}
	}
}

func printPlugin(plugin internal.PluginInfo, indent string) {
	fmt.Printf("%sType: %s\n", indent, plugin.Type)
	if plugin.Name != plugin.Type {
		fmt.Printf("%sName: %s\n", indent, plugin.Name)
	}
	if plugin.Version != "" {
		fmt.Printf("%sVersion: %s\n", indent, plugin.Version)
	}
	if plugin.ConfigPath != "" {
		fmt.Printf("%sConfig: %s\n", indent, plugin.ConfigPath)
	}
	if plugin.BinaryPath != "" {
		fmt.Printf("%sBinary: %s\n", indent, plugin.BinaryPath)
	}
	if plugin.IPAM != "" {
		fmt.Printf("%sIPAM: %s\n", indent, plugin.IPAM)
	}
	if len(plugin.Capabilities) > 0 {
		fmt.Printf("%sCapabilities: %v\n", indent, plugin.Capabilities)
	}

	// Features
	features := []string{}
	if plugin.NetworkPolicy {
		features = append(features, "NetworkPolicy")
	}
	if plugin.ServiceMesh {
		features = append(features, "ServiceMesh")
	}
	if len(features) > 0 {
		fmt.Printf("%sFeatures: %v\n", indent, features)
	}

	// Metadata
	if len(plugin.Metadata) > 0 {
		fmt.Printf("%sMetadata:\n", indent)
		for key, value := range plugin.Metadata {
			fmt.Printf("%s  %s: %s\n", indent, key, value)
		}
	}
}
