# 🌲 Tapio

**Dual-Input Intelligence for Kubernetes**

Tapio correlates what Kubernetes *thinks* is happening with what's *actually* happening at the kernel level, predicting failures before they occur.

## Quick Start

```bash
# Install
go install github.com/yourusername/tapio/cmd/tapio@latest

# Analyze a problematic pod
tapio analyze pod/my-broken-app

# Start continuous monitoring
tapio guard --namespace production
What Makes Tapio Special

Dual Intelligence: Combines K8s API data with kernel-level eBPF insights
Predictive: Warns about OOM kills, network failures, and resource issues before they happen
Developer-Focused: CLI-first tool that fits your debugging workflow
Zero Instrumentation: No application changes required

Example Output
❌ Pod will OOM in 8 minutes (95% confidence)
📊 Memory growing 15Mi/min, limit is 256Mi
🔧 Fix: kubectl patch deployment api -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"limits":{"memory":"1Gi"}}}]}}}}'
⚡ Auto-apply? [y/N]
Architecture
Tapio consists of three loosely-coupled components:

CLI Tool - Local analysis using your kubeconfig
eBPF Collectors - Kernel-level data collection (optional)
API Watchers - Historical trend analysis (optional)

Installation
See docs/installation.md for detailed instructions.
Contributing
See docs/development.md for development setup.
License
Apache 2.0 - see LICENSE

