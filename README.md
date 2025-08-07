# Tapio

A correlation engine for Kubernetes observability that actually finds root causes.

## What is Tapio?

Tapio watches your Kubernetes cluster and automatically correlates events to identify why things break. Instead of drowning in logs and metrics, you get clear answers about what went wrong and why.

## How It Works

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Kubernetes │     │    System   │     │   Network   │
│   Cluster   │     │  (eBPF/sys) │     │  (DNS/CNI)  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                    │
       │ events            │ events             │ events
       ▼                   ▼                    ▼
┌─────────────────────────────────────────────────────┐
│                     Collectors                      │
│  (kubeapi, kubelet, ebpf, systemd, etcd, cni, dns) │
└─────────────────────────┬───────────────────────────┘
                          │
                          │ raw events
                          ▼
                    ┌───────────┐
                    │   NATS    │
                    │  Message  │
                    │    Bus    │
                    └─────┬─────┘
                          │
                          │ unified events
                          ▼
                ┌───────────────────┐
                │   Correlation     │
                │     Engine        │
                └─────────┬─────────┘
                          │
                          │ correlations
                          ▼
                ┌───────────────────┐
                │    Analysis       │
                │     Engine        │
                │   "Smart Brain"   │
                └─────────┬─────────┘
                          │
                          │ insights
                          ▼
                ┌───────────────────┐
                │    Root Cause     │
                │   + What To Do    │
                └───────────────────┘
```

## Core Components

### Collectors (Level 1)
- **kubeapi**: Kubernetes API events and resource changes
- **kubelet**: Node-level metrics and pod lifecycle events
- **ebpf**: Kernel-level system calls and network events  
- **etcd**: Cluster state changes and configuration updates
- **systemd**: Service logs and system events
- **cni**: Container networking events and connectivity
- **dns**: DNS queries and resolution patterns

### Intelligence Layer (Level 2)
- **Correlation Engine**: Finds relationships between events
  - Temporal correlation (events happening together)
  - Kubernetes ownership chains
  - Service dependency mapping
  - Network communication patterns
  
- **Analysis Engine**: The "Smart Brain" that produces insights
  - Aggregates correlations from multiple sources
  - Scores confidence based on evidence strength
  - Detects patterns (cascading failures, periodic issues)
  - Generates human-readable recommendations

### Architecture Principles

We follow a strict 5-level hierarchy:
```
Level 0: domain/       # Core types, zero dependencies
Level 1: collectors/   # Data collection, domain only  
Level 2: intelligence/ # Correlation & analysis
Level 3: integrations/ # External systems
Level 4: interfaces/   # APIs and UIs
```

Each level can only import from lower levels. No exceptions.

## Getting Started

```bash
# Build the services
make build

# Run correlation service
./bin/correlation-service

# Run Tapio CLI
./bin/tapio --config config/tapio.yaml
```

## Configuration

```yaml
# config/tapio.yaml
collectors:
  enabled:
    - kubeapi
    - kubelet
    - ebpf
    - etcd
    - systemd
    - cni
    - dns
  buffer_size: 2000
  
pipeline:
  endpoint: "localhost:50051"
```

## How It Works

1. **Collectors** gather raw events from every layer of your infrastructure
2. **Pipeline** (NATS) transports and buffers events reliably
3. **Correlation Engine** finds relationships between seemingly unrelated events
4. **Analysis Engine** turns technical correlations into actionable insights

Example: When a pod crashes, Tapio doesn't just tell you it crashed - it tells you:
- The ConfigMap change 5 minutes ago triggered it
- Which resulted in a connection pool exhaustion
- That caused memory pressure
- Leading to the OOM kill

## Development

```bash
# Format code (required)
make fmt

# Run tests
make test

# Build everything
make build
```

## Status

This is an active research project exploring semantic correlation in observability. We're building real implementations, not prototypes.

Core components working:
- ✅ Multi-layer event collection (K8s, eBPF, network, system)
- ✅ Correlation engine with pattern detection
- ✅ Analysis engine with confidence scoring
- ✅ NATS-based event pipeline

---

Built with discipline. No stubs, no shortcuts, no excuses.