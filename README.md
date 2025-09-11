# Tapio

> "Experience without theory is blind, but theory without experience is mere intellectual play." — Immanuel Kant

**Observability that understands your systems, not just measures them.**

## The Idea

Most observability tools collect metrics and hope you can figure out what went wrong. Tapio watches the kernel and correlates events to tell you what actually happened.

When your service starts failing, you don't need another dashboard showing CPU is high. You need to know that the memory allocator is fragmenting, causing garbage collection storms, which trigger circuit breakers in your API gateway, leading to cascading timeouts across your service mesh.

That's correlation. That's understanding.

## Observer Architecture

```
                     🏢 Kubernetes Cluster
    ┌─────────────────────────────────────────────────────────┐
    │                                                         │
    │  📦 Pod            📦 Pod            📦 Pod             │
    │  api-gateway       redis-cache       worker-service     │
    │                                                         │
    └─────────────┬───────────────┬───────────────┬───────────┘
                  │               │               │
    ┌─────────────▼───────────────▼───────────────▼───────────┐
    │                 🔍 Observer Layer                       │
    │  ┌─────────────────────────────────────────────────────┐ │
    │  │          Specialized Observers                      │ │
    │  │                                                     │ │
    │  │  Network ────┬──── Status ────┬──── Memory          │ │
    │  │      │       │        │       │        │            │ │
    │  │  Services ───┼──── Health ────┼──── Kernel          │ │
    │  │      │       │        │       │        │            │ │
    │  │  Storage ────┴──── Runtime ───┴──── Scheduler       │ │
    │  │                                                     │ │
    │  └─────────────────┬───────────────────────────────────┘ │
    │                    │ Structured Events                   │
    │                    ▼                                     │
    │  ┌─────────────────────────────────────────────────────┐ │
    │  │           🧠 Intelligence Layer                      │ │
    │  │                                                     │ │
    │  │   Event         Pattern        Root Cause          │ │
    │  │   Correlation ─▶ Recognition ─▶ Analysis           │ │
    │  │                                                     │ │
    │  └─────────────────┬───────────────────────────────────┘ │
    └────────────────────┼─────────────────────────────────────┘
                         │
                         ▼
        📊 Understanding: "Memory leak in redis caused 
            API timeouts leading to user retry storm"
```

## What We Actually Built

**15 observers** that watch different aspects of your system:

**Infrastructure**: Kernel syscalls, network L7 protocols, storage I/O, memory allocation, container runtime
**Application**: HTTP/gRPC status patterns, service dependencies, process signals, health checks  
**Platform**: Pod scheduling, resource lifecycle, systemd services, network links, OpenTelemetry

Each observer understands its domain deeply. The Status Observer doesn't just count HTTP 500s—it detects cascading failure patterns and retry storms. The Memory Observer doesn't just track allocations—it identifies leak patterns and fragmentation issues.

## Why This Matters

> "The task of the critic is to transform experience into memory." — Walter Benjamin

Traditional monitoring gives you the present moment. Tapio gives you the story of how you got there.

Instead of:
- "CPU is at 80%"
- "Response time increased"  
- "Error rate spiked"

You get:
- "Memory fragmentation triggered GC pressure, causing API timeouts, leading to client retry storms"

## Real Deployment

```bash
git clone https://github.com/yairfalse/tapio
cd tapio
make build
kubectl apply -f k8s/
```

Tapio runs as a DaemonSet, one agent per node, collecting kernel-level events and correlating them into understanding.

## Current State

We have the observer layer working and the correlation foundation built. The intelligence layer is being developed to connect events into meaningful patterns.

This is systems software for people who understand that observability is about comprehension, not collection.

---

*Built for engineers who need to understand, not just monitor.*