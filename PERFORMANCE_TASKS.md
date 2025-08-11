# Performance Optimization Tasks for Intelligence Package

## CRITICAL TASKS (Fix Immediately - Blocking Production)

### PERF-001: Remove map[string]interface{} from Neo4j Query Interfaces
**Priority**: CRITICAL  
**Impact**: 40% reduction in memory allocations  
**Branch**: `perf/001-typed-neo4j-queries`

**Files to Modify**:
- `pkg/intelligence/patterns/detector.go`
- `pkg/intelligence/service.go`
- `pkg/intelligence/queries/correlations.go`

**Changes Required**:
1. Replace `map[string]interface{}` with strongly-typed structs
2. Create type-safe query result structures
3. Remove runtime type assertions

**Success Criteria**:
- Zero `interface{}` in public APIs
- All type assertions removed
- Benchmark shows 40% allocation reduction

---

### PERF-002: Implement Object Pooling for CorrelationResults
**Priority**: CRITICAL  
**Impact**: 60% reduction in GC pressure  
**Branch**: `perf/002-correlation-result-pooling`

**Files to Modify**:
- `pkg/intelligence/correlation/engine.go`
- `pkg/intelligence/correlation/pool.go` (new)

**Changes Required**:
1. Create `sync.Pool` for CorrelationResult objects
2. Implement proper reset methods
3. Add pool metrics

**Success Criteria**:
- GC pressure reduced by 60%
- No memory leaks
- Pool hit rate > 90%

---

### PERF-003: Replace Synchronous Storage with Async Batching
**Priority**: CRITICAL  
**Impact**: 10x throughput improvement  
**Branch**: `perf/003-async-batch-storage`

**Files to Modify**:
- `pkg/intelligence/correlation/engine.go`
- `pkg/intelligence/correlation/batch_storage.go` (new)

**Changes Required**:
1. Implement batch accumulator with time/size triggers
2. Add async flush with error recovery
3. Implement backpressure control

**Success Criteria**:
- 10x throughput increase
- P99 latency < 10ms
- Zero data loss

---

## HIGH PRIORITY TASKS (Fix Within Days)

### PERF-004: Optimize Lock Contention in processEvent
**Priority**: HIGH  
**Impact**: 70% reduction in lock wait time  
**Branch**: `perf/004-reduce-lock-contention`

**Files to Modify**:
- `pkg/intelligence/correlation/engine.go:395-406`

**Changes Required**:
1. Replace mutex with atomic operations for counters
2. Use lock-free structures for metrics
3. Minimize critical sections

**Success Criteria**:
- Lock contention reduced by 70%
- No race conditions
- Benchmark improvement

---

### PERF-005: Implement Graph Query Result Caching
**Priority**: HIGH  
**Impact**: 80% reduction in Neo4j load  
**Branch**: `perf/005-query-result-caching`

**Files to Modify**:
- `pkg/intelligence/correlation/cache.go` (new)
- `pkg/intelligence/correlation/ownership_correlator.go`
- `pkg/intelligence/correlation/dependency_correlator.go`

**Changes Required**:
1. Implement TTL-based cache with LRU eviction
2. Add cache invalidation logic
3. Add cache metrics

**Success Criteria**:
- 80% cache hit rate
- Neo4j query reduction
- Memory bounded

---

### PERF-006: Replace Mutexes with Lock-Free Structures
**Priority**: HIGH  
**Impact**: 3x better scaling under load  
**Branch**: `perf/006-lock-free-structures`

**Files to Modify**:
- `pkg/intelligence/correlation/temporal.go`
- `pkg/intelligence/correlation/engine.go`

**Changes Required**:
1. Use atomic.Value for read-heavy data
2. Implement lock-free ring buffers
3. Use channels for coordination

**Success Criteria**:
- 3x scaling improvement
- Zero deadlocks
- Benchmark validation

---

## MEDIUM PRIORITY TASKS (Fix Within Weeks)

### PERF-007: Batch Correlation Processing
**Priority**: MEDIUM  
**Impact**: 60% overhead reduction  
**Branch**: `perf/007-batch-correlation`

**Files to Modify**:
- `pkg/intelligence/correlation/engine.go`
- `pkg/intelligence/correlation/batch_processor.go` (new)

**Changes Required**:
1. Accumulate events for batch processing
2. Process correlations in parallel batches
3. Implement adaptive batch sizing

---

### PERF-008: Query Result Object Pooling
**Priority**: MEDIUM  
**Impact**: 50% allocation reduction  
**Branch**: `perf/008-query-result-pooling`

**Files to Modify**:
- `pkg/intelligence/correlation/graph_store.go`
- `pkg/intelligence/correlation/query_pool.go` (new)

---

### PERF-009: Pre-compiled Cypher Query Templates
**Priority**: MEDIUM  
**Impact**: 30% query preparation reduction  
**Branch**: `perf/009-precompiled-queries`

**Files to Modify**:
- `pkg/intelligence/correlation/query_templates.go` (new)
- All correlator files using queries

---

### PERF-010: Optimize Temporal Window with Circular Buffer
**Priority**: MEDIUM  
**Impact**: 40% faster window operations  
**Branch**: `perf/010-circular-buffer`

**Files to Modify**:
- `pkg/intelligence/correlation/temporal.go`

---

## Testing Requirements for All Tasks

### Benchmarks Required
```go
func BenchmarkBeforeOptimization(b *testing.B)
func BenchmarkAfterOptimization(b *testing.B)
```

### Load Tests Required
- 1000 events/second sustained
- 10,000 events burst
- Memory usage under 2GB

### Verification Tests
- Race detector clean (`go test -race`)
- No memory leaks (pprof analysis)
- Coverage > 80%

## Commit Message Format
```
perf(correlation): [task description]

- [Specific change 1]
- [Specific change 2]
- [Performance improvement metric]

Benchmark results:
Before: [metric]
After: [metric]
Improvement: [percentage]

Fixes PERF-XXX
```