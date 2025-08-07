# Analysis Package - The Smart Brain

This package is the intelligence layer that transforms raw correlations into actionable insights.

## ✅ Status: OPERATIONAL

The analysis package has been completely rebuilt with:
- **Real analysis engine** - No stubs, no fakes
- **Confidence scoring** with decay and weighting algorithms
- **Pattern detection** for cascading failures, periodic issues, etc.
- **Insight generation** - Human-readable understanding
- **Recommendation engine** - Actionable steps to resolve issues

## Architecture

### Core Components

1. **Engine** (`engine.go`)
   - Main orchestrator that processes correlations
   - Aggregates related correlations
   - Generates findings, insights, and recommendations

2. **Confidence Scorer** (`confidence_scorer.go`)
   - Calculates confidence based on:
     - Correlator agreement
     - Evidence strength
     - Temporal proximity
     - Time decay

3. **Pattern Matcher** (`pattern_matcher.go`)
   - Detects known patterns:
     - Cascading failures
     - Periodic issues
     - Progressive degradation
     - Correlated events
     - Sequential patterns

4. **History Store** (`history_store.go`)
   - Stores historical findings for pattern matching
   - Enables learning from past incidents

## How It Works

```go
// 1. Correlation engine produces results
correlations := []CorrelationData{
    {ID: "corr1", Source: "k8s", Confidence: 0.8, ...},
    {ID: "corr2", Source: "temporal", Confidence: 0.7, ...},
}

// 2. Analysis engine processes them
engine := NewEngine(logger, config)
report := engine.Analyze(ctx, correlations)

// 3. Get actionable intelligence
fmt.Println(report.Summary)           // "CRITICAL: 2 issues need attention"
fmt.Println(report.Findings[0].Title) // "Config change caused pod failures"
fmt.Println(report.Recommendations[0].Title) // "Rollback ConfigMap version"
```

## No Dependencies on Other Intelligence Packages

The analysis package uses a minimal `CorrelationData` interface to avoid circular dependencies:

```go
type CorrelationData struct {
    ID         string
    Source     string    // which correlator
    EventIDs   []string
    Confidence float64
    Evidence   []string
    Summary    string
    // ... minimal fields needed
}
```

## Integration

The API layer (Level 4) orchestrates:
1. Collects correlation results
2. Transforms to `CorrelationData`
3. Feeds to analysis engine
4. Returns findings and recommendations

## Testing

```bash
cd pkg/intelligence/analysis
go test ./...
```

## What's Different Now

### Before (Fake)
- Stub functions returning hardcoded values
- Fake confidence scores (always 0.7)
- No actual analysis logic
- Circular dependencies with aggregator

### After (Real)
- Real scoring algorithms with configurable weights
- Pattern detection using actual data
- Insight generation based on evidence
- Clean architecture with no circular dependencies
- Production-ready code

## Next Steps

1. Add more pattern definitions
2. Implement machine learning for pattern discovery
3. Add persistent history store (Redis/PostgreSQL)
4. Enhance recommendation automation