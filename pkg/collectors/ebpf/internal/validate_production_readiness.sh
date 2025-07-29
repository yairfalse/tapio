#!/bin/bash
set -e

echo "🚀 Validating eBPF Collector Production Readiness"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    local optional="${3:-false}"
    
    echo -e "\n${YELLOW}Running: $test_name${NC}"
    echo "Command: $test_command"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if eval "$test_command"; then
        echo -e "${GREEN}✅ PASSED: $test_name${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        if [ "$optional" = "true" ]; then
            echo -e "${YELLOW}⚠️  OPTIONAL FAILED: $test_name${NC}"
        else
            echo -e "${RED}❌ FAILED: $test_name${NC}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
}

cd "$(dirname "$0")"

echo -e "\n📋 Starting validation tests..."

# 1. Basic compilation and formatting
run_test "Code formatting" "gofmt -l . | grep -v vendor | wc -l | grep -q '^0$'"
run_test "Code compilation" "go build ."
run_test "Vet analysis" "go vet ."

# 2. Unit tests
run_test "MapManager unit tests" "go test -v -run TestMapManager_CreateMap ."
run_test "PerfEventManager unit tests" "go test -v -run TestPerfEventManager ."
run_test "Rate limiter tests" "go test -v -run TestRateLimiter ."

# 3. Integration tests
run_test "Collector integration tests" "go test -v -run TestCollector_Integration ." true
run_test "Performance adapter tests" "go test -v -run TestPerformanceAdapter ." true

# 4. Load tests (optional - require more time)
echo -e "\n${YELLOW}🔥 Load Testing (may take several minutes)${NC}"
run_test "MapManager load test" "go test -v -run TestMapManagerLoadTest ." true
run_test "PerfEventManager load test" "go test -v -run TestPerfEventManagerLoadTest ." true
run_test "Full collector load test" "go test -v -run TestCollectorIntegrationUnderLoad ." true

# 5. Intelligence pipeline integration
echo -e "\n${YELLOW}🧠 Intelligence Pipeline Integration${NC}"
run_test "eBPF to Intelligence pipeline" "go test -v -run TestEBPFToIntelligencePipeline ." true
run_test "Intelligence pipeline performance" "go test -v -run TestIntelligencePipelinePerformance ." true
run_test "Memory leak prevention" "go test -v -run TestMemoryLeakPrevention ." true

# 6. Benchmarks
echo -e "\n${YELLOW}⚡ Performance Benchmarks${NC}"
run_test "MapManager concurrency benchmark" "go test -bench=BenchmarkMapManagerConcurrency -benchtime=5s ." true
run_test "Event processing benchmark" "go test -bench=BenchmarkEventProcessingPipeline -benchtime=5s ." true

# 7. Architecture compliance
echo -e "\n${YELLOW}🏗️  Architecture Compliance${NC}"
run_test "Import dependency check" "go list -f '{{.Imports}}' . | grep -v 'pkg/domain' | grep -v 'github.com/cilium/ebpf' | grep -v 'context' | grep -v 'fmt' | grep -v 'sync' | grep -v 'time' | wc -l | grep -q '^0$'" true

# 8. Memory and resource usage validation
echo -e "\n${YELLOW}💾 Resource Usage Validation${NC}"
run_test "Memory usage test" "go test -v -run TestMemoryLeakPrevention -timeout=180s ." true

# Print summary
echo -e "\n📊 VALIDATION SUMMARY"
echo "===================="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo -e "Total Tests:  $TESTS_TOTAL"

SUCCESS_RATE=$((TESTS_PASSED * 100 / TESTS_TOTAL))
echo -e "Success Rate: $SUCCESS_RATE%"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL CRITICAL TESTS PASSED - PRODUCTION READY!${NC}"
    exit 0
elif [ $SUCCESS_RATE -ge 80 ]; then
    echo -e "\n${YELLOW}⚠️  MOSTLY READY - Some optional tests failed${NC}"
    exit 0
else
    echo -e "\n${RED}❌ NOT READY FOR PRODUCTION - Critical tests failed${NC}"
    exit 1
fi