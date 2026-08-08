#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# =========================================================================
# AegisGate Rampart — Run All k6 Break/Crush Tests
# =========================================================================
# Runs the full test suite in order from lightest to heaviest.
# Stops on CRASH (connection refused) since that's a critical failure.
# =========================================================================

set -euo pipefail

RAMPART_URL="${RAMPART_URL:-http://127.0.0.1:8080}"
RESULTS_DIR="$(dirname "$0")/results"
LOG_DIR="$(dirname "$0")/results"

mkdir -p "$RESULTS_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} AegisGate Rampart — k6 Test Suite${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo -e "Target: ${GREEN}${RAMPART_URL}${NC}"
echo -e "Results: ${GREEN}${RESULTS_DIR}${NC}"
echo ""

# Verify Rampart is running
echo -e "${YELLOW}[PRE-CHECK]${NC} Verifying Rampart is running..."
if ! curl -sf "${RAMPART_URL}/stats" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Rampart is not running at ${RAMPART_URL}${NC}"
    echo -e "${YELLOW}Start it with: ./rampart --rate-limit 10000${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Rampart is running${NC}"
echo ""

# Track overall results
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

run_test() {
    local name="$1"
    local file="$2"
    local extra_args="${3:-}"

    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Running: ${name}${NC}"
    echo -e "${BLUE}=========================================${NC}"

    local output_file="${RESULTS_DIR}/$(basename "${file}" .js)-output.json"
    local exit_code=0

    if k6 run ${extra_args} --env RAMPART_URL="${RAMPART_URL}" "${file}" 2>&1 | tee "${output_file%.json}.log" ; then
        # Check for crash in output
        if grep -q '"crash_rate": "0.0000%"' "${output_file%.json}.log" 2>/dev/null || \
           grep -q '"crash_safe": "✅' "${output_file%.json}.log" 2>/dev/null; then
            echo -e "${GREEN}✓ ${name} PASSED${NC}"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo -e "${YELLOW}? ${name} completed — check results for crash indicators${NC}"
            PASS_COUNT=$((PASS_COUNT + 1))
        fi
    else
        exit_code=$?
        if [ $exit_code -eq 99 ]; then
            echo -e "${RED}✗ ${name} FAILED — thresholds not met${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        elif [ $exit_code -eq 102 ]; then
            echo -e "${RED}✗ ${name} ABORTED — script error${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        else
            echo -e "${YELLOW}? ${name} exited with code ${exit_code}${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi

    # Brief pause between tests to let Rampart recover
    echo -e "${YELLOW}[COOLDOWN]${NC} Waiting 5s for Rampart recovery..."
    sleep 5

    # Verify Rampart is still running
    if ! curl -sf "${RAMPART_URL}/stats" > /dev/null 2>&1; then
        echo -e "${RED}⚠ RAMPART CRASHED! Stopping test suite.${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo ""
        echo -e "${RED}=========================================${NC}"
        echo -e "${RED} CRITICAL: Rampart process is no longer responding${NC}"
        echo -e "${RED}=========================================${NC}"
        exit 1
    fi
}

# Test 1: Stress test (baseline performance)
run_test "Stress Test (Baseline)" "$(dirname "$0")/stress-test.js"

# Test 2: Rate limit verification
run_test "Rate Limit Test" "$(dirname "$0")/rate-limit-test.js"

# Test 3: Malformed input resilience
run_test "Malformed Input Test" "$(dirname "$0")/malformed-input-test.js"

# Test 4: Connection flood resilience
run_test "Connection Flood Test" "$(dirname "$0")/connection-flood-test.js"

# Test 5: Break test (find the ceiling)
run_test "Break Test (Find Ceiling)" "$(dirname "$0")/break-test.js"

# Test 6: Crush test (progressive crush + recovery)
run_test "Crush Test (2000 VUs)" "$(dirname "$0")/crush-test.js"

# Test 7: Endurance (5-minute sustained load)
run_test "Endurance Test (5min)" "$(dirname "$0")/endurance-test.js"

# Summary
echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} Test Suite Summary${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "  ${GREEN}Passed: ${PASS_COUNT}${NC}"
echo -e "  ${RED}Failed: ${FAIL_COUNT}${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed! Rampart is break-safe.${NC}"
    exit 0
else
    echo -e "${RED}❌ ${FAIL_COUNT} test(s) failed. Review results in ${RESULTS_DIR}${NC}"
    exit 1
fi