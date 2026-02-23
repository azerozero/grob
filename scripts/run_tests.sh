#!/bin/bash
# TDD Test Runner for Claude Code Mux

set -e

echo "Running Claude Code Mux Test Suite"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run tests
run_tests() {
    local test_type=$1
    local color=$2

    echo -e "${color}Running $test_type tests...${NC}"

    if cargo test "$test_type" -- --nocapture; then
        echo -e "${GREEN}✓ $test_type tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_type tests failed${NC}"
        return 1
    fi
}

# Track results
FAILED=0

# Run unit tests
if ! run_tests "unit" "$GREEN"; then
    FAILED=1
fi

# Run doc tests
if ! run_tests "--doc" "$YELLOW"; then
    FAILED=1
fi

# Summary
echo ""
echo "=================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed${NC}"
fi

exit $FAILED
