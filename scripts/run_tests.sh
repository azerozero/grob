#!/usr/bin/env bash
#
# TDD test runner for Grob (unit + doc tests).
#
# Usage: see --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

usage() {
  cat <<EOF
${SCRIPT_NAME} - TDD test runner for Grob

Runs unit tests and doc tests via cargo test. Returns non-zero if any
test type fails.

Usage: ${SCRIPT_NAME} [options]

Options:
  -h, --help       Show this help and exit
  -v, --verbose    Enable verbose output (shell trace)

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} --verbose

Exit codes:
  0  all tests passed
  1  one or more test suites failed
EOF
}

# Color vars are set in main() and consumed here via globals.
run_tests() {
  local test_type=$1
  local color=$2

  echo -e "${color}Running ${test_type} tests...${NC}"

  if cargo test "${test_type}" -- --nocapture; then
    echo -e "${GREEN}PASS: ${test_type} tests passed${NC}"
    return 0
  else
    echo -e "${RED}FAIL: ${test_type} tests failed${NC}"
    return 1
  fi
}

main() {
  local verbose=0
  while getopts "hv-:" opt; do
    case "${opt}" in
      h) usage; exit 0 ;;
      v) verbose=1 ;;
      -)
        case "${OPTARG}" in
          help) usage; exit 0 ;;
          verbose) verbose=1 ;;
          *) echo "Unknown option --${OPTARG}" >&2; usage >&2; exit 1 ;;
        esac
        ;;
      *) usage >&2; exit 1 ;;
    esac
  done
  shift $((OPTIND - 1))

  if [[ "${verbose}" -eq 1 ]]; then
    set -x
  fi

  echo "Running Grob Test Suite"
  echo "=================================="

  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
  else
    RED='' GREEN='' YELLOW='' NC=''
  fi
  export RED GREEN YELLOW NC

  local failed=0

  if ! run_tests "unit" "${GREEN}"; then
    failed=1
  fi

  if ! run_tests "--doc" "${YELLOW}"; then
    failed=1
  fi

  echo ""
  echo "=================================="
  if [ ${failed} -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
  else
    echo -e "${RED}Some tests failed${NC}"
  fi

  exit ${failed}
}

main "$@"
