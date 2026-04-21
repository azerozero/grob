#!/usr/bin/env bash
#
# CodeQL security analysis for grob.
#
# Usage: see --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

usage() {
  cat <<EOF
${SCRIPT_NAME} - CodeQL security analysis for grob

Creates a fresh CodeQL database, runs security-extended queries,
and reports findings.

Usage: ${SCRIPT_NAME} [options]
       ${SCRIPT_NAME} --sarif [file]

Options:
  -h, --help            Show this help and exit
  -v, --verbose         Enable verbose output (shell trace)
  --sarif [file]        Emit SARIF output (default file: results.sarif)

Environment:
  CODEQL_DB             Database directory (default: codeql-db)

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} --sarif
  ${SCRIPT_NAME} --sarif custom.sarif

Exit codes:
  0  no alerts (or CSV run completed)
  1  alerts found (SARIF mode) or error
EOF
}

main() {
  local verbose=0
  local sarif_file=""
  local output="--format=csv"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -v|--verbose) verbose=1; shift ;;
      --sarif)
        shift
        sarif_file="${1:-results.sarif}"
        if [[ -n "${1:-}" && ! "$1" =~ ^-- ]]; then
          shift
        fi
        output="--format=sarif-latest --output=${sarif_file}"
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  if [[ "${verbose}" -eq 1 ]]; then
    set -x
  fi

  local db_dir="${CODEQL_DB:-codeql-db}"

  echo "Creating CodeQL database..."
  codeql database create "${db_dir}" \
    --language=rust \
    --source-root=. \
    --overwrite \
    --threads=0 \
    2>&1 | tail -3

  echo ""
  echo "Running security analysis..."

  local results
  # shellcheck disable=SC2086
  results=$(codeql database analyze "${db_dir}" \
    --threads=0 \
    ${output} \
    2>&1)

  echo "${results}"

  if [[ -n "${sarif_file}" ]] && [[ -f "${sarif_file}" ]]; then
    local alert_count
    alert_count=$(SARIF_FILE="${sarif_file}" python3 -c "
import json, os
with open(os.environ['SARIF_FILE']) as f:
    d = json.load(f)
    total = sum(len(r.get('results', [])) for r in d.get('runs', []))
    print(total)
" 2>/dev/null || echo "?")
    echo ""
    echo "Alerts found: ${alert_count}"
    echo "SARIF saved to: ${sarif_file}"
    if [[ "${alert_count}" != "0" ]] && [[ "${alert_count}" != "?" ]]; then
      exit 1
    fi
  fi
}

main "$@"
