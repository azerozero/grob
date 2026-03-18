#!/usr/bin/env bash
# CodeQL security analysis for grob.
# Usage: ./scripts/codeql-check.sh [--sarif results.sarif]
#
# Creates a fresh CodeQL database, runs security-extended queries,
# and reports findings. Exit code 0 = no alerts, 1 = alerts found.

set -euo pipefail

DB_DIR="${CODEQL_DB:-codeql-db}"
OUTPUT="${1:---format=csv}"
SARIF_FILE=""

if [[ "${1:-}" == "--sarif" ]]; then
    SARIF_FILE="${2:-results.sarif}"
    OUTPUT="--format=sarif-latest --output=$SARIF_FILE"
fi

echo "Creating CodeQL database..."
codeql database create "$DB_DIR" \
    --language=rust \
    --source-root=. \
    --overwrite \
    --threads=0 \
    2>&1 | tail -3

echo ""
echo "Running security analysis..."

# shellcheck disable=SC2086
RESULTS=$(codeql database analyze "$DB_DIR" \
    --threads=0 \
    $OUTPUT \
    2>&1)

echo "$RESULTS"

if [[ -n "$SARIF_FILE" ]] && [[ -f "$SARIF_FILE" ]]; then
    ALERT_COUNT=$(python3 -c "
import json, sys
with open('$SARIF_FILE') as f:
    d = json.load(f)
    total = sum(len(r.get('results', [])) for r in d.get('runs', []))
    print(total)
" 2>/dev/null || echo "?")
    echo ""
    echo "Alerts found: $ALERT_COUNT"
    echo "SARIF saved to: $SARIF_FILE"
    if [[ "$ALERT_COUNT" != "0" ]] && [[ "$ALERT_COUNT" != "?" ]]; then
        exit 1
    fi
fi
