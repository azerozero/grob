#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

AUDIT_DIR="/tmp/grob-audit"
HOST="127.0.0.1:13456"
JWT=$(cat auth/tokens/jwt-hospital-eu.txt)

rm -rf "$AUDIT_DIR" && mkdir -p "$AUDIT_DIR"

echo "Generating audit entries..."
for i in $(seq 1 3); do
  curl -sf -X POST "http://${HOST}/v1/chat/completions" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d @fixtures/chat-simple.json > /dev/null
done

sleep 2

PASS=0; FAIL=0
for test in tests/audit/A*.sh; do
  if bash "$test" "$AUDIT_DIR"; then
    echo "✓ $(basename "$test")"
    ((PASS++)) || true
  else
    echo "✗ $(basename "$test")"
    ((FAIL++)) || true
  fi
done

echo ""
echo "Audit tests: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
