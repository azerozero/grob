#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

AUDIT_DIR="/tmp/grob-audit"
HOST="127.0.0.1:13456"
JWT=$(cat auth/tokens/jwt-hospital-eu.txt)

# Grob keeps this journal open: deleting it would leave writes on an unlinked
# inode. Verify new entries instead of resetting a live mounted directory.
before=0
if [[ -f "$AUDIT_DIR/current.jsonl" ]]; then
  before=$(wc -l < "$AUDIT_DIR/current.jsonl")
fi

echo "Generating audit entries..."
for _ in $(seq 1 3); do
  curl -sf -X POST "http://${HOST}/v1/chat/completions" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d @fixtures/chat-simple.json > /dev/null
done

for ((attempt=0; attempt<10; attempt++)); do
  if [[ -f "$AUDIT_DIR/current.jsonl" ]] && (( $(wc -l < "$AUDIT_DIR/current.jsonl") > before )); then
    break
  fi
  sleep 1
done
if [[ ! -f "$AUDIT_DIR/current.jsonl" ]] || (( $(wc -l < "$AUDIT_DIR/current.jsonl") <= before )); then
  echo "No new audit entries were written" >&2
  exit 1
fi

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
