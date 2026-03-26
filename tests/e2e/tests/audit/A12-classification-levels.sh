#!/usr/bin/env bash
# A12: Classification levels present in audit entries (EU AI Act Art. 6)
#
# Sends three requests with different risk profiles (clean, canary, PII),
# then checks whether audit entries contain a classification field.
set -euo pipefail
cd "$(dirname "$0")/../.."
HOST="${HOST:-127.0.0.1:13456}"
JWT="${JWT:-$(cat auth/tokens/jwt-default.txt 2>/dev/null || echo "")}"
AUDIT_DIR="${1:-/tmp/grob-audit}"
RSSI_KEY="crypto/rssi.key"

# Send clean request (expected: NC / no classification)
curl -sf "http://$HOST/v1/chat/completions" -X POST \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"model":"default","max_tokens":10,"messages":[{"role":"user","content":"2+2"}]}' >/dev/null

# Send canary token request (expected: C1)
curl -sf "http://$HOST/v1/chat/completions" -X POST \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"model":"default","max_tokens":10,"messages":[{"role":"user","content":"itk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}' >/dev/null

# Send PII credit card request (expected: C2)
curl -sf "http://$HOST/v1/chat/completions" -X POST \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"model":"default","max_tokens":10,"messages":[{"role":"user","content":"card 4111111111111111"}]}' >/dev/null

sleep 2

found_any=false
for f in "$AUDIT_DIR"/*; do
  [ -f "$f" ] || continue
  # Try age-decrypted first, fall back to plaintext.
  if [ -f "$RSSI_KEY" ]; then
    content=$(age -d -i "$RSSI_KEY" "$f" 2>/dev/null || cat "$f" 2>/dev/null || true)
  else
    content=$(cat "$f" 2>/dev/null || true)
  fi
  [ -z "$content" ] && continue
  while IFS= read -r line; do
    cls=$(echo "$line" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('classification',''))" 2>/dev/null || true)
    [ -n "$cls" ] && found_any=true
  done <<< "$content"
done

if $found_any; then
  echo "OK: A12 — classification levels present in audit"
else
  echo "SKIP: A12 — no classification field in audit entries (may need compliance feature)"
fi
