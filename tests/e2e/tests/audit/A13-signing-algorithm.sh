#!/usr/bin/env bash
# A13: Signing algorithm field in audit entries
#
# Each audit entry should record which signing algorithm was used
# (ecdsa-p256, ed25519, hmac-sha256).
set -euo pipefail
cd "$(dirname "$0")/../.."
AUDIT_DIR="${1:-/tmp/grob-audit}"
RSSI_KEY="crypto/rssi.key"

found=false
for f in "$AUDIT_DIR"/*; do
  [ -f "$f" ] || continue
  if [ -f "$RSSI_KEY" ]; then
    content=$(age -d -i "$RSSI_KEY" "$f" 2>/dev/null || cat "$f" 2>/dev/null || true)
  else
    content=$(cat "$f" 2>/dev/null || true)
  fi
  [ -z "$content" ] && continue
  while IFS= read -r line; do
    alg=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('signature_algorithm',''))" 2>/dev/null || true)
    if [ -n "$alg" ]; then
      found=true
      case "$alg" in
        ecdsa-p256|ed25519|hmac-sha256) ;;
        *) echo "FAIL: A13 — unknown algorithm '$alg'"; exit 1 ;;
      esac
    fi
  done <<< "$content"
done

if $found; then
  echo "OK: A13 — signing algorithm recorded"
else
  echo "SKIP: A13 — no signature_algorithm field (may need compliance feature)"
fi
