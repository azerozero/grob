#!/usr/bin/env bash
# A7: Decrypted entry must contain token counts (EU AI Act Art. 12)
AUDIT_DIR="${1:?}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."
for f in "$AUDIT_DIR"/*; do
  tokens=$(age -d -i "$RSSI_KEY" "$f" | jq -r '.token_counts // .usage // empty' 2>/dev/null)
  [ -n "$tokens" ] || { echo "FAIL: no token_counts/usage field in $f"; exit 1; }
done
echo "OK: all entries have token counts"
