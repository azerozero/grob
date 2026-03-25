#!/usr/bin/env bash
# A6: Decrypted entry must contain model name (EU AI Act Art. 12)
AUDIT_DIR="${1:?}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."
for f in "$AUDIT_DIR"/*; do
  model=$(age -d -i "$RSSI_KEY" "$f" | jq -r '.model // .model_name // empty' 2>/dev/null)
  [ -n "$model" ] || { echo "FAIL: no model field in $f"; exit 1; }
done
echo "OK: all entries have model name"
