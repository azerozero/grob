#!/usr/bin/env bash
# A10: Verify audit entries have batch signing fields when batch_size > 1.
# NOTE: requires grob config with audit_batch_size > 1.
# For now, just verify that entries have the signature field.
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."

for f in "$AUDIT_DIR"/*; do
  decrypted=$(age -d -i "$RSSI_KEY" "$f" 2>/dev/null) || { echo "FAIL: cannot decrypt $f"; exit 1; }
  sig=$(echo "$decrypted" | jq -r '.signature // empty' 2>/dev/null)
  [ -n "$sig" ] || { echo "FAIL: no signature field in $f"; exit 1; }
done
echo "OK: all entries have signature field"
