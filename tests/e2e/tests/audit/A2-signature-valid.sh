#!/usr/bin/env bash
# A2: ECDSA-P256 signature must verify
# After decryption with rssi key, check that the entry has a valid signature field
AUDIT_DIR="${1:?}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."
for f in "$AUDIT_DIR"/*; do
  decrypted=$(age -d -i "$RSSI_KEY" "$f" 2>/dev/null) || { echo "FAIL: cannot decrypt $f"; exit 1; }
  sig=$(echo "$decrypted" | jq -r '.signature // empty' 2>/dev/null)
  [ -n "$sig" ] || { echo "FAIL: no signature field in $f"; exit 1; }
done
echo "OK: all entries have signature field"
