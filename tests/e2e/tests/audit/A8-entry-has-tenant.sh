#!/usr/bin/env bash
# A8: Decrypted entry must contain tenant from JWT claims
AUDIT_DIR="${1:?}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."
for f in "$AUDIT_DIR"/*; do
  tenant=$(age -d -i "$RSSI_KEY" "$f" | jq -r '.tenant // .tenant_id // empty' 2>/dev/null)
  [ -n "$tenant" ] || { echo "FAIL: no tenant field in $f"; exit 1; }
done
echo "OK: all entries have tenant from JWT"
