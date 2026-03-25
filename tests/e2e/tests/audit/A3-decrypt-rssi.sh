#!/usr/bin/env bash
# A3: RSSI key can decrypt and produce valid JSON
AUDIT_DIR="${1:?}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."
for f in "$AUDIT_DIR"/*; do
  decrypted=$(age -d -i "$RSSI_KEY" "$f" 2>/dev/null) || { echo "FAIL: cannot decrypt $f with RSSI key"; exit 1; }
  echo "$decrypted" | jq . > /dev/null 2>&1 || { echo "FAIL: decrypted $f is not valid JSON"; exit 1; }
done
echo "OK: RSSI can decrypt all entries to valid JSON"
