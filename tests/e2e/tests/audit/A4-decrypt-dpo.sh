#!/usr/bin/env bash
# A4: DPO key can decrypt and produce valid JSON
AUDIT_DIR="${1:?}"
DPO_KEY="crypto/dpo.key"
cd "$(dirname "$0")/../.."
for f in "$AUDIT_DIR"/*; do
  decrypted=$(age -d -i "$DPO_KEY" "$f" 2>/dev/null) || { echo "FAIL: cannot decrypt $f with DPO key"; exit 1; }
  echo "$decrypted" | jq . > /dev/null 2>&1 || { echo "FAIL: decrypted $f is not valid JSON"; exit 1; }
done
echo "OK: DPO can decrypt all entries to valid JSON"
