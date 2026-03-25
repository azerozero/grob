#!/usr/bin/env bash
# A5: Intruder key must NOT decrypt any audit entry
AUDIT_DIR="${1:?}"
INTRUDER_KEY="crypto/intruder.key"
cd "$(dirname "$0")/../.."
for f in "$AUDIT_DIR"/*; do
  if age -d -i "$INTRUDER_KEY" "$f" > /dev/null 2>&1; then
    echo "FAIL: intruder decrypted $f — this should not be possible"
    exit 1
  fi
done
echo "OK: intruder cannot decrypt any audit entry"
