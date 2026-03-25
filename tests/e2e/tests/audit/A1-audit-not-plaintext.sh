#!/usr/bin/env bash
# A1: Audit files must be encrypted (not plaintext JSON)
AUDIT_DIR="${1:?}"
for f in "$AUDIT_DIR"/*; do
  if file "$f" | grep -qE "JSON|ASCII text|UTF-8 text"; then
    echo "FAIL: $f appears to be plaintext"
    exit 1
  fi
done
echo "OK: all audit files are binary (encrypted)"
