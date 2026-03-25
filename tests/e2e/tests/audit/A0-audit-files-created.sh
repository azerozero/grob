#!/usr/bin/env bash
# A0: Audit files must exist after requests
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
count=$(find "$AUDIT_DIR" -type f | wc -l)
[ "$count" -gt 0 ] || { echo "FAIL: no audit files in $AUDIT_DIR"; exit 1; }
echo "OK: $count audit file(s) found"
