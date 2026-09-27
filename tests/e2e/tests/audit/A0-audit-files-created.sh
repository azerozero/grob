#!/usr/bin/env bash
# F-AUDIT-01: the journal and its signing key exist where [security].audit_dir points.
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
[ -s "$AUDIT_DIR/current.jsonl" ] || { echo "FAIL: $AUDIT_DIR/current.jsonl missing or empty"; exit 1; }
[ -s "$AUDIT_DIR/audit_key.pem" ] || { echo "FAIL: $AUDIT_DIR/audit_key.pem missing"; exit 1; }
echo "OK: journal and signing key present"
