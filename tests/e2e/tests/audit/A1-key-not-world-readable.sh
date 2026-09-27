#!/usr/bin/env bash
# F-AUDIT-02: the signing key is private to the grob user (mode 0600).
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
mode=$(stat -c '%a' "$AUDIT_DIR/audit_key.pem")
[ "$mode" = "600" ] || { echo "FAIL: audit_key.pem mode is $mode, expected 600"; exit 1; }
echo "OK: signing key is 0600"
