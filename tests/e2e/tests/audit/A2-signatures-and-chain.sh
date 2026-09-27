#!/usr/bin/env bash
# F-AUDIT-03/04: every entry in the tail window is ECDSA-signed and each
# signature covers the hash the next entry chains to.
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
cd "$(dirname "$0")" || exit 1
python3 verify_chain.py "$AUDIT_DIR" --window 200
