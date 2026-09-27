#!/usr/bin/env bash
# F-AUDIT-05: a modified signature is rejected by the same verifier.
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
cd "$(dirname "$0")" || exit 1
python3 verify_chain.py "$AUDIT_DIR" --window 20 --tamper
