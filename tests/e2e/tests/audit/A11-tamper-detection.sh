#!/usr/bin/env bash
# A11: Modify an audit entry and verify chain integrity breaks.
# This is a negative test — tampering should be detectable.
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."

# Decrypt all entries into a temp JSONL file.
PLAINTEXT=$(mktemp)
for f in $(ls "$AUDIT_DIR"/* | sort); do
  age -d -i "$RSSI_KEY" "$f" 2>/dev/null >> "$PLAINTEXT" || { echo "FAIL: cannot decrypt $f"; exit 1; }
  echo >> "$PLAINTEXT"
done

LINES=$(grep -c . "$PLAINTEXT")
if [ "$LINES" -lt 2 ]; then
  rm -f "$PLAINTEXT"
  echo "SKIP: need at least 2 entries for tamper check (got $LINES)"
  exit 0
fi

# Tamper with the first entry by modifying the tenant field.
TAMPERED=$(mktemp)
sed '1s/default/TAMPERED/' "$PLAINTEXT" > "$TAMPERED"

# Verify chain breaks: previous_hash of entry N must NOT match hash of
# the tampered entry N-1.
if python3 -c "
import json, hashlib, sys
lines = [l for l in open('$TAMPERED').readlines() if l.strip()]
prev_hash = ''
for i, line in enumerate(lines):
    e = json.loads(line)
    if i == 0:
        prev_hash = hashlib.sha256(line.strip().encode()).hexdigest()
        continue
    entry_prev = e.get('previous_hash', '')
    if entry_prev != prev_hash:
        sys.exit(0)  # Chain broken = tamper detected = PASS
    prev_hash = hashlib.sha256(line.strip().encode()).hexdigest()
sys.exit(1)  # Chain not broken = tamper NOT detected = FAIL
" 2>/dev/null; then
  echo "OK: tampering detected (chain broken)"
else
  echo "FAIL: tampering NOT detected"
  rm -f "$PLAINTEXT" "$TAMPERED"
  exit 1
fi

rm -f "$PLAINTEXT" "$TAMPERED"
