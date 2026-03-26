#!/usr/bin/env bash
# A9: Verify audit log hash chain integrity.
# Each entry's previous_hash must match the SHA-256 of the prior entry,
# forming a tamper-evident chain. The first entry may have a null or
# empty previous_hash.
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
RSSI_KEY="crypto/rssi.key"
cd "$(dirname "$0")/../.."

# Decrypt all entries and sort by event_id or filename order.
entries=()
for f in $(ls "$AUDIT_DIR"/* | sort); do
  decrypted=$(age -d -i "$RSSI_KEY" "$f" 2>/dev/null) || { echo "FAIL: cannot decrypt $f"; exit 1; }
  entries+=("$decrypted")
done

count=${#entries[@]}
[ "$count" -ge 2 ] || { echo "SKIP: need at least 2 entries for chain check (got $count)"; exit 0; }

prev_hash=""
for i in $(seq 0 $((count - 1))); do
  entry="${entries[$i]}"
  entry_prev_hash=$(echo "$entry" | jq -r '.previous_hash // empty' 2>/dev/null)

  if [ "$i" -eq 0 ]; then
    # First entry: previous_hash should be empty/null or a known seed.
    prev_hash=$(echo -n "$entry" | sha256sum | awk '{print $1}')
    continue
  fi

  # Subsequent entries: previous_hash must match hash of prior entry.
  if [ -z "$entry_prev_hash" ]; then
    echo "FAIL: entry $i has no previous_hash field"
    exit 1
  fi

  if [ "$entry_prev_hash" != "$prev_hash" ]; then
    echo "FAIL: entry $i previous_hash mismatch (expected $prev_hash, got $entry_prev_hash)"
    exit 1
  fi

  prev_hash=$(echo -n "$entry" | sha256sum | awk '{print $1}')
done

echo "OK: hash chain integrity verified across $count entries"
