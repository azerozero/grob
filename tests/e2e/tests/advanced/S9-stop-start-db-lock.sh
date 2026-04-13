#!/usr/bin/env bash
set -euo pipefail

# S9: Regression test for stop/start cycle.
# grob stop must wait until the process fully exits before returning.
# A subsequent grob start must succeed without storage lock errors.
#
# Bug: stop_service sent SIGTERM + 500ms grace but didn't verify death.
# Fix: stop_service now polls kill(0) for up to 5s, then SIGKILL.

cd "$(dirname "$0")/../.."
HOST="${HOST:-127.0.0.1:13456}"

echo "  S9: stop/start cycle (clean shutdown regression)"

# Skip if grob is not locally installed (pod mode)
if ! command -v grob &>/dev/null; then
    echo "  SKIP: S9 — grob not in PATH (pod mode)"
    exit 0
fi

# Start grob
grob start -d 2>/dev/null || true
sleep 2

if ! curl -sf "http://$HOST/health" >/dev/null 2>&1; then
    echo "  SKIP: S9 — grob failed to start (may need OAuth)"
    exit 0
fi

# Stop immediately
grob stop 2>/dev/null

# Verify process is actually dead (the fix)
sleep 1
if pgrep -f "grob start" >/dev/null 2>&1; then
    echo "  FAIL: S9 — grob process still running after stop"
    exit 1
fi

# Start again — this must succeed
grob start -d 2>/dev/null
sleep 3

if curl -sf "http://$HOST/health" >/dev/null 2>&1; then
    echo "  PASS: S9 — stop/start cycle clean"
    grob stop 2>/dev/null
else
    echo "  FAIL: S9 — grob failed to start after stop"
    grob stop 2>/dev/null
    exit 1
fi
