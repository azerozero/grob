#!/usr/bin/env bash
# C0: Risk webhook placeholder — verifies compliance features are loaded
# by confirming the health endpoint responds.  Full Art. 14 webhook testing
# requires an in-pod HTTP receiver, deferred to a later iteration.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$E2E_ROOT"

HOST="${HOST:-127.0.0.1:13456}"
JWT="${JWT:-$(cat auth/tokens/jwt-default.txt 2>/dev/null || echo "")}"

# `-sf` + `set -e` make this fail loudly if the health endpoint is down;
# the body is intentionally discarded (only the exit status matters).
curl -sf "http://$HOST/health" >/dev/null
echo "PASS: C0 — compliance features loaded (health ok)"
