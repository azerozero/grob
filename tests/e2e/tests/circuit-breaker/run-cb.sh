#!/usr/bin/env bash
# run-cb.sh — Orchestrates Toxiproxy state for circuit-breaker lifecycle tests.
#
# CB defaults (hardcoded in grob):
#   failure_threshold:    5  (opens after 5 consecutive failures per provider)
#   success_threshold:    3  (closes after 3 successes in half-open)
#   timeout:             30s (half-open probe window)
#   half_open_max_calls:  3
#
# The "default" model maps to 3 providers (anthropic-mock p1, openai-mock p2,
# gemini-mock p3).  CB is per-provider, so to exhaust all providers we must
# open CB on all three.  Each request that fails on all 3 providers counts as
# one failure on each.
#
# Lifecycle:
#   Phase 1: Disable all proxies, send 4 requests → all return 502 (failover
#            exhausted), CB still CLOSED on each (4 < threshold of 5).
#   Phase 2: 5th request → CB opens on all providers → 502.
#   Phase 3: While CB open, send request → fast-fail 502 (<500ms).
#   Phase 4: Re-enable proxies, wait 31s for half-open timeout, send request
#            → half-open probe succeeds → 200.
#   Phase 5: Send 2 more successful requests to satisfy success_threshold=3
#            → CB fully closes → 200.
#   Phase 6: Disable proxies again, send request → failure in half-open →
#            CB re-opens → 502.
#
# Usage: bash run-cb.sh
#   Env: HOST, TOXIPROXY_API, JWT (or reads from auth/tokens/jwt-default.txt)
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TOXIPROXY_API="${TOXIPROXY_API:-http://127.0.0.1:8474}"
HOST="${HOST:-127.0.0.1:13456}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
JWT="${JWT:-$(cat "${E2E_ROOT}/auth/tokens/jwt-default.txt" 2>/dev/null || echo "")}"

HURL_OPTS="--test --color --variable host=${HOST} --variable jwt_default=${JWT}"

PASS=0
FAIL=0
TOTAL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
toxi_disable() {
    local proxy="$1"
    curl -sf -X POST \
        "${TOXIPROXY_API}/proxies/${proxy}" \
        -H "Content-Type: application/json" \
        -d '{"enabled": false}' >/dev/null
}

toxi_enable() {
    local proxy="$1"
    curl -sf -X POST \
        "${TOXIPROXY_API}/proxies/${proxy}" \
        -H "Content-Type: application/json" \
        -d '{"enabled": true}' >/dev/null
}

toxi_reset() {
    curl -sf -X POST "${TOXIPROXY_API}/reset" >/dev/null 2>&1 || true
    for p in anthropic-mock openai-mock gemini-mock; do
        toxi_enable "$p" 2>/dev/null || true
    done
}

disable_all() {
    toxi_disable "anthropic-mock"
    toxi_disable "openai-mock"
    toxi_disable "gemini-mock"
}

enable_all() {
    toxi_enable "anthropic-mock"
    toxi_enable "openai-mock"
    toxi_enable "gemini-mock"
}

run_hurl() {
    local label="$1"
    local file="$2"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "--- [${TOTAL}] ${label} ---"
    if hurl ${HURL_OPTS} "${file}"; then
        echo "PASS: ${label}"
        PASS=$((PASS + 1))
    else
        echo "FAIL: ${label}"
        FAIL=$((FAIL + 1))
    fi
}

# Send a request with curl and check the HTTP status code.
# Usage: send_expect <label> <expected_status>
send_expect() {
    local label="$1"
    local expected="$2"
    TOTAL=$((TOTAL + 1))
    echo "  → ${label}"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://${HOST}/v1/chat/completions" \
        -H "Authorization: Bearer ${JWT}" \
        -H "Content-Type: application/json" \
        -d '{"model":"default","messages":[{"role":"user","content":"ping"}],"max_tokens":10}' \
        2>/dev/null || echo "000")
    if [[ "${status}" == "${expected}" ]]; then
        echo "    PASS (HTTP ${status})"
        PASS=$((PASS + 1))
    else
        echo "    FAIL (expected HTTP ${expected}, got HTTP ${status})"
        FAIL=$((FAIL + 1))
    fi
}

# Send a request and check it completes within a time bound (milliseconds).
# Usage: send_expect_fast <label> <expected_status> <max_ms>
send_expect_fast() {
    local label="$1"
    local expected="$2"
    local max_ms="$3"
    TOTAL=$((TOTAL + 1))
    echo "  → ${label}"
    local output
    output=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" \
        -X POST "http://${HOST}/v1/chat/completions" \
        -H "Authorization: Bearer ${JWT}" \
        -H "Content-Type: application/json" \
        -d '{"model":"default","messages":[{"role":"user","content":"ping"}],"max_tokens":10}' \
        2>/dev/null || echo "000 0")
    local status duration_s
    status=$(echo "${output}" | awk '{print $1}')
    duration_s=$(echo "${output}" | awk '{print $2}')
    # Convert seconds (float) to milliseconds (integer).
    local duration_ms
    duration_ms=$(awk "BEGIN {printf \"%d\", ${duration_s} * 1000}")

    if [[ "${status}" == "${expected}" ]] && (( duration_ms <= max_ms )); then
        echo "    PASS (HTTP ${status}, ${duration_ms}ms <= ${max_ms}ms)"
        PASS=$((PASS + 1))
    elif [[ "${status}" != "${expected}" ]]; then
        echo "    FAIL (expected HTTP ${expected}, got HTTP ${status})"
        FAIL=$((FAIL + 1))
    else
        echo "    FAIL (HTTP ${status} OK, but ${duration_ms}ms > ${max_ms}ms)"
        FAIL=$((FAIL + 1))
    fi
}

# Ensure clean state on entry and exit.
trap 'toxi_reset' EXIT
toxi_reset

# ---------------------------------------------------------------------------
# Phase 1: Disable all proxies, send 4 requests.
# Each request fails on all 3 providers → 502 (all providers exhausted).
# After 4 rounds, each provider has 4 consecutive failures (< threshold 5),
# so CB is still CLOSED.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 1: 4 failures — CB stays CLOSED (all return 502 via failover exhaustion) ==="
disable_all

for i in 1 2 3 4; do
    send_expect "Request ${i}/4 (all providers down → 502)" "502"
done

# ---------------------------------------------------------------------------
# Phase 2: 5th request → 5th consecutive failure on each provider.
# CB opens on all three providers after this request.
# The request itself still returns 502 (providers failed before CB trips).
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 2: 5th failure — CB opens on all providers ==="
send_expect "Request 5 (triggers CB open → 502)" "502"

# ---------------------------------------------------------------------------
# Phase 3: CB is now OPEN on all providers.
# Next request should fail-fast without attempting any provider call.
# Grob returns 502 (all providers skipped by CB) in under 500ms.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 3: CB open — fast-fail ==="
send_expect_fast "Fast-fail while CB open (expect 502, <500ms)" "502" 500
send_expect_fast "Fast-fail again (expect 502, <500ms)" "502" 500

# ---------------------------------------------------------------------------
# Phase 4: Re-enable all proxies, wait for half-open timeout (30s).
# After 31s, CB transitions to HALF-OPEN and allows a probe request.
# With proxies re-enabled, the probe should succeed → 200.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 4: Wait 31s for half-open timeout ==="
enable_all
echo "  Waiting 31 seconds for CB half-open window..."
sleep 31

run_hurl "53-cb-halfopen (probe request → 200)" \
    "${SCRIPT_DIR}/53-cb-halfopen.hurl"

# ---------------------------------------------------------------------------
# Phase 5: Send 2 more successful requests to reach success_threshold (3).
# CB should transition from HALF-OPEN to CLOSED.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 5: 2 more successes — CB closes ==="
run_hurl "54-cb-recovers (success 2/3 + 3/3 → CB closed)" \
    "${SCRIPT_DIR}/54-cb-recovers.hurl"

send_expect "Extra success to confirm closed (200)" "200"

# ---------------------------------------------------------------------------
# Phase 6: Disable proxies again and send enough failures to re-open CB.
# This tests the HALF-OPEN → OPEN transition on failure during probing.
#
# We first need to accumulate 5 failures again to re-open the CB.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 6: Re-open CB (relapse) ==="
disable_all

for i in 1 2 3 4 5; do
    send_expect "Relapse failure ${i}/5 (all down → 502)" "502"
done

# CB should now be open again — fast-fail.
send_expect_fast "Relapse fast-fail (CB re-opened → 502, <500ms)" "502" 500

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================="
echo "Circuit-breaker results: ${PASS} passed, ${FAIL} failed (of ${TOTAL})"
echo "======================================="

if (( FAIL > 0 )); then
    exit 1
fi
