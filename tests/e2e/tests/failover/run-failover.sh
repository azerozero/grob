#!/usr/bin/env bash
# run-failover.sh — Orchestrates Toxiproxy state for failover tests.
#
# Scenarios:
#   1. Primary down        → failover to secondary (200)
#   2. Primary rate-limited → failover to secondary (200)
#   3. ALL proxies down    → no backend reachable (502)
#   4. Primary has 5s lat  → timeout + failover (200, <10s)
#   5. Mid-stream failure  → partial stream cut (skipped: hard to assert)
#
# Usage: bash run-failover.sh
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

toxi_add_latency() {
    local proxy="$1"
    local latency_ms="$2"
    curl -sf -X POST \
        "${TOXIPROXY_API}/proxies/${proxy}/toxics" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"slow-latency\",\"type\":\"latency\",\"attributes\":{\"latency\":${latency_ms}}}" >/dev/null
}

toxi_remove_toxic() {
    local proxy="$1"
    local toxic_name="$2"
    curl -sf -X DELETE \
        "${TOXIPROXY_API}/proxies/${proxy}/toxics/${toxic_name}" >/dev/null 2>&1 || true
}

toxi_reset() {
    curl -sf -X POST "${TOXIPROXY_API}/reset" >/dev/null 2>&1 || true
    # Re-enable all proxies after reset (reset removes toxics but does not
    # re-enable disabled proxies).
    for p in anthropic-mock openai-mock gemini-mock; do
        toxi_enable "$p" 2>/dev/null || true
    done
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

# Ensure clean state on entry and exit.
trap 'toxi_reset' EXIT
toxi_reset

# ---------------------------------------------------------------------------
# Scenario 1: Primary provider down → fallback to secondary (200)
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 1: Primary provider down ==="
toxi_disable "anthropic-mock"

run_hurl "10-primary-down (anthropic disabled, expect 200 via fallback)" \
    "${SCRIPT_DIR}/10-primary-down.hurl"

toxi_enable "anthropic-mock"

# ---------------------------------------------------------------------------
# Scenario 2: Primary returns connection failure (simulates rate-limit /
# unavailability) → fallback to secondary (200)
#
# Toxiproxy cannot inject HTTP 429 at the TCP level, so we simulate provider
# unavailability by disabling the proxy.  Grob treats connection refusal as a
# retryable failure and falls over to the next mapping.
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 2: Primary unavailable (rate-limit proxy) ==="
toxi_disable "anthropic-mock"

run_hurl "11-ratelimit-429 (anthropic disabled, expect 200 via fallback)" \
    "${SCRIPT_DIR}/11-ratelimit-429.hurl"

toxi_enable "anthropic-mock"

# ---------------------------------------------------------------------------
# Scenario 3: ALL providers down → 502 Bad Gateway
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 3: All providers down ==="
toxi_disable "anthropic-mock"
toxi_disable "openai-mock"
toxi_disable "gemini-mock"

run_hurl "12-cascade-all-down (all disabled, expect 502)" \
    "${SCRIPT_DIR}/12-cascade-all-down.hurl"

toxi_enable "anthropic-mock"
toxi_enable "openai-mock"
toxi_enable "gemini-mock"

# ---------------------------------------------------------------------------
# Scenario 4: Primary has 5000ms latency → timeout + fallback (200, <10s)
#
# Grob's api_timeout_ms = 5000, so a 5000ms latency on the primary should
# cause a timeout.  Grob should fall over to the secondary which has no
# latency, returning 200 well within the 10s assertion window.
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 4: Primary slow (5s latency) ==="
toxi_add_latency "anthropic-mock" 5000

run_hurl "13-timeout-slow (5s latency on primary, expect 200 <10s)" \
    "${SCRIPT_DIR}/13-timeout-slow.hurl"

toxi_remove_toxic "anthropic-mock" "slow-latency"

# ---------------------------------------------------------------------------
# Scenario 5: Mid-stream failure (limit_data toxic on streaming request)
#
# Skipped: Toxiproxy limit_data truncates after N bytes, but asserting on
# partial SSE output is fragile.  Leaving the hurl file for manual use.
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 5: Mid-stream failure (SKIPPED — fragile assertion) ==="

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================="
echo "Failover results: ${PASS} passed, ${FAIL} failed (of ${TOTAL})"
echo "======================================="

if (( FAIL > 0 )); then
    exit 1
fi
