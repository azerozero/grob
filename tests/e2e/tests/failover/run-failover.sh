#!/usr/bin/env bash
# run-failover.sh — Orchestrates Toxiproxy state for failover tests.
#
# Each step:
#   1. Disables anthropic-mock → runs 10-primary-down.hurl (expects 200 via fallback)
#   2. Re-enables anthropic-mock
#   3. Adds 5 000 ms latency on anthropic-mock → runs 13-timeout-slow.hurl
#   4. Removes all toxics → clean state
#
# Dependencies: hurl, curl (for Toxiproxy API)
# Usage: bash run-failover.sh [--variable host=127.0.0.1:13456] [--variable jwt_default=<token>]
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TOXIPROXY_API="${TOXIPROXY_API:-127.0.0.1:8474}"
HOST="${HOST:-127.0.0.1:13456}"
JWT="${JWT:-$(cat "$(dirname "$0")/../../auth/tokens/jwt-default.txt" 2>/dev/null || echo "")}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HURL_OPTS="--test --color --variable host=${HOST} --variable jwt_default=${JWT}"

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
toxi_disable() {
    local proxy="$1"
    echo "→ Disabling Toxiproxy proxy: ${proxy}"
    curl -sf -X POST \
        "http://${TOXIPROXY_API}/proxies/${proxy}" \
        -H "Content-Type: application/json" \
        -d '{"enabled": false}' >/dev/null
}

toxi_enable() {
    local proxy="$1"
    echo "→ Re-enabling Toxiproxy proxy: ${proxy}"
    curl -sf -X POST \
        "http://${TOXIPROXY_API}/proxies/${proxy}" \
        -H "Content-Type: application/json" \
        -d '{"enabled": true}' >/dev/null
}

toxi_add_latency() {
    local proxy="$1"
    local latency_ms="$2"
    echo "→ Adding ${latency_ms}ms latency toxic to ${proxy}"
    curl -sf -X POST \
        "http://${TOXIPROXY_API}/proxies/${proxy}/toxics" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"slow-latency\",\"type\":\"latency\",\"attributes\":{\"latency\":${latency_ms}}}" >/dev/null
}

toxi_delete_toxic() {
    local proxy="$1"
    local toxic_name="$2"
    echo "→ Removing toxic '${toxic_name}' from ${proxy}"
    curl -sf -X DELETE \
        "http://${TOXIPROXY_API}/proxies/${proxy}/toxics/${toxic_name}" >/dev/null || true
}

run_hurl() {
    local label="$1"
    local file="$2"
    echo ""
    echo "=== ${label} ==="
    if hurl ${HURL_OPTS} "${file}"; then
        echo "PASS: ${label}"
        PASS=$((PASS + 1))
    else
        echo "FAIL: ${label}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Primary provider down → expect fallback (200)
# ---------------------------------------------------------------------------
toxi_disable "anthropic-mock"

run_hurl "10-primary-down (fallback to secondary)" \
    "${SCRIPT_DIR}/10-primary-down.hurl"

# ---------------------------------------------------------------------------
# Step 2: Restore anthropic-mock
# ---------------------------------------------------------------------------
toxi_enable "anthropic-mock"

# ---------------------------------------------------------------------------
# Step 3: Latency toxic → timeout + fallback or 504
# ---------------------------------------------------------------------------
toxi_add_latency "anthropic-mock" 5000

run_hurl "13-timeout-slow (5s latency, expect 200 or 504 within 10s)" \
    "${SCRIPT_DIR}/13-timeout-slow.hurl"

# ---------------------------------------------------------------------------
# Step 4: Clean up all toxics
# ---------------------------------------------------------------------------
toxi_delete_toxic "anthropic-mock" "slow-latency"
toxi_enable "anthropic-mock"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================="
echo "Failover test results: ${PASS} passed, ${FAIL} failed"
echo "======================================="

if (( FAIL > 0 )); then
    exit 1
fi
