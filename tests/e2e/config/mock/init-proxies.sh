#!/usr/bin/env bash
set -euo pipefail

# Creates three Toxiproxy proxies that forward incoming connections on the
# provider mock ports to VidaiMock on port 8100.
#
# Proxy layout:
#   anthropic-mock  0.0.0.0:9001 → VidaiMock:8100
#   openai-mock     0.0.0.0:9002 → VidaiMock:8100
#   gemini-mock     0.0.0.0:9003 → VidaiMock:8100
#
# All containers share the pod network namespace, so 127.0.0.1 resolves to
# VidaiMock running in the same pod.

TOXIPROXY_API="${TOXIPROXY_API:-http://127.0.0.1:8474}"
# VidaiMock serves all LLM provider formats on a single port.
VIDAIMOCK_UPSTREAM="127.0.0.1:8100"
WAIT_TIMEOUT=30
WAIT_INTERVAL=2

# ---------------------------------------------------------------------------
# Wait for Toxiproxy API to be reachable
# ---------------------------------------------------------------------------
echo "→ Waiting for Toxiproxy API at ${TOXIPROXY_API}…"
deadline=$(( $(date +%s) + WAIT_TIMEOUT ))

while true; do
    if curl -sf "${TOXIPROXY_API}/version" >/dev/null 2>&1; then
        echo "→ Toxiproxy is ready"
        break
    fi

    now=$(date +%s)
    if (( now >= deadline )); then
        echo "ERROR: Toxiproxy did not become ready within ${WAIT_TIMEOUT}s." >&2
        exit 1
    fi

    sleep "${WAIT_INTERVAL}"
done

# ---------------------------------------------------------------------------
# Helper: create or update a proxy
# ---------------------------------------------------------------------------
create_proxy() {
    local name="$1"
    local listen="$2"
    local upstream="$3"

    # Check if proxy already exists
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        "${TOXIPROXY_API}/proxies/${name}" 2>/dev/null || echo "000")

    if [[ "${status}" == "200" ]]; then
        echo "  → proxy '${name}' already exists, skipping"
        return 0
    fi

    echo "  → creating proxy '${name}': ${listen} → ${upstream}"
    curl -sf -X POST "${TOXIPROXY_API}/proxies" \
        -H "Content-Type: application/json" \
        -d "{
              \"name\":     \"${name}\",
              \"listen\":   \"${listen}\",
              \"upstream\": \"${upstream}\",
              \"enabled\":  true
            }" \
        >/dev/null
}

# ---------------------------------------------------------------------------
# Create the three provider proxies
# ---------------------------------------------------------------------------
echo "→ Creating Toxiproxy proxies…"

create_proxy "anthropic-mock" "0.0.0.0:9001" "${VIDAIMOCK_UPSTREAM}"
create_proxy "openai-mock"    "0.0.0.0:9002" "${VIDAIMOCK_UPSTREAM}"
create_proxy "gemini-mock"    "0.0.0.0:9003" "${VIDAIMOCK_UPSTREAM}"

echo "✓ Toxiproxy proxies ready"
echo "  anthropic-mock → ${TOXIPROXY_API}/proxies/anthropic-mock"
echo "  openai-mock    → ${TOXIPROXY_API}/proxies/openai-mock"
echo "  gemini-mock    → ${TOXIPROXY_API}/proxies/gemini-mock"
