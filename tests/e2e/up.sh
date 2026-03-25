#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POD_MANIFEST="${SCRIPT_DIR}/kube/e2e-pod.yml"
AUTH_KEY="${SCRIPT_DIR}/auth/keys/test-signing.key"
GROB_HOST="127.0.0.1"
GROB_PORT="13456"
HEALTH_TIMEOUT=60
HEALTH_INTERVAL=2

# ---------------------------------------------------------------------------
# 1. Check podman
# ---------------------------------------------------------------------------
if ! command -v podman &>/dev/null; then
    echo "ERROR: podman is not installed or not in PATH." >&2
    exit 1
fi

echo "→ podman $(podman --version)"

# ---------------------------------------------------------------------------
# 2. Generate auth keys if they do not exist
# ---------------------------------------------------------------------------
if [[ ! -f "${AUTH_KEY}" ]]; then
    echo "→ Auth keys not found — running auth/generate.sh"
    bash "${SCRIPT_DIR}/auth/generate.sh"
else
    echo "→ Auth keys already present, skipping generation"
fi

# ---------------------------------------------------------------------------
# 3. Ensure audit log directory exists on the host
# ---------------------------------------------------------------------------
mkdir -p /tmp/grob-audit

# ---------------------------------------------------------------------------
# 4. Launch the pod
# ---------------------------------------------------------------------------
echo "→ Starting pod from ${POD_MANIFEST}"
podman play kube "${POD_MANIFEST}"

# ---------------------------------------------------------------------------
# 5. Wait for Grob /health
# ---------------------------------------------------------------------------
echo "→ Waiting for Grob to become healthy (timeout: ${HEALTH_TIMEOUT}s)…"
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))

while true; do
    if curl -sf "http://${GROB_HOST}:${GROB_PORT}/health" >/dev/null 2>&1; then
        echo "→ Grob is healthy"
        break
    fi

    now=$(date +%s)
    if (( now >= deadline )); then
        echo "ERROR: Grob did not become healthy within ${HEALTH_TIMEOUT}s." >&2
        echo "Dumping pod logs:" >&2
        podman pod logs e2e-pod 2>&1 | tail -40 >&2
        exit 1
    fi

    sleep "${HEALTH_INTERVAL}"
done

# ---------------------------------------------------------------------------
# 6. Init Toxiproxy proxies
# ---------------------------------------------------------------------------
echo "→ Initialising Toxiproxy proxies…"
bash "${SCRIPT_DIR}/config/mock/init-proxies.sh"

echo ""
echo "✓ e2e environment ready"
echo "  Grob:          http://${GROB_HOST}:${GROB_PORT}"
echo "  Toxiproxy API: http://127.0.0.1:8474"
echo "  MockLLM:       http://127.0.0.1:8000"
echo "  mock-jwks:     http://127.0.0.1:8443"
