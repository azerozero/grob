#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POD_MANIFEST="${SCRIPT_DIR}/kube/e2e-pod.yml"
GROB_HOST="127.0.0.1"
GROB_PORT="13456"
HEALTH_TIMEOUT=90
HEALTH_INTERVAL=2

# ---------------------------------------------------------------------------
# 1. Check podman
# ---------------------------------------------------------------------------
if ! command -v podman &>/dev/null; then
    echo "ERROR: podman is not installed or not in PATH." >&2
    exit 1
fi
echo "→ podman $(podman --version)"

# Ensure podman machine is running (macOS)
if [[ "$(uname -s)" == "Darwin" ]]; then
    if ! podman machine inspect podman-machine-default 2>/dev/null | grep -q '"State": "running"'; then
        echo "→ Starting podman machine…"
        podman machine start 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# 2. Build images if missing
# ---------------------------------------------------------------------------
echo ""
echo "=== Checking container images ==="

if ! podman image exists localhost/grob:e2e 2>/dev/null; then
    echo "→ Pulling grob image…"
    podman pull ghcr.io/azerozero/grob:0.29.3
    podman tag ghcr.io/azerozero/grob:0.29.3 localhost/grob:e2e
else
    echo "→ localhost/grob:e2e ✓"
fi

if ! podman image exists localhost/vidaimock:e2e 2>/dev/null; then
    echo "→ Building localhost/vidaimock:e2e…"
    podman build -t localhost/vidaimock:e2e "${SCRIPT_DIR}/images/vidaimock"
else
    echo "→ localhost/vidaimock:e2e ✓"
fi

if ! podman image exists localhost/e2e-runner:latest 2>/dev/null; then
    echo "→ Building localhost/e2e-runner:latest…"
    podman build -t localhost/e2e-runner:latest "${SCRIPT_DIR}/images/runner"
else
    echo "→ localhost/e2e-runner:latest ✓"
fi

# ---------------------------------------------------------------------------
# 3. Ensure host dirs exist
# ---------------------------------------------------------------------------
mkdir -p /tmp/grob-audit

# ---------------------------------------------------------------------------
# 4. Launch the pod (from SCRIPT_DIR so relative hostPath volumes resolve)
# ---------------------------------------------------------------------------
echo ""
echo "→ Starting pod from ${POD_MANIFEST}"
# Resolve ${E2E_DIR} in the manifest template to absolute path
export E2E_DIR="${SCRIPT_DIR}"
RESOLVED_MANIFEST="$(mktemp)"
envsubst '${E2E_DIR}' < "${POD_MANIFEST}" > "${RESOLVED_MANIFEST}"
cd "${SCRIPT_DIR}"
podman play kube "${RESOLVED_MANIFEST}"
rm -f "${RESOLVED_MANIFEST}"

# ---------------------------------------------------------------------------
# 5. Wait for Grob /health
# ---------------------------------------------------------------------------
echo ""
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

echo ""
echo "✓ e2e environment ready"
echo "  Grob:          http://${GROB_HOST}:${GROB_PORT}"
echo "  VidaiMock:     http://127.0.0.1:8100"
echo "  Toxiproxy API: http://127.0.0.1:8474"
echo "  mock-jwks:     http://127.0.0.1:8443"
