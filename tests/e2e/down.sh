#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POD_MANIFEST="${SCRIPT_DIR}/kube/e2e-pod.yml"

echo "→ Stopping e2e pod…"
podman play kube --down "${POD_MANIFEST}"

echo ""
echo "✓ e2e environment stopped"
