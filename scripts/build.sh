#!/usr/bin/env bash
# Build script for Grob with security modules
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

echo "Building Grob with full security stack..."

echo "Running security tests..."
cargo test --lib security:: 2>&1 | head -50

echo "Checking compilation..."
cargo check --release --features tls

echo "Build complete!"
