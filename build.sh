#!/bin/bash
# Build script for Grob with security modules
set -e

echo "🔒 Building Grob with full security stack..."
cd /Users/clementliard/Workspace/grob

echo "Running security tests..."
cargo test --lib security:: 2>&1 | head -50

echo "Checking compilation..."
cargo check --release --features tls

echo "✅ Build complete!"
