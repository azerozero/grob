#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

PRESET="${1:?usage: $0 <preset>}"
HOST="127.0.0.1:13456"
JWT=$(cat auth/tokens/jwt-default.txt)

echo "Running live tests for preset: $PRESET"

case "$PRESET" in
  gdpr)      hurl --test --variable host="$HOST" --variable jwt_default="$JWT" tests/live/presets/62-gdpr-eu-only.hurl ;;
  eu-ai-act) hurl --test --variable host="$HOST" --variable jwt_default="$JWT" tests/live/presets/63-eu-ai-act-headers.hurl ;;
  perf)      hurl --test --variable host="$HOST" --variable jwt_default="$JWT" tests/live/presets/60-perf-routing.hurl ;;
  cheap)     hurl --test --variable host="$HOST" --variable jwt_default="$JWT" tests/live/presets/61-cheap-routing.hurl ;;
  local)     hurl --test --variable host="$HOST" --variable jwt_default="$JWT" tests/live/presets/64-local-ollama.hurl ;;
  oauth)     hurl --test --variable host="$HOST" tests/live/presets/65-oauth-anthropic.hurl ;;
  *)         echo "Unknown preset: $PRESET"; exit 1 ;;
esac
