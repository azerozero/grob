#!/usr/bin/env bash
# F0: Fan-out fastest mode — config-swap adds a fan_out model, reloads, sends
# a request, verifies 200, then restores the original config.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$E2E_ROOT"

HOST="${HOST:-127.0.0.1:13456}"
JWT="${JWT:-$(cat auth/tokens/jwt-default.txt 2>/dev/null || echo "")}"
CONFIG="config/mock/grob-test.toml"
BACKUP="${CONFIG}.bak"

cp "$CONFIG" "$BACKUP"
trap 'cp "$BACKUP" "$CONFIG"; curl -sf -X POST "http://$HOST/api/config/reload" -H "Authorization: Bearer $JWT" >/dev/null 2>&1; rm -f "$BACKUP"' EXIT

cat >> "$CONFIG" << 'TOML'

[[models]]
name = "fanout-test"
strategy = "fan_out"

[models.fan_out]
mode = "fastest"

[[models.mappings]]
provider = "anthropic-mock"
actual_model = "claude-sonnet-4-6"
priority = 1

[[models.mappings]]
provider = "openai-mock"
actual_model = "gpt-4o"
priority = 2
TOML

# Reload config.
status=$(curl -sf -o /dev/null -w '%{http_code}' -X POST "http://$HOST/api/config/reload" \
  -H "Authorization: Bearer $JWT")
[ "$status" = "200" ] || { echo "FAIL: F0 — reload returned $status"; exit 1; }

# Send request to fan-out model.
status=$(curl -sf -o /dev/null -w '%{http_code}' -X POST "http://$HOST/v1/chat/completions" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"model":"fanout-test","messages":[{"role":"user","content":"hello"}],"max_tokens":10}')
[ "$status" = "200" ] || { echo "FAIL: F0 — fan-out request returned $status"; exit 1; }

echo "PASS: F0 — fan-out fastest mode returned 200"
