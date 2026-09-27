#!/usr/bin/env bash
# F-AUDIT-09: DLP classification is recorded per entry: NC (clean), C2
# (secret canary) and C1 (PII) after one request of each kind.
set -euo pipefail
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
cd "$(dirname "$0")/../.."
HOST="${HOST:-127.0.0.1:13456}"
JWT=$(cat auth/tokens/jwt-default.txt)
for body in '2+2' 'itk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' 'card 4111111111111111'; do
  curl -sf "http://$HOST/v1/chat/completions" -X POST \
    -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
    -d "{\"model\":\"default\",\"max_tokens\":10,\"messages\":[{\"role\":\"user\",\"content\":\"$body\"}]}" >/dev/null
done
sleep 1
levels=$(tail -n 50 "$AUDIT_DIR/current.jsonl" | python3 -c '
import json, sys
print(" ".join(sorted({json.loads(l)["classification"] for l in sys.stdin if l.strip()})))
')
for want in C1 C2 NC; do
  case " $levels " in *" $want "*) ;; *) echo "FAIL: classification $want not recorded (have: $levels)"; exit 1 ;; esac
done
echo "OK: classification levels recorded: $levels"
