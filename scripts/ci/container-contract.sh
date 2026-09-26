#!/usr/bin/env bash
# Verify the actual image defaults, without overriding USER or CMD.
set -euo pipefail

runtime=${CONTAINER_RUNTIME:-docker}
image=${1:?usage: container-contract.sh IMAGE [--metadata-only]}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

"$runtime" image inspect "$image" --format '{{json .Config}}' | jq -e '
  .User == "65534:65534" and
  .Entrypoint == ["/grob"] and
  .Cmd == ["run", "--json-logs", "--host", "0.0.0.0", "--port", "8080"] and
  (.ExposedPorts | has("8080/tcp")) and
  (.Env | index("GROB_HOME=/var/lib/grob") != null)
' >/dev/null
if [[ ${2:-} == --metadata-only ]]; then
  exit 0
fi

container=
volume=$("$runtime" volume create)
cleanup() {
  if [[ -n "$container" ]]; then "$runtime" rm -f "$container" >/dev/null 2>&1 || true; fi
  "$runtime" volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The fixture deliberately uses 13456: image CMD must override it to 8080.
container=$("$runtime" run -d \
  -v "$root/tests/fixtures/container-smoke.toml:/etc/grob/config.toml:ro" \
  -v "$volume:/var/lib/grob" \
  -e GROB_CONFIG=/etc/grob/config.toml \
  -p 127.0.0.1::8080 "$image")
port=$("$runtime" port "$container" 8080/tcp | head -n 1)
health() {
  for ((attempt=0; attempt<30; attempt++)); do
    if curl -fsS "http://$port/health" >/dev/null; then return 0; fi
    sleep 1
  done
  "$runtime" logs "$container" >&2
  return 1
}
health
"$runtime" restart "$container" >/dev/null
health
echo "Container defaults, writable state and restart verified: $image"
