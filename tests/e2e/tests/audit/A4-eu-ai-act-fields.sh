#!/usr/bin/env bash
# F-AUDIT-06/07/08: RESPONSE entries record model_name, token counts and the
# JWT tenant (EU AI Act Art. 12 traceability). The runner sends its requests
# with jwt-hospital-eu, whose tenant claim is hospital-cardiology-fr.
AUDIT_DIR="${1:?usage: $0 <audit_dir>}"
tail -n 200 "$AUDIT_DIR/current.jsonl" | python3 -c '
import json, sys
seen = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    e = json.loads(line)
    if e.get("action") != "RESPONSE":
        continue
    seen += 1
    eid = e["event_id"]
    for field in ("model_name", "input_tokens", "output_tokens"):
        if e.get(field) is None:
            sys.exit("FAIL: RESPONSE %s lacks %s" % (eid, field))
    if not e.get("tenant_id"):
        sys.exit("FAIL: RESPONSE %s has no tenant_id" % eid)
    if seen >= 3:
        break
if seen == 0:
    sys.exit("FAIL: no RESPONSE entry in the last 200 lines")
print("OK: %d RESPONSE entries carry model, tokens and tenant" % seen)
'
