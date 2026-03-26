# State transition: OPEN → HALF-OPEN after 30s timeout
# Probe request is allowed through.  Proxies must be re-enabled before
# this file runs (handled by run-cb.sh).
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
