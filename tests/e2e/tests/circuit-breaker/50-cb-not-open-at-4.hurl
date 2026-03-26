# State transition: 4 consecutive failures → circuit stays CLOSED
# Pre-condition: all proxies disabled via run-cb.sh (Toxiproxy orchestration).
# After 4 failures per provider, CB is still CLOSED (threshold is 5).
# All providers are down so grob returns 502 (all mappings exhausted).
# This file is invoked by run-cb.sh which handles Toxiproxy state.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 502
# Circuit is NOT open yet — providers are attempted but unreachable
