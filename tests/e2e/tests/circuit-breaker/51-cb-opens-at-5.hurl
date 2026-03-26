# State transition: 5th consecutive failure → circuit OPENS
# After 5 failures per provider, CB opens on all providers.
# Grob returns 502 (all provider mappings failed / CB-rejected).
# This file is invoked by run-cb.sh which handles Toxiproxy state.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 502
[Asserts]
# Fast response (fail-fast, no network call)
duration < 500
