# State: OPEN → requests fail-fast without reaching provider
# Grob returns 502 (all providers CB-rejected).
# This file is invoked by run-cb.sh which handles Toxiproxy state.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 502
[Asserts]
duration < 500
