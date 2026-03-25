# State transition: 4 consecutive failures → circuit stays CLOSED
# Pre-condition: anthropic-mock returns 500 (set by run-cb-tests.sh)
# After 4 failures, Grob still attempts the provider (circuit is still CLOSED)
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP [200, 502]
# Circuit is NOT open yet — request reaches provider
