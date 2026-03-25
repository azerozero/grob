# State transition: 5th consecutive failure → circuit OPENS
# After 5 failures, circuit breaker should open
# Subsequent requests should fail-fast (no provider call)
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP [503]
[Asserts]
# Fast response (fail-fast, no network call)
duration < 500
