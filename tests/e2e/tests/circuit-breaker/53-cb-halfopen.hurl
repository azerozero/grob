# State transition: OPEN → HalfOpen after 30s timeout
# Probe request is allowed through
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP [200, 503]
