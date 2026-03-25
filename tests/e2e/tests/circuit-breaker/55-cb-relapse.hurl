# State transition: HalfOpen → OPEN again on 1 failure during probing
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP [503]
[Asserts]
duration < 500
