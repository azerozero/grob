# State: OPEN → requests fail-fast without reaching provider
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP [503]
[Asserts]
duration < 500
