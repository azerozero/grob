POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_wrong_issuer}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 401
