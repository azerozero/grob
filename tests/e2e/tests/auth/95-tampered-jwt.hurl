POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_tampered}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
jsonpath "$.error.message" contains "JWT validation failed"
