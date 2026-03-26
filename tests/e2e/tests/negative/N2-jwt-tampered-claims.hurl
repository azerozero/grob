# Valid JWT structure, payload modified after signing → 401
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_tampered}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
jsonpath "$.error.message" contains "JWT validation failed"
# Error message must not reveal signing key or internal details
body not contains "secret"
body not contains "private"
