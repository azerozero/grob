# JWT signed with unknown key (not in JWKS) → 401
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_self_signed}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
jsonpath "$.error.message" contains "JWT validation failed"
body not contains "sk-"
body not contains "api_key"
