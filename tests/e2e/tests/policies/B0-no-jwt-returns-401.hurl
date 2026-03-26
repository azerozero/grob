# Decision table row 1: JWT=invalid → 401, policy not evaluated
POST http://{{host}}/v1/chat/completions
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
jsonpath "$.error.message" contains "Missing or invalid Authorization header"
