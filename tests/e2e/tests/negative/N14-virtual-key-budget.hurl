# Virtual key with grob_ prefix rejected in JWT auth mode.
# Virtual keys only work when auth mode is "api_key". When the server
# uses JWT validation, any grob_xxxx bearer token is not a valid JWT
# and must return 401.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer grob_testkey00000000000000000000
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" exists
