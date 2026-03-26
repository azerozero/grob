# In JWT auth mode, a virtual key (grob_ prefix) must be rejected.
# Virtual keys only work when auth mode is "api_key". When the server
# uses JWT validation, any grob_xxxx bearer token is not a valid JWT
# and must return 401.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer grob_fake_virtual_key_12345678
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" exists
