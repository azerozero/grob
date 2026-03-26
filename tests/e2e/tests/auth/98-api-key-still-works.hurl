# In JWT auth mode, x-api-key without a valid JWT is rejected
# The server api_key is for admin endpoints, not for Bearer auth
POST http://{{host}}/v1/chat/completions
x-api-key: grob-siege-master-key
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
