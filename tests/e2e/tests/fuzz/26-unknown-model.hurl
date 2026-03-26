# Requests a model name that does not exist in the provider registry.
# The server must reject the request with a clear error rather than
# attempting to route it to a non-existent provider.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"nonexistent-model-xyz","messages":[{"role":"user","content":"hi"}],"max_tokens":10}
HTTP 400
[Asserts]
jsonpath "$.error.message" exists
