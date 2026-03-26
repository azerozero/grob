# Verifies the Anthropic-compatible token counting endpoint.
# The server must accept the request and return a 200 with a token count.
POST http://{{host}}/v1/messages/count_tokens
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","messages":[{"role":"user","content":"Hello world"}]}
HTTP 200
