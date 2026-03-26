# Verifies DLP scanning works on streaming responses.
# Sends a prompt containing a well-known fake AWS Access Key ID with
# streaming enabled.  The DLP pipeline must still intercept and redact
# the secret even though the response is chunked as SSE.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","messages":[{"role":"user","content":"My key AKIAIOSFODNN7EXAMPLE"}],"max_tokens":50,"stream":true}
HTTP 200
[Asserts]
header "content-type" contains "text/event-stream"
body not contains "AKIAIOSFODNN7EXAMPLE"
