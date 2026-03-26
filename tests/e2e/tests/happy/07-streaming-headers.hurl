# Verifies that a streaming chat completion returns the correct SSE
# content-type and Grob transparency headers (provider, model).
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","messages":[{"role":"user","content":"count"}],"max_tokens":50,"stream":true}
HTTP 200
[Asserts]
header "content-type" contains "text/event-stream"
header "x-ai-provider" exists
header "x-ai-model" exists
