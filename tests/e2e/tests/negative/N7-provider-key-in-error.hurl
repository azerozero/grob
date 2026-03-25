# Force a provider error — response must not leak provider API keys
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
`{"model":"force-error-model","messages":[{"role":"user","content":"test"}],"max_tokens":10}`
HTTP [400, 404, 500, 502]
[Asserts]
body not contains "sk-mock-anthropic"
body not contains "sk-mock-openai"
body not contains "mock-gemini-key"
body not contains "sk-ant"
