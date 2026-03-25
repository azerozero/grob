# Live: local ollama preset — no external provider calls, fully air-gapped
# Requires: Ollama running locally + GROB_CONFIG=tests/e2e/config/presets/grob-local.toml
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
`{"model":"llama3","messages":[{"role":"user","content":"Hello"}],"max_tokens":10}`
HTTP 200
[Asserts]
jsonpath "$.choices" exists
header "x-ai-provider" == "ollama"
