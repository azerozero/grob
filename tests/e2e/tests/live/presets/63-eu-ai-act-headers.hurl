# Live: EU AI Act preset — transparency headers required (Art. 50 + Art. 12)
# Requires: GROB_CONFIG=tests/e2e/config/presets/grob-eu-ai-act.toml
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}],"max_tokens":10}`
HTTP 200
[Asserts]
header "x-ai-provider" exists
header "x-ai-model" exists
header "x-ai-generated" exists
