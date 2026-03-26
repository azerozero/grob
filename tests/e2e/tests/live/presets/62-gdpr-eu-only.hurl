# Live: gdpr preset — only EU providers used
# Requires: GROB_CONFIG=tests/e2e/config/presets/grob-gdpr.toml
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}],"max_tokens":10}`
HTTP 200
[Asserts]
jsonpath "$.content" exists
header "x-ai-provider" exists
