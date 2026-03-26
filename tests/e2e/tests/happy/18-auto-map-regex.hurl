# Verifies auto_map_regex routes unlisted models to "default".
# The config has auto_map_regex = "^claude-", so requesting model
# "claude-sonnet-4-6" (not in [[models]]) should auto-map to "default"
# and succeed against the mock backend.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"max_tokens":10}
HTTP 200
[Asserts]
header "x-ai-provider" exists
jsonpath "$.choices" exists
duration < 3000
