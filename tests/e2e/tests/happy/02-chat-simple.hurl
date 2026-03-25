# Verifies the basic OpenAI-compatible chat completion endpoint:
# - returns a 200 with a populated choices array
# - Grob injects routing headers (x-ai-provider, x-ai-model)
# - response arrives within 3 seconds against the mock backend
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
jsonpath "$.choices[0].message.content" exists
header "x-ai-provider" exists
header "x-ai-model" exists
duration < 3000
