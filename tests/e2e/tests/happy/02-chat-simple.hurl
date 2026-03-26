# Verifies the basic chat completion endpoint:
# - returns a 200 with a populated content array (Anthropic format)
# - Grob injects routing headers (x-ai-provider, x-ai-model, x-ai-generated)
# - response arrives within 3 seconds against the mock backend
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.content" exists
jsonpath "$.content[0].text" exists
header "x-ai-provider" exists
header "x-ai-model" exists
header "x-ai-generated" == "true"
duration < 3000
