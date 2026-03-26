# Verifies that tool-calling requests are forwarded correctly.
# The mock backend returns an OpenAI-format response with a choices array
# (it does not actually invoke tools).
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-tool-calling.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
jsonpath "$.choices[0].message.content" exists
header "x-ai-provider" exists
