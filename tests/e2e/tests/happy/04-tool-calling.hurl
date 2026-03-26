# Verifies that tool-calling requests are forwarded correctly.
# The mock backend returns a generic Anthropic-format response with a
# content array (it does not actually invoke tools).
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-tool-calling.json;
HTTP 200
[Asserts]
jsonpath "$.content" exists
jsonpath "$.content[0].text" exists
header "x-ai-provider" exists
