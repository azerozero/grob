# Verifies the Anthropic-native Messages API endpoint (/v1/messages).
# The response must follow the Anthropic schema: top-level "content" array.
POST http://{{host}}/v1/messages
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-anthropic-native.json;
HTTP 200
[Asserts]
jsonpath "$.content" exists
