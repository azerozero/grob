# Verifies that tool-calling requests are forwarded correctly.
# The model should respond with a tool_calls entry or a choices array;
# either way the top-level choices key must be present.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-tool-calling.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
