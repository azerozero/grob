# Verifies EU AI Act Article 12 record-keeping.
# Sends a chat completion request and asserts the response includes a
# usage object with token counts for regulatory audit trails.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.usage" exists
