# First request — populates cache
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-temperature-zero.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists

# Second identical request — should hit cache and still be OpenAI format
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-temperature-zero.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
