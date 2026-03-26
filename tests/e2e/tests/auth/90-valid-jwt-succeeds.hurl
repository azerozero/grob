POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
header "x-ai-provider" exists
header "x-ai-model" exists
header "x-ai-generated" == "true"
