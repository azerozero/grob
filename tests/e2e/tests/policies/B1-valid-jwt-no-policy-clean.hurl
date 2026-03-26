# Decision table row 2: JWT=valid, no policy match, DLP=disabled → 200
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
header "x-ai-provider" exists
