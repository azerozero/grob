# api_key auth works alongside JWT auth
POST http://{{host}}/v1/chat/completions
x-api-key: grob-siege-master-key
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
