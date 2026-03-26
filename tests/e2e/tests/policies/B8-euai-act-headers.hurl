# Verifies EU AI Act Article 52 transparency headers.
# Every response must declare the AI provider, model, and generated flag
# so downstream consumers can fulfil disclosure obligations.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
header "x-ai-provider" exists
header "x-ai-model" exists
header "x-ai-generated" == "true"
