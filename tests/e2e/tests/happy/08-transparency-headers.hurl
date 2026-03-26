# Verifies EU AI Act transparency headers (Article 12).
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
header "x-content-type-options" == "nosniff"
