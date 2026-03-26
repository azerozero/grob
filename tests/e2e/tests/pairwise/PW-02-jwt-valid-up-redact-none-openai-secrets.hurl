# Pairwise: Auth=jwt_valid, Provider=up, DLP=redact, Policy=none, Format=openai, Payload=secrets
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-aws-key.json;
HTTP 200
[Asserts]
body not contains "AKIAIOSFODNN7EXAMPLE"
header "x-ai-provider" exists
