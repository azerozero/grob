# Pairwise: Auth=jwt_tampered, Provider=up, DLP=block, Policy=none, Format=openai, Payload=secrets
# Tampered JWT must be rejected before any processing.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_tampered}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-aws-key.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
jsonpath "$.error.message" contains "JWT validation failed"
