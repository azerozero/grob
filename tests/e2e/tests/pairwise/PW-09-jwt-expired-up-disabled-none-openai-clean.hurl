# Pairwise: Auth=jwt_expired, Provider=up, DLP=disabled, Policy=none, Format=openai, Payload=clean
# Expired JWT must be rejected before any processing.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_expired}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
jsonpath "$.error.message" contains "JWT validation failed"
