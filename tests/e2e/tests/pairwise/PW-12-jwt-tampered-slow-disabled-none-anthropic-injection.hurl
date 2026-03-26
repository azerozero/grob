# Pairwise: Auth=jwt_tampered, Provider=slow, DLP=disabled, Policy=none, Format=anthropic, Payload=injection
# Tampered JWT rejected regardless of provider state or payload.
POST http://{{host}}/v1/messages
Authorization: Bearer {{jwt_tampered}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
