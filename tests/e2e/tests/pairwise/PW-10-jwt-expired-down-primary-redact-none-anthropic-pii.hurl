# Pairwise: Auth=jwt_expired, Provider=down_primary, DLP=redact, Policy=none, Format=anthropic, Payload=pii
# Auth rejection happens before provider or DLP evaluation.
POST http://{{host}}/v1/messages
Authorization: Bearer {{jwt_expired}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-iban.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
