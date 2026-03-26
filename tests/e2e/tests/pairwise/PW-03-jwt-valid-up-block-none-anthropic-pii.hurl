# Pairwise: Auth=jwt_valid, Provider=up, DLP=block, Policy=none, Format=anthropic, Payload=pii
POST http://{{host}}/v1/messages
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-iban.json;
HTTP 200
[Asserts]
body not contains "FR7630006000011234567890189"
