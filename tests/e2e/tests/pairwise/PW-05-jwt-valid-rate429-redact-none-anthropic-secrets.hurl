# Pairwise: Auth=jwt_valid, Provider=rate429, DLP=redact, Policy=none, Format=anthropic, Payload=secrets
# Provider returns 429; Grob retries on alternate provider. DLP redacts secrets.
POST http://{{host}}/v1/messages
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-jwt.json;
HTTP 200
[Asserts]
body not contains "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
