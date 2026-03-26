# Pairwise: Auth=jwt_valid, Provider=up, DLP=block, Policy=hospital_eu, Format=anthropic, Payload=secrets
# Hospital policy with DLP block on secrets.
POST http://{{host}}/v1/messages
Authorization: Bearer {{jwt_hospital_eu}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-aws-key.json;
HTTP 200
[Asserts]
body not contains "AKIAIOSFODNN7EXAMPLE"
