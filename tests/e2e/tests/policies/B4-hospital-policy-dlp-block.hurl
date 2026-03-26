# Decision table row 5: JWT=hospital-eu, policy match, DLP=block (policy override)
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_hospital_eu}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-aws-key.json;
HTTP 200
[Asserts]
body not contains "AKIAIOSFODNN7EXAMPLE"
