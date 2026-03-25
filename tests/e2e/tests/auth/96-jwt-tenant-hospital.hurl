# JWT with tenant=hospital-eu-paris → hospital-eu policy applied
# Policy: DLP secrets=block, rate_limit=10rps, budget=50usd
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_hospital_eu}}
Content-Type: application/json
file,../../fixtures/dlp/prompt-with-aws-key.json;
HTTP [200, 400]
[Asserts]
# AWS key must not appear in response (DLP block policy)
body not contains "AKIAIOSFODNN7EXAMPLE"
