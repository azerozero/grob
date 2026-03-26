# Sends a prompt containing both a credit card number and an AWS Access Key ID.
# The DLP pipeline must redact or block both secrets simultaneously.
# Neither secret must appear verbatim in the response body.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-multi-secrets.json;
HTTP 200
[Asserts]
body not contains "4532015112830366"
body not contains "AKIAIOSFODNN7EXAMPLE"
jsonpath "$.choices" exists
