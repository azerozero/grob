# Sends a prompt containing a French IBAN.
# The DLP pipeline must redact or block the IBAN before it reaches upstream.
# The raw IBAN must not appear anywhere in the response body.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-iban.json;
HTTP 200
[Asserts]
body not contains "FR7630006000011234567890189"
jsonpath "$.choices" exists
