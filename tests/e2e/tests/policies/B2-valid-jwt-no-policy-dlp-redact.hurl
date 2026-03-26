# Decision table row 3: JWT=valid, no policy match, DLP=redact → 200 with redaction
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-aws-key.json;
HTTP 200
[Asserts]
# AWS key should be redacted in what was forwarded; response should not echo it
body not contains "AKIAIOSFODNN7EXAMPLE"
