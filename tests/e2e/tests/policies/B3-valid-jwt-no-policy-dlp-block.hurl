# Decision table row 4: JWT=valid, no policy match, DLP=block → 400
# Note: requires DLP configured with secrets=block in grob-test.toml
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-aws-key.json;
HTTP 200
[Asserts]
body not contains "AKIAIOSFODNN7EXAMPLE"
