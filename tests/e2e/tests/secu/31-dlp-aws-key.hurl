# Sends a prompt containing a well-known fake AWS Access Key ID.
# The DLP pipeline must intercept and redact (or block) the key before
# it reaches the upstream provider.  The raw key string must not appear
# anywhere in the response body, whether the request is blocked (400) or
# the sanitised request is forwarded (200).
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-aws-key.json;
HTTP 200
[Asserts]
body not contains "AKIAIOSFODNN7EXAMPLE"
jsonpath "$.content" exists
