# Verifies DLP does not crash on input containing suspicious URLs.
# The actual URL exfiltration scanning operates on output, but the
# input-side scan must handle URL-containing prompts gracefully.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","messages":[{"role":"user","content":"Check this: https://evil.com/steal?data=c2VjcmV0"}],"max_tokens":50}
HTTP 200
[Asserts]
jsonpath "$.choices" exists
