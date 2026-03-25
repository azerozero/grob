# Sends a valid JSON payload but declares it as text/plain.
# Grob should reject with 400 (body parse error) or 415 (Unsupported Media Type).
# A 200 here would mean Grob is not enforcing Content-Type, which is a defect.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: text/plain
`{"model":"gpt-4o","messages":[{"role":"user","content":"test"}],"max_tokens":10}`
HTTP [400, 415]
