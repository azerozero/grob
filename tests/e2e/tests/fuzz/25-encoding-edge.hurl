# Sends a message containing a null byte (\u0000) embedded in a UTF-8 string.
# Grob must handle or reject this gracefully; a 200 is acceptable if the null
# byte is stripped/escaped, 400 is acceptable if Grob rejects invalid input.
# A 500 or a crash is not acceptable.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello \ud83c\udf89 \u0000 world"}],"max_tokens":50}`
HTTP [200, 400]
