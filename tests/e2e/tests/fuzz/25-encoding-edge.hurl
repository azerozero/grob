# Sends a message containing emoji characters (encoding edge case).
# Grob must handle UTF-8 multi-byte sequences gracefully.
# A 200 is acceptable; a 500 or crash is not.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","messages":[{"role":"user","content":"Hello 🎉 world"}],"max_tokens":50}
HTTP 200
