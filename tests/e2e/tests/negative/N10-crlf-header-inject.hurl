# CRLF injection attempt in header value
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
X-Forwarded-For: 127.0.0.1\r\nSet-Cookie: evil=true
file,../../fixtures/chat-simple.json;
HTTP [200, 400]
[Asserts]
header "Set-Cookie" not exists
