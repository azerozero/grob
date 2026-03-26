# Primary provider has a 5 000 ms latency toxic injected via Toxiproxy.
# Grob should either time out and fall back to a faster provider (200) or
# surface a 504 Gateway Timeout.  Either outcome is acceptable; what is NOT
# acceptable is hanging for more than 10 seconds.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
duration < 10000
