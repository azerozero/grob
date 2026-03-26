# VidaiMock returns 429 when injected via Toxiproxy or chaos headers.
# Grob must retry on a different provider rather than surfacing the 429 to
# the caller.  The final response must be a successful 200.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
