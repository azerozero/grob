# Verifies that streaming responses use the SSE content-type.
# The mock backend must emit at least one data: chunk so the header is set.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-streaming.json;
HTTP 200
[Asserts]
header "content-type" contains "text/event-stream"
