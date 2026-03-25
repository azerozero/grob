# A limit_data toxic truncates the SSE stream after a few bytes.
# Grob must not crash or hang; it should either complete a partial response
# or return an error status.  Any of 200/500/502 is acceptable here.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-streaming.json;
HTTP [200, 500, 502]
