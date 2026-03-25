# Sends a deeply nested JSON object (200 levels) to probe recursion limits
# in Grob's JSON parser.  The server must not stack-overflow or hang;
# it should return 200 (if parsed successfully), 400 (parse error), or
# 413 (Payload Too Large) depending on configured limits.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/malformed/nested-1000.json;
HTTP [200, 400, 413]
