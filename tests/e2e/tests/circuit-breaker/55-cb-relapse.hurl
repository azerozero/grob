# State transition: CLOSED → OPEN again after 5 new failures (relapse).
# All proxies disabled again by run-cb.sh.  Grob returns 502.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 502
[Asserts]
duration < 500
