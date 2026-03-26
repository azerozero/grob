# State transition: HALF-OPEN → CLOSED after successful probes
# (success_threshold = 3).  Proxies are enabled; this is success 2 of 3.
# Invoked by run-cb.sh after the half-open probe (53) succeeded.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
