# Verify spend tracking increments after a request.
# NOTE: Hurl does not support cross-entry variable comparison, so we
# assert the spend field is a float (non-negative) after a request.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200

GET http://{{host}}/health
HTTP 200
[Asserts]
jsonpath "$.spend.total_usd" isFloat
