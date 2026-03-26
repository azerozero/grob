# Pairwise: Auth=none, Provider=up, DLP=disabled, Policy=none, Format=openai, Payload=clean
# No auth header at all; must be rejected.
POST http://{{host}}/v1/chat/completions
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
jsonpath "$.error.message" contains "Missing or invalid Authorization header"
