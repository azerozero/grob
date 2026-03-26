# Pairwise: Auth=api_key, Provider=up, DLP=disabled, Policy=none, Format=openai, Payload=clean
# API key auth (x-api-key header) is rejected in JWT-only mode.
POST http://{{host}}/v1/chat/completions
x-api-key: grob-siege-master-key
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
