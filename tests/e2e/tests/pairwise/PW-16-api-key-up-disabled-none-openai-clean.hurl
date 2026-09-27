# Pairwise: Auth=api_key, Provider=up, DLP=disabled, Policy=none, Format=openai, Payload=clean
# The server api_key is an administrative credential accepted alongside JWT;
# a clean OpenAI-format request with it reaches the provider.
POST http://{{host}}/v1/chat/completions
x-api-key: grob-siege-master-key
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices[0].message.role" == "assistant"
