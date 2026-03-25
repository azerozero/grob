# Primary provider (anthropic-mock) is disabled via Toxiproxy before this test.
# Grob must detect the connection failure and fall back to the next provider
# in its routing chain (openai-mock or gemini-mock).
# Run run-failover.sh to orchestrate the Toxiproxy state around this test.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices[0].message.content" exists
