# Pairwise: Auth=jwt_valid, Provider=down_primary, DLP=disabled, Policy=none, Format=openai, Payload=clean
# Primary is down; Grob should failover to next provider.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices[0].message.content" exists
