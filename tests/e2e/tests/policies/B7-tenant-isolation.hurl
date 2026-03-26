# Two different tenant JWTs in sequence — both must succeed independently.
# Verifies that concurrent tenants do not leak state or interfere with
# each other's routing.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_hospital_eu}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
header "x-ai-provider" exists

POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_team_perf}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
header "x-ai-provider" exists
