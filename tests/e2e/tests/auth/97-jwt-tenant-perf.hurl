# JWT with tenant=team-perf-alpha → team-perf policy applied
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_team_perf}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
header "x-ai-provider" exists
header "x-ai-model" exists
