# Decision table row 6: JWT=team-perf, policy match, rate_limit=500rps
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_team_perf}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
# Team-perf gets 500rps limit — normal request should succeed
