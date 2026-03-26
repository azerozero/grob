# Tenant B (team-perf) must work even if Tenant A (hospital-eu) exhausts its budget
# This is a structural invariant — tenants are budget-isolated
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_team_perf}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
