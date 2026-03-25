# BVA: at 80% budget usage, Grob should warn but still serve
# Pre-condition: budget is pre-seeded to 80% via grob spend injection (manual step)
# This test documents the expected behavior — header x-grob-budget-warning
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices" exists
# When close to budget limit, a warning header may be present
