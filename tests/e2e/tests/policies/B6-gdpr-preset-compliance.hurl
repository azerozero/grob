# GDPR-flagged tenant must receive compliance transparency headers.
# When a hospital-eu tenant (GDPR jurisdiction) sends a request, the
# response must include AI Act disclosure headers for regulatory tracing.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_hospital_eu}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
header "x-ai-provider" exists
header "x-ai-model" exists
header "x-ai-generated" == "true"
jsonpath "$.choices" exists
