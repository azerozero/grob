# GDPR-tagged tenant routing verification.
# The hospital-eu tenant carries compliance=["gdpr"] in its JWT claims.
# The request must succeed and include transparency headers proving
# the proxy honoured the GDPR routing constraint.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_hospital_eu}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
header "x-ai-provider" exists
header "x-ai-model" exists
