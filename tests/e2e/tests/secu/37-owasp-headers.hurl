# Verifies that Grob sets OWASP-recommended security response headers.
# The x-content-type-options: nosniff header prevents MIME-type sniffing
# attacks in downstream consumers.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
header "x-content-type-options" == "nosniff"
