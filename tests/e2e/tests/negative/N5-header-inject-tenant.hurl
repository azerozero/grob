# Attempt to inject tenant claim via header (without valid JWT)
# Grob must ignore x-grob-tenant header and require JWT
POST http://{{host}}/v1/chat/completions
x-grob-tenant: hospital-eu-paris
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 401
[Asserts]
# Must not be treated as authenticated
