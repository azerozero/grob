# Verifies DLP handles input containing personal names gracefully.
# Name pseudonymization requires explicit names config in TOML.
# Without it, the request must still succeed without errors.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","messages":[{"role":"user","content":"Please contact John Smith at Thales Group"}],"max_tokens":50}
HTTP 200
[Asserts]
jsonpath "$.choices" exists
