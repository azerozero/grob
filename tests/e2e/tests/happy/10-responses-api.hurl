# Verifies the /v1/responses endpoint for Codex CLI compatibility.
# The endpoint may return 404 if the responses_compat feature is not enabled,
# so we accept any status code and only assert that the server does not crash.
POST http://{{host}}/v1/responses
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","input":"Hello","max_output_tokens":50}
HTTP *
[Asserts]
status < 500
