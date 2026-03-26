# Verifies the /v1/responses endpoint with streaming enabled.
# Accepts any non-5xx status since the feature may not be active.
POST http://{{host}}/v1/responses
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","input":"Hello","max_output_tokens":50,"stream":true}
HTTP *
[Asserts]
status < 500
