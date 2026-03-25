# Forces a provider-level error by requesting a model that does not exist.
# Verifies that Grob's error response does not leak any provider API key
# material, including mock keys and known key prefixes (sk-mock, sk-ant,
# AKIA...).  Even in test environments, key leakage must be treated as a defect.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
`{"model":"nonexistent-model","messages":[{"role":"user","content":"test"}],"max_tokens":10}`
HTTP [400, 404, 502]
[Asserts]
body not contains "sk-mock"
body not contains "sk-ant"
body not contains "AKIAIOSFODNN"
