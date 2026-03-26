# Pairwise: Auth=none, Provider=rate429, DLP=redact, Policy=none, Format=anthropic, Payload=secrets
# No auth; rejected before provider or DLP evaluation.
POST http://{{host}}/v1/messages
Content-Type: application/json
file,fixtures/dlp/prompt-with-jwt.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
