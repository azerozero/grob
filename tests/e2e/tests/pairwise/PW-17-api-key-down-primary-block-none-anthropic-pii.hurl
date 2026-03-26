# Pairwise: Auth=api_key, Provider=down_primary, DLP=block, Policy=none, Format=anthropic, Payload=pii
# API key rejected before provider or DLP evaluation.
POST http://{{host}}/v1/messages
x-api-key: grob-siege-master-key
Content-Type: application/json
file,fixtures/dlp/prompt-with-iban.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
