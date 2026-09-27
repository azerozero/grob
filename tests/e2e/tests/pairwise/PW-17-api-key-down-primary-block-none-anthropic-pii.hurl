# Pairwise: Auth=api_key, Provider=down_primary, DLP=block, Policy=none, Format=anthropic, Payload=pii
# The server api_key authenticates as admin; the request then goes through
# DLP (IBAN redaction) and provider failover like any other and succeeds.
POST http://{{host}}/v1/messages
x-api-key: grob-siege-master-key
Content-Type: application/json
file,fixtures/dlp/prompt-with-iban.json;
HTTP 200
[Asserts]
jsonpath "$.role" == "assistant"
