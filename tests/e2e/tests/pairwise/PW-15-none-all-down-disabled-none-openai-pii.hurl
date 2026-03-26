# Pairwise: Auth=none, Provider=all_down, DLP=disabled, Policy=none, Format=openai, Payload=pii
# No auth; rejected before provider availability matters.
POST http://{{host}}/v1/chat/completions
Content-Type: application/json
file,fixtures/dlp/prompt-with-cc.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
