# Tests DLP canary token detection.
# The grob-test.toml configures an internal_token pattern (prefix "itk_")
# with action "canary".  A prompt containing a canary token must still
# be forwarded (action is log-only), but the DLP engine must recognise it.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
{"model":"default","messages":[{"role":"user","content":"Token is itk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}],"max_tokens":50}
HTTP 200
[Asserts]
jsonpath "$.choices" exists
