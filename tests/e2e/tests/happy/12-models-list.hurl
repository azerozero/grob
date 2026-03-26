# Verifies that the /v1/models endpoint returns the list of available models.
# The response must include an OpenAI-compatible data array.
GET http://{{host}}/v1/models
Authorization: Bearer {{jwt_default}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
