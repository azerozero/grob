# First request — populates cache
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-temperature-zero.json;
HTTP 200
[Asserts]
jsonpath "$.content" exists

# Second identical request — should hit cache
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-temperature-zero.json;
HTTP 200
[Asserts]
header "x-grob-cache" == "hit"
jsonpath "$.content" exists
duration < 50
