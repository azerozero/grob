# Multiple wrong api_key attempts — must all return 401
# Grob must not reveal the correct key length or format
POST http://{{host}}/v1/chat/completions
x-api-key: wrong-key-attempt-1
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
body not contains "grob-siege-master-key"

POST http://{{host}}/v1/chat/completions
x-api-key: wrong-key-attempt-2
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"

POST http://{{host}}/v1/chat/completions
x-api-key:
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
