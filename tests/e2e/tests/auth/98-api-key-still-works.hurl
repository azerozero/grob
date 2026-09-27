# In JWT auth mode the server api_key remains a valid administrative
# credential: it authenticates without a JWT (operator access), while an
# unknown key is still rejected before any provider is contacted.
POST http://{{host}}/v1/chat/completions
x-api-key: grob-siege-master-key
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
jsonpath "$.choices[0].message.role" == "assistant"

POST http://{{host}}/v1/chat/completions
x-api-key: not-the-admin-key
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 401
[Asserts]
jsonpath "$.error.type" == "authentication_error"
