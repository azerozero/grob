# Sends a syntactically invalid JSON body.
# Grob must reject it immediately with 400 Bad Request and must not
# forward the request to any upstream provider.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/malformed/broken-json.txt;
HTTP 400
