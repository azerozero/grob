# Verifies that the Grob health endpoint returns 200 when the server is up.
# This is the first test to run; if it fails, all others are skipped.
GET http://{{host}}/health
HTTP 200
[Asserts]
jsonpath "$.status" == "ok"
jsonpath "$.service" == "grob"
