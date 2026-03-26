# All providers are disabled via Toxiproxy before this test.
# With no reachable backend, Grob must return a 502 Bad Gateway or
# 503 Service Unavailable rather than hanging or returning a 200.
# Run run-failover.sh which disables all proxies before executing this file.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 502
