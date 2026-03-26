# Pairwise: Auth=jwt_valid, Provider=all_down, DLP=disabled, Policy=none, Format=openai, Payload=clean
# NOTE: This combination requires Toxiproxy orchestration (all proxies disabled).
# When run standalone (proxies up), grob succeeds → 200.
# Tested properly in tests/failover/run-failover.sh scenario 3.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
