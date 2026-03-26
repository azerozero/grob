# Pairwise: Auth=jwt_valid, Provider=slow, DLP=disabled, Policy=hospital_eu, Format=openai, Payload=injection
# Slow provider triggers timeout fallback. Hospital policy active.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_hospital_eu}}
Content-Type: application/json
file,fixtures/chat-simple.json;
HTTP 200
[Asserts]
duration < 10000
