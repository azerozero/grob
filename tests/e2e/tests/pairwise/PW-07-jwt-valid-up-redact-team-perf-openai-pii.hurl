# Pairwise: Auth=jwt_valid, Provider=up, DLP=redact, Policy=team_perf, Format=openai, Payload=pii
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_team_perf}}
Content-Type: application/json
file,fixtures/dlp/prompt-with-cc.json;
HTTP 200
[Asserts]
body not contains "4532015112830366"
header "x-ai-provider" exists
