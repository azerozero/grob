# BVA: provider-level budget exhausted (anthropic-mock: $50) → fallback to next provider
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP [200, 402]
