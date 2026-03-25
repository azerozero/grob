# JWT with alg:none (classic attack) → 401
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_algo_none}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 401
