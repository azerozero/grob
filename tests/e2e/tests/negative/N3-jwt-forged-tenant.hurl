# JWT signed with wrong key claiming hospital-eu tenant → 401
# (same as self-signed but with hospital-eu claim — should not bypass policy)
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_self_signed}}
Content-Type: application/json
file,../../fixtures/chat-simple.json;
HTTP 401
