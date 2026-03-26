# Verifies config hot-reload is idempotent.
# Two successive reloads must both succeed — the second swap must not
# fail because the previous snapshot was already replaced.
POST http://{{host}}/api/config/reload
Authorization: Bearer {{jwt_default}}
HTTP 200

POST http://{{host}}/api/config/reload
Authorization: Bearer {{jwt_default}}
HTTP 200
