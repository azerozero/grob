# Verifies config hot-reload is idempotent.
# Two successive reloads must both succeed — the second swap must not
# fail because the previous snapshot was already replaced.
# Reload is administrative, so the server api_key is used (see 06).
POST http://{{host}}/api/config/reload
x-api-key: grob-siege-master-key
HTTP 200

POST http://{{host}}/api/config/reload
x-api-key: grob-siege-master-key
HTTP 200
