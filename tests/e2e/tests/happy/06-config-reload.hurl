# Verifies the config hot-reload endpoint atomically swaps reloadable state
# (router, provider registry, model index) without restart.
# In JWT auth mode the endpoint requires a valid bearer token.
POST http://{{host}}/api/config/reload
Authorization: Bearer {{jwt_default}}
HTTP 200
