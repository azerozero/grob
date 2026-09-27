# Verifies the config hot-reload endpoint atomically swaps reloadable state
# (router, provider registry, model index) without restart.
# Reload is administrative: a tenant JWT is authenticated but not an admin,
# so it is refused; the server api_key (admin credential) is required.
POST http://{{host}}/api/config/reload
Authorization: Bearer {{jwt_default}}
HTTP 403
[Asserts]
jsonpath "$.error.type" == "permission_error"

POST http://{{host}}/api/config/reload
x-api-key: grob-siege-master-key
HTTP 200
[Asserts]
jsonpath "$.status" == "success"
