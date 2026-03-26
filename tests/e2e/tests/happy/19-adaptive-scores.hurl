# Verifies the /api/scores endpoint is reachable and does not 500.
# The endpoint exposes adaptive provider scoring data used by the
# routing engine.  It may require auth or may be open — we accept
# any non-5xx status.
GET http://{{host}}/api/scores
Authorization: Bearer {{jwt_default}}
HTTP *
[Asserts]
status < 500
