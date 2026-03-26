# Verifies the Prometheus metrics endpoint is reachable and exposes
# Grob-specific metrics.  The /metrics path is typically unauthenticated.
GET http://{{host}}/metrics
HTTP 200
[Asserts]
body contains "grob_"
