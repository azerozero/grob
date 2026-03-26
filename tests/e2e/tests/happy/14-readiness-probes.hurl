# Verifies health, liveness, and readiness probe endpoints.
# These are critical for container orchestration (Kubernetes, Podman).
GET http://{{host}}/health
HTTP 200
[Asserts]
jsonpath "$.status" == "ok"

GET http://{{host}}/live
HTTP 200

GET http://{{host}}/ready
HTTP 200
