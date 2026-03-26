# Verifies grob survives a stop/start cycle without db lock issues.
# This is a regression test for the redb lock bug where grob stop
# returned before the process fully exited, causing the next start
# to fail with "Failed to open redb database".
#
# NOTE: This test only checks that grob is healthy. The actual
# stop/start cycle is tested via the advanced/S9 shell script.
GET http://{{host}}/health
HTTP 200
[Asserts]
jsonpath "$.status" == "ok"
