# Verifies grob survives a stop/start cycle without issues.
# Regression test for a bug where grob stop returned before the
# process fully exited, causing the next start to fail.
#
# NOTE: This test only checks that grob is healthy. The actual
# stop/start cycle is tested via the advanced/S9 shell script.
GET http://{{host}}/health
HTTP 200
[Asserts]
jsonpath "$.status" == "ok"
