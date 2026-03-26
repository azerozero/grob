# Verify budget-related spend info is exposed in health endpoint.
GET http://{{host}}/health
HTTP 200
[Asserts]
jsonpath "$.spend" exists
jsonpath "$.spend.total_usd" exists
jsonpath "$.spend.budget_usd" exists
