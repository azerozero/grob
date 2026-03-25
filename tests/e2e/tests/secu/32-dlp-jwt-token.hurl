# Sends a prompt containing a real-looking JWT (HS256, test payload).
# The DLP pipeline must redact or block the token so that its signature
# segment does not appear verbatim in the response body.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
file,../../fixtures/dlp/prompt-with-jwt.json;
HTTP [200, 400]
[Asserts]
body not contains "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
