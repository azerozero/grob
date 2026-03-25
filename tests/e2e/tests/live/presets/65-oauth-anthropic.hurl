# Live: OAuth Anthropic preset — token exchange via OAuth PKCE flow
# Requires: valid OAuth credentials in environment
# Note: GROB_JWT is intentionally omitted; authentication relies on OAuth token
GET http://{{host}}/api/oauth/login
HTTP 302
[Asserts]
header "Location" contains "anthropic.com"
