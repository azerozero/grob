# Attempts a CRLF header injection attack via a percent-encoded value in a
# custom request header.  Grob (or the underlying Axum/hyper stack) must
# sanitise the value so that no injected "Injected-Header" appears in the
# HTTP response headers.
POST http://{{host}}/v1/chat/completions
Authorization: Bearer {{jwt_default}}
Content-Type: application/json
X-Custom: value%0d%0aInjected-Header: evil
`{"model":"gpt-4o","messages":[{"role":"user","content":"test"}],"max_tokens":10}`
HTTP [200, 400]
[Asserts]
header "Injected-Header" not exists
