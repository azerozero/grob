# Code-scanning review — September 2026

The review started with 34 open alerts on `main`: CodeQL 69–100 and Semgrep
67–68. Alert numbers below refer to
[grob code scanning](https://github.com/azerozero/grob/security/code-scanning).
They identify findings, not counts of distinct vulnerabilities.

## Credential transport corrections

CodeQL 87–93 concern credential probes, device authorization, OAuth token
exchange, and the two Gemini request paths. Some default endpoints already
use HTTPS, but operator overrides were not consistently enforced and the
HTTP clients followed redirects.

The shared endpoint validator now parses the URL, rejects userinfo and
non-HTTP(S) schemes, and permits plaintext HTTP only for loopback hosts.
The affected clients do not follow redirects, including 307/308 responses
that could replay credential-bearing bodies or custom headers. Operators
must configure the final HTTPS endpoint. Local test servers and local
integrations remain supported; the exception assumes a trusted local host.

The review also found a Gemini API key in request URLs printed by streaming
debug logs. Both inference paths and the credential probe now send the key
in `x-goog-api-key`, as supported by the
[Gemini API](https://ai.google.dev/gemini-api/docs/api-key).
Inference headers are marked sensitive so request debug output redacts them.
Probe transport errors omit their URL.

Regression tests exercise actual HTTP requests against local mock servers:

- Gemini streaming and non-streaming send the header without a key query parameter.
- Request debug output does not contain the Gemini key.
- Remote HTTP and loopback lookalikes are rejected before credentials are sent.
- OAuth form/JSON, device start/poll, credential probes, and Gemini refuse redirects; a second server receives zero requests.
- Existing local probe success and invalid-key handling still work.

## Findings without a production vulnerability at the reported sink

| Alerts | Source / trust boundary | Disposition |
| --- | --- | --- |
| 99–100 | `src/storage/encrypt.rs`: zero-initialized key/nonce buffers are fully overwritten by `OsRng.fill_bytes` before cryptographic use. The initializer is not a hard-coded cryptographic value. | False positive |
| 97–98 | `src/server/openai_compat/transform.rs`: both reported preallocation sizes are capped by `.min(1024)`. This only bounds initial allocation; deployments still need the documented request body limit to bound total input memory. | False positive at these allocation sinks |
| 96 | `src/auth/token_store.rs`: the legacy destination is supplied when constructing `TokenStore`; provider IDs are map keys, not path components. Production initialization uses `GrobStore`. Canonicalization alone is not a sandbox, but no untrusted HTTP field chooses this legacy destination. | False positive |
| 94–95 | `benches/proxy_overhead.rs` and `src/commands/bench/mock.rs`: `backend_url` comes from a mock listener bound to `127.0.0.1:0`, installed in server state by the benchmark runner. Incoming JSON cannot select that URL. | False positive |
| 84–86 | `benches/http_overhead.rs`: certificate verification is deliberately disabled for the benchmark's own ephemeral self-signed loopback server. These clients are not production provider transports. | Used in tests |
| 81–83 | `src/providers/openai/mod.rs`: OAuth credentials go into request headers. The tracing call in `apply_oauth_headers` prints the provider name, not the bearer token or extracted account ID. The reported `.send()` sites do not log the request. | False positive |
| 69–72, 79 | `connect` and `doctor` print configured provider IDs and credential-source labels, not the credentials obtained from those sources. | False positive |
| 73, 80 | `src/commands/key.rs`: revoke output prints a parsed UUID identifying a key record, not its secret key value. | False positive |
| 74–75 | `src/commands/secrets.rs`: list output prints a count and secret names, not values. | False positive |
| 76 | `src/commands/secrets.rs`: default show output runs through `redact`; short values are fully hidden and longer values expose only an identifying prefix/suffix. | False positive |
| 77 | `grob secrets show --unsafe-show` explicitly reveals a local secret on stdout, only after the operator opts in. Default output is redacted. This is intentional credential-export functionality, not unattended application logging. | Accepted behavior (`won't fix`) |
| 78 | `src/preset/mod.rs`: auth information contains an OAuth slot name, environment-variable reference, or configured/missing status. Literal API key values are not printed by this sink. | False positive |
| 67–68 | `src/features/media/scan/mod.rs`: synthetic GitHub-token-shaped OCR fixtures test secret detection. They do not authenticate to GitHub. | Used in tests |

The same synthetic-token pattern in `src/commands/bench/payloads.rs` is a DLP
benchmark input, not a GitHub credential. Semgrep may report it separately
as rules evolve; it has the same test-fixture disposition.

Dismissals apply to individually reviewed alerts with source-specific
justifications. No scanner rule, production directory, or severity level is
excluded. Revisit a dismissal if its trust boundary changes, especially if
benchmark URLs become configurable or identifiers begin carrying secret values.
