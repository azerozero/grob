# Route service credentials with or without Vault

Use the HTTP service gateway when an agent should keep a stable Grob identity
while an administrator rotates an upstream token or username/password pair.
Local encrypted storage supports the same injection path as Vault/OpenBao KV v2.
The existing LLM `secret:<name>` references remain separate and compatible.

## Create a dedicated agent identity

Keep the administrator credential separate from agent credentials:

```toml
[auth]
mode = "api_key"
api_key = "secret:grob-admin"
adopt_from_system = false
```

```sh
grob secrets add grob-admin
grob key create --name service-agent --tenant operations
```

Store the returned key in the agent and use its returned UUID in the binding
below. Gateway bindings require an explicit tenant. Keys restricted to LLM models
or providers are rejected by this endpoint; provision a dedicated service key.
With JWT authentication, use `jwt:<subject>` instead of `key:<uuid>` and match the
verified tenant claim. Forwarded identity headers never grant access.

## Configure an exact service destination

Add this binding to `config.toml`, replacing the example UUID, origin and IP with
your own approved values:

```toml
[[credential_services]]
id = "tickets"
tenant = "operations"
agents = ["key:00000000-0000-4000-8000-000000000001"]
origin = "https://tickets.example.com"
allowed_ips = ["203.0.113.10"]
paths = ["/api/tickets", "/api/status"]
methods = ["GET", "POST"]

[credential_services.injection]
type = "bearer"
```

Connections use only `allowed_ips`, with DNS resolution and environment HTTP
proxies disabled. TLS still verifies the configured hostname. Include a port in
the origin when the service uses a nondefault port. HTTPS is required, except for
explicitly pinned loopback HTTP used by local services and tests. Update the IP
list when the upstream changes addresses.

Paths match exactly. Query strings, percent-encoded paths, dot segments, duplicate
slashes and redirects are rejected. The agent supplies a service identifier and
path; it cannot supply an upstream origin or secret reference. Arbitrary custom
request headers and cookies are not forwarded. Supported content types are JSON,
plain text, event streams and form data. Binary response types are rejected.
Request bodies are limited to 2 MiB. Upstream exchanges have a **60-second total
deadline**, including the response stream; this is not an idle timeout.

Reload the server after editing configuration. Any binding change requires
explicit credential publication against that new configuration; an earlier
credential does not silently acquire new destinations or permissions.

## Provision or rotate local credentials

Supply a complete JSON bundle through stdin, without putting literal secret
values in command arguments or shell history. For example, a secret manager can
pipe a bundle into:

```sh
grob credentials local tickets
```

The stdin shape for Bearer or an API key header is:

```json
{"token":"<upstream-token>"}
```

For an API key header, configure:

```toml
[credential_services.injection]
type = "header"
name = "x-api-key"
```

For HTTP Basic, configure `type = "basic"` and provide one coherent bundle:

```json
{"username":"<upstream-user>","password":"<upstream-password>"}
```

Run the same `credentials local` command to rotate or explicitly switch from
Vault to local authority. New dispatches read the new encrypted record; already
dispatched requests can finish. The agent key and service URL remain unchanged.
Use `--expires-at <unix-seconds>` to impose a credential deadline, and optionally
set `expires_at` on the service binding to bound the policy itself.
When rotating without `--expires-at`, the existing credential deadline is
preserved. Extending an expired deadline requires an explicit new timestamp.

Call `https://<grob-host>/v1/services/tickets/api/tickets` with the agent's Grob
Bearer key. Grob authenticates the agent, checks the binding and applicable
existing spend limits, then injects the upstream credential. Local mode does not
contact Vault and needs no Vault installation.

## Add optional Vault or OpenBao

Store the same JSON bundle in a KV v2 entry. Give a dedicated Vault token only
`read` access to its data path. Have Vault Agent auto-auth maintain the token in
an owner-only regular file (0400/0600 on Unix, not a symlink); Grob rereads that file on each authoritative refresh.
Grob does not issue or renew the Vault authentication token itself.

Add the following table inside the service binding, after its injection table:

```toml
[credential_services.vault]
endpoint = "https://vault.example.com:8200/v1/secret/data/tickets"
allowed_ips = ["10.0.0.12"]
token_file = "/run/grob/vault-token"
refresh_secs = 5
max_offline_secs = 60
```

`refresh_secs` must be 1–300 seconds. `max_offline_secs` defaults to zero, which
disables outage recovery; the largest permitted value is one day. These intervals
also bound rotation/revocation visibility. Reads within the refresh interval use
the last verified generation. Concurrent refreshes are coalesced per service per
process; stale results cannot overwrite a newer administrative publication.

Each successful Vault read replaces the current version's deletion deadline.
A newer version can have a later deadline or none. Administrative and binding
deadlines remain independent restrictions. An expired cached version can trigger
a fresh authoritative read; it is never used during an outage. A failed refresh
still observes retry backoff, so expiry does not create an unbounded retry loop.

After reloading configuration, explicitly activate Vault authority:

```sh
grob credentials vault tickets
```

The first call must successfully read Vault. A fresh installation cannot recover
an unknown secret. Recovery snapshots are encrypted separately from legacy
provider secrets, and cannot be provisioned as if they were local credentials.

During a classified connection failure, timeout, or HTTP 502/504, a previously
verified snapshot may be used within the configured offline age. Policy expiry
and KV deletion deadlines can shorten this window. Cache reads, failures and
restarts do not extend it. Clock rollback rejects access. A process without Vault
connectivity cannot discover a new remote revocation; choose zero offline age if
that uncertainty is unacceptable.

Permission denial, deletion, a lower KV version, malformed data, TLS validation
failure, or HTTP 503 (which may indicate a sealed Vault) disable the binding and
durably discard its snapshot. Fix the cause and explicitly run `credentials vault`
again to clear the denial. A new token file alone cannot resurrect a revoked
binding. Vault returning online never replaces an explicit local override.

The adapter supports KV v2 static bundles. Dynamic secret issuance and lease
renewal, Vault namespaces, browser login forms, MFA and transparent HTTPS tunnel
interception are outside this implementation.

## Inspect, revoke and recover

```sh
grob credentials status tickets
grob credentials check tickets
grob credentials revoke tickets
```

The authenticated administrative endpoint `GET /api/credentials/status` reports
`local`, `remote`, `verification_due`, `recovery` or `unavailable`, along with
generation and validity metadata. It never returns bundle values. Revocation
survives process restarts. Only explicit local or Vault publication clears it.
Unrelated local bindings continue working during a Vault outage.

### Upgrade records with an old combined expiry

New records use format 2 and keep administrative and Vault version expiry
separate. Format 1 records remain readable, but their old combined deadline stays
a conservative restriction: Grob cannot prove whether an administrator set it.
`credentials check` reports `legacy_expiry_requires_review` for affected records.

Before that deadline, review the intended restriction. Put any required lasting
deadline in the binding's `expires_at`, reload the configuration, then explicitly
run `grob credentials vault tickets` to publish a format 2 record. The next
dispatch must validate Vault again. This command also clears revocation, so use
it only after deciding the binding should be active. Keep a backup before the
upgrade; older binaries reject format 2 records rather than misread their bounds.

Persist `GROB_HOME/credentials/` and `GROB_HOME/encryption.check` across container
recreation, and retain the associated encryption key in a separate protected
location. See [key custody and lifecycle](protect-credential-storage.md). Bundles and ownership/validity metadata share one authenticated
AES-256-GCM envelope, published by atomic replacement with durable directory
updates. The plaintext buffers owned by the broker are erased on drop; this does
not encrypt all RAM or protect a compromised host.

Response filtering decodes JSON strings and form values before removing echoes.
A matching scalar is replaced as a whole; a matching object/form key rejects the
response because renaming keys could merge fields. JSON syntax characters are
not credential values. JSON and form documents are buffered up to 2 MiB; malformed
JSON is rejected. SSE is processed one complete event at a time, limited to 64 KiB,
including multiline data and CR/LF boundaries. JSON event data is decoded before
masking. A completed event does not wait for the next event or stream completion.
One leading UTF-8 BOM is accepted; later payload characters remain unchanged.
Media types are compared without ASCII case sensitivity, including permitted
spaces before parameters, and are forwarded in canonical form.
Plain text keeps only a suffix that could still match a literal credential.

Unsupported or compressed response types are rejected. A rejection after response
headers have been sent terminates the response body; consumers must handle body
errors. Responses are never cached; only a sanitized content type is forwarded.
The approved upstream still receives the secret and remains trusted: arbitrary
transformations or encodings by a malicious upstream cannot be reliably redacted.

This gateway has its own service policy and does not run LLM classification,
prompt DLP, tool policy or token-based billing. Configurations with `[[policies]]`
are rejected when credential services are present, preventing those policies from
being silently bypassed. Use a dedicated gateway configuration for this case.

## Run fault qualification

```sh
cargo build --release
python3 scripts/ci/credential-recovery.py --binary target/release/grob \
  --engine docker --output /tmp/grob-credential-recovery
```

Use `--engine podman` with Podman. The test creates its own OpenBao container,
synthetic service and temporary encrypted store. It checks local and remote
rotation, concurrent dispatch, outages, offline expiry, explicit source changes,
revocation, a sealed Vault and Grob process SIGKILL/restart. It removes only its
own resources. The same qualification runs in the existing hardening CI job.
Connection/stream regression tests run with `cargo test --lib credential`.
TLS hostname validation and HTTP/2 reuse are exercised with
`cargo test --lib --features tls credentials::transport::tls_tests`.
CI qualifies OpenBao 2.5.5 and 2.7.0 separately; this is not a claim of blanket
compatibility with all Vault/OpenBao releases.

See [ADR-0031](../decisions/0031-optional-vault-credential-routing.md) for the design
and [memory qualification](harden-memory.md) for broader crash-test limitations.
