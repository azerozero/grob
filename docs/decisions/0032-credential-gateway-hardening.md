# ADR-0032: Credential gateway hardening

Status: implemented. Date: 2026-09-26.

The gateway keeps its embedded data plane and its standalone encrypted store.
The current-practice review identified protocol corruption, discarded HTTP pools,
key/data colocation, and missing qualification of streaming and TLS reuse.

## Execution plan

1. Replace unstructured response masking with bounded JSON, SSE, text and form
   handling. Reject unsupported binary content. Verify punctuation passwords,
   escaped echoes, first-event delivery, limits and malformed input.
2. Scope reusable service and Vault HTTP clients to immutable configuration
   snapshots. Keep pinned addresses, hostname verification, disabled proxies and
   redirects. Verify rotation and reload with connection-count and TLS/H2 tests.
3. Add an external key-file source compatible with systemd credentials and
   container secret mounts. Fail closed on missing, unsafe or conflicting keys;
   document migration and independent backup/recovery without exposing key values.
4. Measure storage contention before changing persistence. Preserve per-request
   cross-process reads, generation fencing, durable revocation and clock rollback
   checks. Keep fsync unless measurements and crash tests justify a replacement.
5. Complete OWASP lifecycle diagnostics, bounded protected file reads, optional
   Vault/OpenBao companion guidance, current interoperability and CI qualification.

## Invariants

Authorization precedes secret resolution. A caller cannot select an origin,
secret path or another tenant's credential. Local authority remains explicit.
Authority denial, malformed state, expiry and revocation fail closed. Offline
recovery remains opt-in, bounded by the last authoritative verification, and
never gains extra lifetime from a companion cache. No secret appears in logs,
status, command arguments or error messages. Response protection applies to
decoded payload values; JSON/SSE protocol delimiters are not payload values.

Short-lived workload credentials are preferable where the upstream supports
them. Existing expiring bundles can be rotated by a trusted external issuer.
Grob must not invent an OAuth grant, audience or scope for Basic/API-key services.
Companion auto-auth can replace Vault token lifecycle code; a second secret cache
must be disabled. Exact paths and pinned destinations remain the default until a
concrete service needs a separately reviewed query/header/discovery extension.

## References

- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [reqwest client reuse](https://docs.rs/reqwest/latest/reqwest/struct.Client.html)
- [Vault Proxy caching](https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy/caching)
- [OpenBao Agent and Proxy](https://openbao.org/docs/agent-and-proxy/)
- [systemd credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredentialEncrypted=)
- [OAuth security BCP, RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700)

## Storage decision

A native Criterion baseline on macOS arm64 used 100 samples per case. Median
sample-mean time was 20.95 microseconds for a current-watermark read (p95 22.72
microseconds), and 8.26 milliseconds for a read that durably advances the clock
(p95 12.56 milliseconds). These are local microbenchmarks, not request latency or
production capacity. The durability barrier dominates the occasional write.

Keep the existing lock and fsync protocol in this change. No target-host evidence
justifies weakening it, and a TTL cache would change administrative revocation
and rollback semantics. The connection-lifecycle defect has direct independent
evidence: 32 consumed HTTP/1.1 responses use 32 connections with fresh clients and
one connection with a reusable client. No general latency multiplier is claimed.
