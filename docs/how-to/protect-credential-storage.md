# Protect credential storage and lifecycle

This guide applies the [OWASP Secrets Management recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
to Grob's service gateway. It is a deployment guide, not a certification.

## Separate the storage key from the data

Set `GROB_ENCRYPTION_KEY_FILE` to an absolute path containing exactly 32 raw bytes.
The variable contains a **path**, never a secret value. The file must be outside
`GROB_HOME`, a regular file, and owner-only on Unix (0400 or 0600). Final-component
symlinks and oversized files are rejected. Protect its parent directories too;
these are administrator-owned trust boundaries. On Windows restrict the file's
ACL to the service account and administrators; Unix mode checks do not apply.

```ini
# systemd service override; the encrypted credential must already be provisioned.
[Service]
LoadCredentialEncrypted=grob-storage-key:/etc/credstore.encrypted/grob-storage-key
Environment=GROB_ENCRYPTION_KEY_FILE=%d/grob-storage-key
```

systemd decrypts the credential before starting Grob. Its encrypted source can be
protected by a host key, TPM2, or both, depending on the host's setup. Follow the
[systemd credential documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredentialEncrypted=)
for provisioning and test recovery before binding the key to hardware.
Grob reads the resulting protected credential; it does not implement its own TPM
protocol or claim to encrypt every plaintext copy in RAM.

In a container, mount the same key as a read-only file such as
`/run/secrets/grob-storage-key`, outside the persistent `/data` volume. Set
`GROB_HOME=/data` and `GROB_ENCRYPTION_KEY_FILE=/run/secrets/grob-storage-key` for
both daemon and administrative commands. Configure the secret's mode as 0400 or
0600 and ownership for the container's user. Do not bake it into the image or
back it up together with the data volume. Direct symlink-based secret mounts
need a protected regular-file projection; Grob deliberately refuses symlinks.

Without this variable, the compatible local `encryption.key` remains available.
`grob credentials check <service>` flags this colocated-key mode. It protects
against unrelated OS users, but copying the complete data directory copies both
the ciphertext and its decryption key. Vault is not required for external keys.

## Migrate an existing key safely

1. Stop all processes writing the store. Back up encrypted records, spend journals
   and `encryption.check`; protect the key backup independently and limit access.
2. Provision the **existing 32-byte key** into the external credential source.
   Moving key custody does not generate a different data-encryption key.
3. Open the store with `GROB_ENCRYPTION_KEY_FILE` configured. A remaining local key
   must match; the authenticated `encryption.check` must verify. Older stores
   without that check authenticate their encrypted records before accepting an
   external key. Missing, corrupt or conflicting sources stop startup.
4. Test reading a non-production restored copy, local rotation, revocation, and
   restart. Then remove the redundant local key copy from the live store and
   ordinary backups under your retention policy. The diagnostic reports a
   remaining local copy even when the external source is selected.
5. Start every daemon and CLI with the same source. Omitting a required key never
   generates a replacement over existing encrypted data.

Retain `encryption.check` with the data: it prevents an incorrect key from being
accepted before new writes. Replacing the key file with unrelated random bytes
is **not key rotation**; it is refused. Rotating a data-encryption key requires a
coordinated decrypt/re-encrypt migration and independent recovery testing. This
change adds custody separation, not that migration protocol. Historical backup
copies and SSD snapshots cannot be reliably erased by overwriting one file.

## Delegate Vault authentication without a second secret cache

The simplest integration is a Vault/OpenBao Agent auto-auth **file sink**, mode
0600, referenced by `token_file`. Grob checks the file on each authoritative
refresh, bounds reads to 16 KiB, and never places its token in logs or arguments.

On Unix, a local Vault/OpenBao Proxy can instead own the auto-auth token:

```toml
[credential_services.vault]
endpoint = "http://localhost/v1/secret/data/tickets"
allowed_ips = ["127.0.0.1"]
proxy_socket = "/run/grob-vault/proxy.sock"
refresh_secs = 5
max_offline_secs = 0
```

Omit `token_file` in this mode. The HTTP origin is a logical URL; the transport
uses only the configured Unix socket, never a TCP listener. Give Grob and the
companion the same dedicated OS identity, protect the socket directory, and make
the socket owner-only. A missing socket is an outage; unsafe permissions or an
authority denial are hard failures. Do not make a general-purpose shared proxy
socket accessible to agents.

The companion's relevant configuration is:

```hcl
# Add your environment's auto_auth method with read-only access to the KV path.
vault {
  address = "https://vault.example.com:8200"
  retry { num_retries = -1 }
}
api_proxy {
  use_auto_auth_token = "force"
}
listener "unix" {
  address = "/run/grob-vault/proxy.sock"
  socket_mode = "0600"
  tls_disable = true
  require_request_header = true
}
# Deliberately omit the cache stanza; even an empty stanza enables caching.
```

Grob sends `X-Vault-Request: true` and no Vault token in socket mode. The companion
must verify the remote Vault TLS certificate. Keep the companion's secret cache
disabled: Grob cannot distinguish an authoritative successful response from a
stale cached response and must not refresh its verification age from the latter.
The socket integration is tested with a protocol fixture; qualify your actual
auto-auth method and Proxy version before deployment. See
[Vault Proxy](https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy),
[cache limitations](https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy/caching)
and [OpenBao Agent/Proxy](https://openbao.org/docs/agent-and-proxy/).

## OWASP lifecycle controls

| Recommendation | Grob control | Operator responsibility |
|---|---|---|
| Least privilege | Tenant + agent + exact destination/path/method, pinned IPs, separate admin plane | Dedicated identities and read-only KV path policy; no root Vault tokens |
| Central rotation | Local atomic bundles or bounded KV refresh; pooled connections get current auth per request | Rotate the upstream credential, then publish it; check the next request |
| Expiry and revocation | Separate administrative and current Vault-version deadlines, durable revocation, fail-closed recovery | Set `--expires-at` for local bundles or binding `expires_at` for persistent policy; choose offline age and revoke at the issuer too |
| Key separation | External protected key file and authenticated key check | Separate volumes/backups and recovery keys; restore drills |
| Audit and alerting | Metadata-only publication/revocation logs; actor/service on dispatch; `CREDENTIAL_USE` in configured signed audit log | Retain/ship logs, use OS audit for CLI administrators, alert on denial/recovery and expiry |
| No secret exposure | Protected bounded file reads, sensitive HTTP headers, zeroizing owned buffers, decoded response filtering | No secrets in shell arguments, tracing bodies or ordinary backups; approved upstream remains trusted |
| Availability | Autonomous local authority, bounded opt-in recovery, crash qualification | Monitor source readiness and disk failures; exercise recovery on the target host |

`grob credentials check <service>` reports local readiness and warnings without
calling an upstream. For Vault it explicitly reports that remote authorization
was not probed; it cannot promise the issuer will accept a request. It flags a
missing expiry, a colocated key and a remaining local key copy.
It also flags old combined-expiry records that need an
[explicit upgrade review](route-service-credentials.md#upgrade-records-with-an-old-combined-expiry).

For OAuth-capable services, prefer a trusted issuer/controller that obtains
short-lived, audience- and scope-limited tokens and publishes them with
`credentials local --expires-at`. Validate issuer, audience, scope and expiry in
that controller; the generic gateway does not validate arbitrary JWT claims or
mint grants. mTLS/DPoP require provider-specific support and are not advertised by
this gateway. Follow [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700).
Basic/API-key-only upstreams continue to use rotating bundles.

## Measure before changing persistence

`cargo bench --bench credential_store` measures current-watermark reads and reads
that must durably advance the clock watermark. Every dispatch still consults the
shared store; there is no TTL-only credential cache. Global locking, fsync and
generation fencing remain in place until target-host contention measurements and
crash tests justify a different protocol. The benchmark uses a temporary store
and synthetic credentials. It does not establish production capacity.
