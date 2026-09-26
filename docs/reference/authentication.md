# Authentication Reference

Choose how clients enter Grob and how Grob authenticates to upstream providers. These are separate decisions.

| Need | Use |
|------|-----|
| One trusted local workstation | `[auth] mode = "none"` on a loopback listener |
| Agents with separate permissions | `[auth] mode = "api_key"`, one administrative secret, and a virtual key per agent |
| An existing identity provider | `[auth] mode = "jwt"` with `[auth.jwt]` |
| A provider subscription | OAuth in `[[providers]]`; it does not authenticate clients to Grob |

Restart after changing the authentication mode or JWT configuration. For live credential replacement, see [Manage Secrets](../how-to/manage-secrets.md#replace-credentials-without-changing-the-agent).

## Auth modes

```toml
[auth]
mode = "none"  # "none" | "api_key" | "jwt"
```

### Exempt endpoints

The following endpoints bypass the main API-key/JWT check:

- `GET /health`, `GET /live`, `GET /ready`
- `GET /metrics` (its [separate bearer token](../how-to/deploy.md#protect-metrics-with-a-bearer-token) still applies when configured)
- OAuth callbacks: `/auth/callback` and `/api/oauth/callback`

The other `/api/oauth/*` endpoints require administrative access, including token listing. Virtual keys and tenant JWTs cannot administer OAuth, approve human-in-the-loop requests, or save/reload configuration. A loopback peer on an explicitly unauthenticated loopback listener has administrative access; a proxy header does not grant it.

## 1. None (default)

```toml
[auth]
mode = "none"
```

No authentication required. Suitable only when Grob binds to localhost (`[::1]` or `127.0.0.1`). All requests are treated as a single implicit tenant.

## 2. API key

```toml
[auth]
mode = "api_key"
api_key = "secret:grob-admin"
```

Create the named secret in the same `GROB_HOME` as the daemon:

```bash
grob secrets add grob-admin
```

Clients authenticate via either header:
- `Authorization: Bearer <key>`
- `x-api-key: <key>`

### Security properties

- API key comparison uses **constant-time equality** (`subtle` crate) to prevent timing side-channel attacks.
- `secret:<name>` resolves the current value for each authentication attempt. The configuration contains the reference rather than the plaintext key.
- The `/api/config` endpoint redacts API keys in its response.

### Edge cases

- A syntactically valid `Authorization: Bearer ...` takes precedence over `x-api-key`. If that bearer value is wrong, a correct `x-api-key` does not rescue it.
- An empty administrative key cannot grant administrative access. Valid virtual keys can still authenticate in `api_key` mode.
- `[server] api_key` remains a legacy fallback. A non-empty configured key activates API-key authentication even when `auth.mode = "none"`.
- `$ENV_VAR` is expanded for the legacy `server.api_key`, but **not** for `auth.api_key`. Use the named secret example above instead of a dollar-prefixed value in `[auth]`.

## 3. JWT

```toml
[auth]
mode = "jwt"

[auth.jwt]
jwks_url = "https://auth.example.com/.well-known/jwks.json"
jwks_refresh_interval = 3600          # seconds between JWKS refreshes (default: 3600)
issuer = "grob-auth"                  # expected `iss` claim (optional)
audience = "grob-proxy"               # expected `aud` claim (optional)
```

### Algorithm support

| Algorithm | Config field | Use case |
|-----------|-------------|----------|
| HS256 (HMAC-SHA256) | `hmac_secret` | Self-hosted, shared-secret setups |
| RS256 (RSA), ES256 (EC) | `jwks_url` | External identity providers |

For HS256, set `auth.jwt.hmac_secret` to the actual shared secret in a protected config file. This field currently does **not** resolve `$ENV_VAR` or `secret:<name>` references; either would be treated as the literal signing secret. Prefer JWKS when the identity provider supports it.

When both are configured, Grob tries HMAC first, then RSA and EC JWKS keys. Set a separate `auth.api_key = "secret:grob-admin"` if administrators need management access: tenant JWTs have operator access only.

### JWT claims format

```json
{
  "sub": "user-123",
  "tenant": "org-456",
  "exp": 1742313600,
  "iss": "grob-auth",
  "aud": "grob-proxy"
}
```

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | Subject (user ID). Used as tenant ID when `tenant` is absent. |
| `tenant` | No | Explicit tenant override. When present, takes precedence over `sub` for tenant identification. |
| `exp` | Yes | Expiration time (UNIX timestamp), checked during signature validation. See the cache limitation below. |
| `iss` | No | Issuer. Validated against `auth.jwt.issuer` if configured. |
| `aud` | No | Audience. Validated against `auth.jwt.audience` if configured. If `audience` is not set in config, audience validation is disabled. |

### Tenant resolution

The effective tenant ID is determined by:
1. `tenant` claim if present.
2. `sub` claim otherwise.

This tenant ID is used for rate limiting, spend tracking, and audit logging.

### Validation cache

Validated signatures are cached in memory by `SHA-256(token)` for up to 5 minutes, with a capacity of 10,000 entries. Every request rechecks `exp`, including cache hits, with the validator's 60-second clock-skew tolerance. Expired entries are rejected and removed. This cache does not provide immediate revocation: JWKS key removal does not immediately invalidate cached signatures.

### JWKS key rotation

When `jwks_url` is configured, a background task immediately fetches RSA and EC keys, then refreshes them every `jwks_refresh_interval` seconds. Failed refreshes use increasing retry intervals, up to eight times that interval. The fetch has a 10-second HTTP timeout. JWTs that depend on JWKS receive `401` until the first successful fetch; check startup logs when diagnosing this failure.

### Error responses

| Error | HTTP status | Condition |
|-------|-------------|-----------|
| Missing token | 401 | No `Authorization: Bearer` header |
| Invalid token | 401 | Signature mismatch, wrong issuer/audience |
| Expired token | 401 | Signature validation rejects `exp`; the cache limitation above applies |
| Administrative access required | 403 | A valid virtual key or tenant JWT attempts a management operation |

## 4. Virtual keys

Virtual keys provide multi-tenant access control with per-key budget, rate limit, and model restrictions. Keys have the format `grob_<32 hex chars>` (37 characters total).

### Creating a virtual key

Keep the administrative key out of agents. Create a scoped agent key, then use the emitted key as its bearer token:

```bash
grob key create --name coding-agent --tenant local --allowed-providers anthropic
grob key list
```

Use your configured provider name instead of `anthropic`. List and revoke keys with `grob key --help`; commands use the same `GROB_HOME` as the daemon. Virtual keys are accepted in `api_key` mode, not as JWTs. Each record contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID v4 | Unique identifier for management operations |
| `name` | string | Human-readable label (e.g., `"ci-pipeline"`) |
| `prefix` | string | First 12 characters of the key (for display) |
| `key_hash` | string | SHA-256 hex digest of the full key (stored, not the key itself) |
| `tenant_id` | string | Tenant this key belongs to |
| `budget_usd` | f64? | Optional per-key monthly budget in USD |
| `rate_limit_rps` | u32? | Optional per-key rate limit (overrides global) |
| `allowed_models` | string[]? | Optional allowlist of logical model names |
| `allowed_providers` | string[] | Provider allowlist; empty permits all providers |
| `created_at` | DateTime | Creation timestamp |
| `expires_at` | DateTime? | Optional expiration (requests rejected after this time) |
| `revoked` | bool | Whether the key has been revoked |
| `last_used_at` | DateTime? | Timestamp of most recent authenticated request |

### Authentication flow

1. Client sends `Authorization: Bearer grob_<hex>` or `x-api-key: grob_<hex>`.
2. Grob computes `SHA-256(key)` and looks up its encrypted hash-keyed record.
3. If found and not revoked/expired, the request proceeds with the key's tenant ID, budget, rate limit, and model allowlist applied.

### Storage

Virtual key records are stored as individually encrypted files (`~/.grob/vkeys/<hash>.json.enc`, AES-256-GCM). One hash-keyed file is authoritative for authentication and management; listing and operations by ID scan these records. Legacy secondary index files are ignored. See [Storage Reference](storage.md).

### Security properties

- The full key is never stored. Only the SHA-256 hash is persisted.
- Records are encrypted at rest with AES-256-GCM (same cipher as OAuth tokens).
- Revoked keys return an authentication error immediately.

## 5. OAuth (per-provider)

OAuth PKCE authentication for subscription-based providers. Configured per-provider, not globally.

```toml
[[providers]]
name = "claude-max"
provider_type = "anthropic"
auth_type = "oauth"
oauth_provider = "anthropic-max"   # matches provider_id in token store
models = []                      # legacy field; define routing with [[models.mappings]]
```

### Supported OAuth providers

| Provider | Config constructor | Client ID | Scopes |
|----------|--------------------|-----------|--------|
| Anthropic (Claude Pro/Max) | `OAuthConfig::anthropic()` | `9d1c250a-...` | `org:create_api_key user:profile user:inference` |
| Anthropic Console | `OAuthConfig::anthropic_console()` | Same | Same (different auth URL) |
| OpenAI (Codex CLI) | `OAuthConfig::openai_codex()` | `app_EMoamE...` | `openid profile email offline_access` |
| Google Gemini | `OAuthConfig::gemini()` | `681255809395-...` | `cloud-platform userinfo.email userinfo.profile` |

### PKCE flow

All providers use PKCE (Proof Key for Code Exchange) with SHA-256 challenge method:

1. **Generate**: Random 32-byte verifier, base64url-encoded. Challenge = `base64url(SHA-256(verifier))`.
2. **Authorize**: Redirect user to provider's auth URL with `code_challenge` and `code_challenge_method=S256`.
3. **Exchange**: POST authorization code + verifier to token endpoint. Provider verifies `SHA-256(verifier) == challenge`.
4. **Store**: Access token, refresh token, and expiration saved as encrypted files (`~/.grob/tokens/<id>.json.enc`, AES-256-GCM).

### Token lifecycle

| Event | Behavior |
|-------|----------|
| Token valid | Used as-is for provider requests |
| Token expires in < 5 minutes | Auto-refreshed before the next request (`needs_refresh()`) |
| Token expired | Refresh attempted; if refresh fails, re-authentication required |
| Refresh token rotated | New refresh token saved; old one discarded |

### API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/oauth/authorize` | POST | Returns authorization URL with PKCE challenge |
| `/api/oauth/exchange` | POST | Exchanges authorization code for tokens |
| `/api/oauth/tokens` | GET | Lists all stored OAuth tokens |
| `/api/oauth/tokens/refresh` | POST | Manually triggers token refresh |
| `/api/oauth/tokens/delete` | POST | Deletes a stored token |

### Token storage

OAuth tokens are stored as individually encrypted files in `~/.grob/tokens/<id>.json.enc` (AES-256-GCM). Each file is written atomically (write → fsync → rename) and has restricted permissions (`0600`). See [Storage Reference](storage.md).

### Provider-specific notes

**Anthropic**: Uses JSON-encoded token exchange requests (not form-encoded). The `state` parameter doubles as the PKCE verifier.

**OpenAI**: Uses a separate random hex `state` parameter (not the PKCE verifier). Includes `codex_cli_simplified_flow=true` and `originator=codex_cli_rs` query parameters.

**Gemini**: Requires `client_secret` (a public installed-app secret from the Gemini CLI). Uses `access_type=offline` and `prompt=consent` to obtain a refresh token. After initial authentication, `loadCodeAssist` must be called to obtain the Google Cloud project ID. Override credentials via `GEMINI_OAUTH_CLIENT_ID` / `GEMINI_OAUTH_CLIENT_SECRET` environment variables.

### Security notes

- Token files have restricted permissions (`0600` on Unix, owner-only DACL on Windows).
- PKCE prevents authorization code interception attacks.
- Token URLs are validated: a warning is emitted if a non-localhost endpoint uses plaintext HTTP.
- Sensitive data (codes, verifiers, token responses) is excluded from debug logs.
