# Authentication Reference

Complete configuration reference for Grob's five authentication methods: none, api_key, jwt, virtual_keys, and oauth.

Settings live under the `[auth]` section of `config.toml`, with OAuth configured per-provider in `[[providers]]`.

## Auth modes

```toml
[auth]
mode = "none"  # "none" | "api_key" | "jwt"
```

### Exempt endpoints

The following endpoints bypass authentication regardless of mode:

- `GET /health`
- `GET /metrics`
- `POST /api/oauth/*` (OAuth flow endpoints)

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
api_key = "$GROB_API_KEY"  # supports $ENV_VAR syntax
```

Clients authenticate via either header:
- `Authorization: Bearer <key>`
- `x-api-key: <key>`

### Security properties

- API key comparison uses **constant-time equality** (`subtle` crate) to prevent timing side-channel attacks.
- The `$ENV_VAR` syntax resolves environment variables at startup; the plaintext key is never stored in the config file on disk.
- The `/api/config` endpoint redacts API keys in its response.

### Edge cases

- If both `Authorization` and `x-api-key` headers are present, behavior is implementation-defined (check the middleware). Prefer using one consistently.
- An empty `api_key` value with `mode = "api_key"` will reject all requests since no key can match.

## 3. JWT

```toml
[auth]
mode = "jwt"

[auth.jwt]
hmac_secret = "$JWT_SECRET"           # HMAC-SHA256 secret (HS256)
jwks_url = "https://auth.example.com/.well-known/jwks.json"  # RS256 keys (optional)
jwks_refresh_interval = 3600          # seconds between JWKS refreshes (default: 3600)
issuer = "grob-auth"                  # expected `iss` claim (optional)
audience = "grob-proxy"               # expected `aud` claim (optional)
```

### Algorithm support

| Algorithm | Config field | Use case |
|-----------|-------------|----------|
| HS256 (HMAC-SHA256) | `hmac_secret` | Self-hosted, shared-secret setups |
| RS256 (RSA) | `jwks_url` | External identity providers (Auth0, Okta, etc.) |

When both are configured, Grob tries HMAC first, then falls back to JWKS keys.

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
| `exp` | Yes | Expiration time (UNIX timestamp). Tokens past expiration are rejected. |
| `iss` | No | Issuer. Validated against `auth.jwt.issuer` if configured. |
| `aud` | No | Audience. Validated against `auth.jwt.audience` if configured. If `audience` is not set in config, audience validation is disabled. |

### Tenant resolution

The effective tenant ID is determined by:
1. `tenant` claim if present.
2. `sub` claim otherwise.

This tenant ID is used for rate limiting, spend tracking, and audit logging.

### Validation cache

Validated tokens are cached in memory (keyed by `SHA-256(token)`, not the raw JWT) with a 5-minute TTL and a capacity of 10,000 entries. This avoids repeated cryptographic verification for the same token within the cache window.

### JWKS key rotation

When `jwks_url` is configured, Grob spawns a background task that refreshes the JWKS key set every `jwks_refresh_interval` seconds. Only RSA keys (`kty: "RSA"`) are loaded. The refresh is non-blocking and uses a 10-second HTTP timeout.

### Error responses

| Error | HTTP status | Condition |
|-------|-------------|-----------|
| Missing token | 401 | No `Authorization: Bearer` header |
| Invalid token | 401 | Signature mismatch, wrong issuer/audience |
| Expired token | 401 | `exp` claim is in the past |

## 4. Virtual keys

Virtual keys provide multi-tenant access control with per-key budget, rate limit, and model restrictions. Keys have the format `grob_<32 hex chars>` (37 characters total).

### Creating a virtual key

Virtual keys are managed via CLI or API. Each key record contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID v4 | Unique identifier for management operations |
| `name` | string | Human-readable label (e.g., `"ci-pipeline"`) |
| `prefix` | string | First 12 characters of the key (for display) |
| `key_hash` | string | SHA-256 hex digest of the full key (stored, not the key itself) |
| `tenant_id` | string | Tenant this key belongs to |
| `budget_usd` | f64? | Optional per-key monthly budget in USD |
| `rate_limit_rps` | u32? | Optional per-key rate limit (overrides global) |
| `allowed_models` | string[]? | Optional allowlist of model names |
| `created_at` | DateTime | Creation timestamp |
| `expires_at` | DateTime? | Optional expiration (requests rejected after this time) |
| `revoked` | bool | Whether the key has been revoked |
| `last_used_at` | DateTime? | Timestamp of most recent authenticated request |

### Authentication flow

1. Client sends `Authorization: Bearer grob_<hex>` or `x-api-key: grob_<hex>`.
2. Grob computes `SHA-256(key)` and looks up the hash in the `virtual_keys` table.
3. If found and not revoked/expired, the request proceeds with the key's tenant ID, budget, rate limit, and model allowlist applied.

### Storage

Virtual key records are stored as individually encrypted files (`~/.grob/vkeys/<hash>.json.enc`, AES-256-GCM) with two index strategies:
- **Primary**: keyed by SHA-256 hash (for O(1) authentication lookups).
- **Secondary**: keyed by `id:<uuid>` (for list/revoke/delete by ID).

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
