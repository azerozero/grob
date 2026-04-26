# auth

> OAuth flows, JWT validation, persistent token storage, and virtual API keys.

## Purpose

Handles every authentication concern: outbound OAuth (PKCE) for upstream
provider subscriptions (Anthropic Max, ChatGPT, Gemini), inbound JWT validation
for grob's own API surface, and virtual-key issuance for multi-tenant access
control. Uses a custom OAuth implementation (no `oauth2` crate, per ADR-0002).

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `OAuthClient`, `OAuthConfig`, `OAuthProviderType` | `oauth.rs` | `server::oauth_handlers`, `auto_flow` |
| `PKCEVerifier`, `AuthorizationUrl` | `oauth.rs` | `oauth_handlers`, device-code flow |
| `TokenStore` | `token_store.rs` | every provider, `server::AppState` |
| `OAuthToken` | `token_store.rs` | `storage::GrobStore`, refresh daemon |
| `JwtValidator`, `GrobClaims`, `JwtConfig`, `AuthError` | `jwt.rs` | `server::middleware::auth_middleware` |
| `VirtualKeyRecord`, `VirtualKeyContext` | `virtual_keys.rs` | auth middleware, `storage::GrobStore` |
| `virtual_keys::generate_key` | `virtual_keys.rs` | `commands::vkey`, RPC plane |
| `auto_flow` | `auto_flow.rs` | `commands::start` (best-effort credential setup) |
| `device_code` | `device_code.rs` | RFC 8628 headless OAuth |
| `refresh_daemon` | `refresh_daemon.rs` | background task spawned at startup |

## Owns

- Custom OAuth 2.0 + PKCE state machine (no third-party crate).
- JWT validation with caching (validator handles ECDSA / Ed25519 / HMAC).
- Virtual key generation (`grob_*` prefix), SHA-256 hashing, lookup context.
- Proactive token refresh daemon (refreshes before expiry to avoid 401s).
- Automatic startup credential discovery (`auto_flow.rs`).

## Depends on

- `storage::GrobStore` for encrypted persistence of tokens and virtual keys.
- `cli::config` for `[auth]` and `[[oauth_providers]]` configuration.
- `reqwest` for outbound OAuth HTTP, `jsonwebtoken` for JWT.

## Non-goals

- HTTP routing for OAuth callbacks (delegated to `server::oauth_handlers`).
- Persistent storage primitives (delegated to `storage/`).
- Rate limiting and audit logging (delegated to `security/`).

## Tests

- `tests/unit/jwt_cache_test.rs` covers JWT validation caching and key rotation.
- `tests/unit/setup_wizard_test.rs` covers `auto_flow` discovery paths.
- `#[cfg(test)] mod tests` inside `oauth.rs`, `virtual_keys.rs`, `token_store.rs` cover PKCE, key hashing, and store roundtrips.
- `tests/integration/security_test.rs` covers auth middleware end-to-end.

## Related ADRs

- [ADR-0002](../../docs/decisions/0002-custom-oauth-no-crate.md) — custom OAuth implementation rationale.
- [ADR-0006](../../docs/decisions/0006-policy-engine-encrypted-audit-hit-gateway.md) — virtual keys feed per-tenant policy evaluation.
- [ADR-0008](../../docs/decisions/0008-wizard-lifecycle.md) — `auto_flow` and the setup wizard contract.
- [ADR-0013](../../docs/decisions/0013-storage-files-no-redb.md) — encrypted file storage backs `TokenStore`.
