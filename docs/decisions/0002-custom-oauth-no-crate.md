# ADR-0002: Custom OAuth implementation — no oauth2 crate

## Status

Accepted

## Context and Problem Statement

Grob needs OAuth 2.0 with PKCE for authenticating users against LLM provider APIs. Should we use the `oauth2` crate or implement the flow ourselves?

## Decision Drivers

- The `oauth2` crate pulls in heavy dependencies (reqwest features, openidconnect)
- We only need Authorization Code + PKCE, not the full OAuth2 spec
- Custom implementation keeps the dependency tree minimal
- Full control over token storage and refresh logic

## Considered Options

- `oauth2` crate (full-featured OAuth2 client)
- `openidconnect` crate (OIDC superset of OAuth2)
- Custom implementation with PKCE

## Decision Outcome

Chosen option: "Custom implementation with PKCE", because our needs are narrow (single flow, single grant type) and the implementation is straightforward (~200 lines). The `oauth2` crate would add significant dependency weight for features we don't use.

### Consequences

- Good, because minimal dependency footprint
- Good, because full control over token storage format and refresh timing
- Good, because easier to adapt to provider-specific quirks
- Bad, because we own the security surface — must be careful with PKCE verifier generation and token handling

### Confirmation

The OAuth flow is tested end-to-end via `grob connect`. PKCE verifier uses `rand::thread_rng()` for cryptographic randomness; on all supported platforms `thread_rng` is seeded from OS entropy (`getrandom`).
