---
status: proposed
date: 2026-06-07
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: []
---

# ADR-0027: Adopt OAuth Credentials from Co-installed CLIs

## Context and Problem Statement

grob authenticates to the ChatGPT Codex backend and to Anthropic with the
**same OAuth apps** as the official CLIs it sits in front of:

- Codex CLI / Codex.app — OpenAI client id `app_EMoamEEZ73f0CkXaXp7hrann`,
  token at `~/.codex/auth.json`.
- Claude Code — Anthropic client id `9d1c250a-e61b-44d9-88ed-5944d1962f5e`,
  token in the macOS keychain item `Claude Code-credentials`.

Both providers **rotate the `refresh_token` on every refresh**. When grob holds
its own copy of an account's token and the co-installed CLI (or another grob
restart) refreshes independently, each rotation invalidates the other holder's
refresh token. In practice this surfaces as a hard `401 token_invalidated`:
grob returns `authentication_error … revoked. Run: grob connect --force-reauth`,
and every client routed through grob stalls at once. Recovery required an
interactive browser re-auth even though a **valid token already existed on the
machine**, owned by the co-installed CLI.

## Decision Drivers

- Recover from refresh-token rotation without a browser round-trip.
- Never sign the operator out of their other tools as a side effect.
- Opt-in: the default daemon must not read other tools' credentials silently.

## Considered Options

1. **Status quo** — only `grob connect --force-reauth` (browser PKCE flow).
2. **One-shot import** — a CLI command that mirrors the co-installed CLI's token
   into grob's store once.
3. **Adopt + watch** — (2) plus the refresh daemon re-adopting automatically
   when grob's copy is revoked, behind a config toggle.

## Decision Outcome

Chosen option: **3, adopt + watch**, implemented in
[`src/auth/system_creds.rs`](../../src/auth/system_creds.rs) and the refresh
daemon.

- `grob connect <provider> --from-system` mirrors the system token into grob's
  encrypted store (reuses `TokenStore`/`GrobStore`), so no browser flow is
  needed when a valid token already exists locally.
- `[auth] adopt_from_system` (default `false`) enables the watch: on each
  refresh tick the daemon re-adopts a token flagged `needs_reauth`, and a
  terminal refresh failure (revoked token) is healed by re-adoption instead of
  marking it for manual re-auth.

### Refresh ownership (the key constraint)

Because refresh rotates the shared token, **exactly one process may refresh a
given account**. The safe rule differs per source and is encoded in
`system_creds::grob_may_refresh`:

- **Codex** — once adopted, the token is grob-private (Codex CLI through grob
  uses a placeholder key, not its OAuth). grob **may** refresh it. The operator
  must avoid a separate `codex login` / Codex.app refresh on the same account.
- **Claude** — the keychain item is shared by **every Claude Code session on the
  host**. grob therefore treats it as a **read-only mirror**: with the watch on,
  the daemon re-adopts (re-reads) the keychain instead of ever calling the
  OAuth refresh endpoint, so it can never rotate the credential Claude Code
  itself depends on. Claude Code owns the refresh.

### Consequences

- Good: revocation self-heals within one refresh tick (≤ 5 min) when the watch
  is on; no browser for routine recovery.
- Good: read-only Claude handling removes the "grob logged out all my Claude
  Code sessions" failure mode.
- Bad / limits: source readers are platform- and layout-specific (the Claude
  reader is macOS-keychain only; non-macOS returns a clear error). A Codex token
  adopted while Codex.app keeps refreshing the same account will still rotate
  out — the watch recovers it, but the underlying advice is "don't double-refresh
  one account."

## More Information

- Token shapes: Codex `access_token` is an RS256 JWT (its `exp` sets
  `expires_at`); Claude `expiresAt` is a millisecond Unix timestamp.
- Both client ids are the public installed-app ids the upstream CLIs ship, so
  the adopted tokens are interchangeable with grob's own OAuth flows.
