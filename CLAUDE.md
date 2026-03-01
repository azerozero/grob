# Grob Development Guidelines

## Architecture

Grob is a multi-provider LLM routing proxy written in Rust. It routes requests to Anthropic, OpenAI, Gemini, DeepSeek, Ollama, and other providers with automatic fallback and format translation.

### Key Architectural Decisions

- **Config is static at runtime**: The server loads TOML config on startup and does not reload until restart. The `/api/config` endpoints exist for programmatic access but require a server restart to take effect.
- **Provider abstraction**: All providers implement the `LlmProvider` trait (`src/providers/mod.rs`).
- **Routing**: Regex-based prompt rules in `src/router/mod.rs` classify requests into task types (thinking, web_search, background, default).
- **OAuth**: Custom implementation (no `oauth2` crate) with PKCE in `src/auth/oauth.rs`.
- **Spend tracking**: Persistent monthly spend in `~/.grob/spend.json` with budget enforcement.

### Module Layout

| Module | Purpose |
|--------|---------|
| `src/server/mod.rs` | Axum HTTP server, request handlers |
| `src/server/openai_compat.rs` | OpenAI `/v1/chat/completions` translation |
| `src/server/oauth_handlers.rs` | OAuth API endpoints |
| `src/providers/` | Provider implementations (Anthropic, OpenAI, Gemini, etc.) |
| `src/router/mod.rs` | Request routing engine |
| `src/cli/mod.rs` | Config structs and CLI argument parsing |
| `src/auth/` | OAuth client and token store |
| `src/features/token_pricing/` | Pricing, spend tracking, budget enforcement |
| `src/preset.rs` | Preset management system |

## Documentation Standards

### Doc Comment Conventions (RFC 505 + RFC 1574 + Microsoft M-DOC)

- Every public item gets a doc comment (`///` in Rust).
- Summary line: third person singular present indicative ("Returns", not "Return").
- Summary line max 15 words (M-DOC-FIRST-SENTENCE).
- Never start with "This function/method/struct...".
- Standard sections in order: `# Errors`, `# Panics`, `# Safety`, `# Examples`.
- Always use plural `# Examples` even for a single example.
- Examples use `?` for error handling, never `unwrap()`.
- Link related types with `[`TypeName`]` intra-doc link syntax.
- Module-level `//!` docs give a high-level summary; types document themselves fully.

### Inline Comment Conventions (Clean Code + Linux Kernel)

- `//` comments explain **WHY**, not WHAT.
- Tags: `// TODO:`, `// FIXME:`, `// HACK:`, `// NOTE:`, `// SAFETY:`.
- Tags are capitalized, followed by colon and space, sentence ends with period.
- `// TODO:` and `// FIXME:` should reference an issue number when one exists.
- `// SAFETY:` is mandatory before every `unsafe` block — explains why the code satisfies the safety contract.
- No commented-out code. Delete it; git has history.
- No closing brace comments (`} // end if`).

### External Documentation (Diátaxis Framework)

Every doc belongs to exactly one category. Do not mix types in one file.

| Folder | Type | Question Answered |
|--------|------|-------------------|
| `docs/tutorials/` | Tutorial | "How do I learn this?" |
| `docs/how-to/` | How-to | "How do I solve X?" |
| `docs/reference/` | Reference | "What are the exact details?" |
| `docs/explanation/` | Explanation | "Why does it work this way?" |
| `docs/decisions/` | ADR (MADR 4.0) | "Why was this decision made?" |

### What Goes Where

| Content | Location |
|---------|----------|
| API contract, usage, examples | `///` doc comments |
| Why this implementation approach | `//` inline comment |
| Safety justification for unsafe | `// SAFETY:` before unsafe block |
| Safety contract for callers | `# Safety` in doc comment |
| Architecture rationale | `docs/decisions/NNNN-*.md` (ADR) |
| How components interact | `docs/explanation/` |
| Setup procedures | `docs/tutorials/` or `docs/how-to/` |
| Config options | `docs/reference/` |
