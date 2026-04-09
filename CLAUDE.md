# Grob Development Guidelines

## Architecture

Grob is a multi-provider LLM routing proxy written in Rust. It routes requests to Anthropic, OpenAI, Gemini, DeepSeek, Ollama, and other providers with automatic fallback and format translation.

### Distribution

- **Binary only** — grob is distributed as a standalone binary, NOT as a crate on crates.io.
- **crates.io/crates/grob is a different project** (Coding-Badly/grob, "Growable buffer for Windows API"). Do not confuse or reference it.
- Container image: `ghcr.io/azerozero/grob:<version>` (scratch, ~6MB)
- Releases: GitHub Releases via release-plz (auto-bumps version on develop push)
- Install: `brew install azerozero/tap/grob` or `curl -fsSL https://grob.sh | sh`

### Key Architectural Decisions

- **Config is static at runtime**: The server loads TOML config on startup. The `/api/config/reload` endpoint atomically swaps reloadable state (router, provider registry, model index) without restart. In-flight requests continue on the old snapshot.
- **Provider abstraction**: All providers implement the `LlmProvider` trait (`src/providers/mod.rs`).
- **Routing**: Regex-based prompt rules in `src/router/mod.rs` classify requests into task types (thinking, web_search, background, default).
- **OAuth**: Custom implementation (no `oauth2` crate) with PKCE in `src/auth/oauth.rs`.
- **Spend tracking**: Persistent monthly spend in redb (`~/.grob/grob.db`) with budget enforcement.

### Module Layout

| Module | Purpose |
|--------|---------|
| `src/server/mod.rs` | Axum HTTP server, middleware stack, application state |
| `src/server/dispatch/mod.rs` | Core dispatch pipeline: DLP, cache, route, provider loop |
| `src/server/openai_compat/` | OpenAI `/v1/chat/completions` translation |
| `src/server/responses_compat/` | OpenAI Responses API (`/v1/responses`) translation (Codex CLI) |
| `src/server/oauth_handlers.rs` | OAuth API endpoints |
| `src/server/fan_out.rs` | Parallel multi-provider dispatch (fan-out strategy) |
| `src/providers/` | Provider implementations (Anthropic, OpenAI, Gemini, etc.) |
| `src/providers/registry.rs` | Provider registration and model lookup |
| `src/router/mod.rs` | Request routing engine |
| `src/cli/mod.rs` | Config structs and CLI argument parsing |
| `src/cli/args.rs` | CLI command definitions (clap derive) |
| `src/cli/config.rs` | All config struct definitions |
| `src/commands/` | CLI command implementations (start, stop, exec, doctor, etc.) |
| `src/auth/` | OAuth client, token store, JWT validation |
| `src/features/token_pricing/` | Pricing, spend tracking, budget enforcement |
| `src/features/dlp/` | DLP engine (secret scanning, PII, canary tokens) |
| `src/features/mcp/` | MCP tool matrix, JSON-RPC server |
| `src/commands/bench/` | Self-contained bench engine (scenarios, mock, stats, output) |
| `src/features/policies/` | Unified policy engine, HIT Gateway, per-action authorization |
| `src/features/tap/` | Webhook tap (event emission) |
| `src/features/harness/` | Record & replay sandwich testing (opt-in `harness` feature) |
| `src/security/` | Circuit breakers, rate limiting, audit log, headers, scoring |
| `src/traits.rs` | Core trait contracts (7+ traits for dispatch pipeline) |
| `src/storage/` | Unified redb storage backend (GrobStore) |
| `src/preset/` | Preset management system |
| `src/auth/auto_flow.rs` | Automatic credential setup at startup |
| `src/features/tool_layer/` | Tool-calling abstraction layer |
| `src/features/pledge/` | Pledge-based capability restrictions |
| `src/server/watch_sse.rs` | Live traffic inspector SSE backend |

## Local Setup

After cloning, install the pre-commit hooks managed by [prek](https://github.com/j178/prek):

```bash
prek install
```

This activates `cargo fmt`, `clippy`, and `gitleaks` on every commit, and heavier checks (tests, audit) on push. Configuration lives in `prek.toml`.

If `prek` is not installed:

```bash
brew install j178/tap/prek   # macOS / Linuxbrew
# or: cargo install prek
# or: curl -fsSL https://prek.sh | sh
```

## Git Flow & CI/CD

### Branching Model

```
feature/* ──► develop ──► (release-plz PR) ──► main ──► tag v*
```

1. **Feature branches**: Create from `develop`, name `feature/<topic>` or `fix/<topic>`. PR targets `develop`.
2. **`develop`**: Integration branch. Every push triggers the full CI pipeline (lint, test, mutation testing).
3. **Release**: When CI passes on `develop`, release-plz automatically opens a PR to `main` (version bump, changelog, git tag).
4. **`main`**: Production branch. Only receives merges from release-plz PRs. Tag push (`v*`) triggers cross-builds, container image, and Homebrew formula update.

### Critical Rules

- **Never commit or push directly to `main`**. All changes go through `develop` or feature branches.
- **Never create a PR with `develop` as the head branch targeting `main`**. Only release-plz creates PRs to `main` (via temporary `release-plz-*` branches). Creating a manual PR from `develop` to `main` risks `develop` being deleted by GitHub's auto-delete-head-branch setting.
- **Both `main` and `develop` are protected** by GitHub rulesets (no deletion, no force push).
- **Conventional commits required**: `feat:`, `fix:`, `refactor:`, `perf:` with scopes trigger release-plz version bumps. Use `chore:`, `docs:`, `test:`, `style:` for non-release changes.
- **release-plz `release_commits` filter**: only `feat|fix|refactor|perf` with allowed scopes (`auth`, `cache`, `server`, `dispatch`, `providers`, `router`, `dlp`, `security`, `storage`, `preset`, `cli`, `commands`, `compat`) or no scope trigger a version bump.

### CI Pipeline Stages (`.github/workflows/ci.yml`)

| Stage | Trigger | Jobs |
|-------|---------|------|
| Quality gates | push to `develop` / PR | fmt, clippy, doc, actionlint |
| Tests | push to `develop` / PR | unit tests (Ubuntu + macOS + Windows), integration tests |
| Mutation testing | push to `develop` only | cargo-mutants on critical paths (router, DLP) |
| Cross-build | push to `develop` + tag push | Multi-target binaries (Linux amd64/arm64/musl, macOS, Windows) |
| Release | tag `v*` push | GitHub Release, container image, Homebrew formula |

### Release Flow (`.github/workflows/release-plz.yml`)

- Triggered by push to `develop` (only `src/**`, `Cargo.toml`, `Cargo.lock`).
- release-plz creates a PR to `main` with version bump + changelog + git tag.
- Merging the PR pushes the tag, which triggers the full release pipeline.

## Local Setup

After cloning, install the pre-commit hooks managed by [prek](https://github.com/j178/prek):

```bash
prek install
```

This activates `cargo fmt`, `clippy`, and `gitleaks` on every commit, and heavier checks (tests, audit) on push. Configuration lives in `prek.toml`.

If `prek` is not installed:

```bash
brew install j178/tap/prek   # macOS / Linuxbrew
# or: cargo install prek
# or: curl -fsSL https://prek.sh | sh
```

## Git Flow & CI/CD

### Branching Model

```
feature/* ──► develop ──► (release-plz PR) ──► main ──► tag v*
```

1. **Feature branches**: Create from `develop`, name `feature/<topic>` or `fix/<topic>`. PR targets `develop`.
2. **`develop`**: Integration branch. Every push triggers the full CI pipeline (lint, test, mutation testing).
3. **Release**: When CI passes on `develop`, release-plz automatically opens a PR to `main` (version bump, changelog, git tag).
4. **`main`**: Production branch. Only receives merges from release-plz PRs. Tag push (`v*`) triggers cross-builds, container image, and Homebrew formula update.

### CI Pipeline Stages (`.github/workflows/ci.yml`)

| Stage | Trigger | Jobs |
|-------|---------|------|
| Quality gates | push to `develop` / PR | fmt, clippy, doc, shellcheck, actionlint |
| Tests | push to `develop` / PR | unit tests (Ubuntu + macOS + Windows), integration tests |
| Mutation testing | push to `develop` only | cargo-mutants on critical paths (router, DLP) |
| Cross-build | push to `develop` + tag push | Multi-target binaries (Linux amd64/arm64/musl, macOS, Windows) |
| Release | tag `v*` push | GitHub Release, container image, Homebrew formula |

### Release Flow (`.github/workflows/release-plz.yml`)

- Triggered by push to `develop` (only `src/**`, `Cargo.toml`, `Cargo.lock`).
- release-plz creates a PR to `main` with version bump + changelog + git tag.
- Merging the PR pushes the tag, which triggers the full release pipeline.

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
