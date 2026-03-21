# Feature Matrix

Exhaustive list of grob capabilities, extracted from the codebase (v0.17.0+).

## Core Proxy

| Feature | Description | Config |
|---------|-------------|--------|
| Multi-provider failover | Priority-based provider chains with exponential backoff | `[[models.mappings]]` priority |
| Circuit breakers | Auto-disable unhealthy providers (Closed/Open/HalfOpen) | `[security] circuit_breaker = true` |
| Adaptive provider scoring | EWMA latency + rolling success rate ranks providers dynamically | `[security] adaptive_scoring = true` |
| Task classification routing | Intent-based: think, websearch, background, regex, default | `[router]` think/background/websearch |
| Prompt-based routing | Regex rules with capture groups route specific prompts | `[[router.prompt_rules]]` |
| Auto-mapping | Regex model name transformation (e.g., `^claude-` → default) | `[router] auto_map_regex` |
| Fan-out racing | Parallel dispatch: fastest, best_quality, or weighted selection | `strategy = "fan_out"` |
| Response caching | Dedup temperature=0 requests (moka LRU, configurable TTL) | `[cache] enabled = true` |
| Streaming SSE | Full SSE streaming for all endpoints and providers | Built-in |
| Tool calling | Function calling support across all providers | Built-in |
| GDPR routing | Region-based provider filtering (EU-only) | `[router] gdpr = true` |

## API Compatibility

| Endpoint | Format | Streaming | Tool Calling |
|----------|--------|-----------|-------------|
| `/v1/messages` | Anthropic native | Yes | Yes |
| `/v1/chat/completions` | OpenAI compatible | Yes | Yes |
| `/v1/responses` | OpenAI Responses API (Codex CLI) | Yes | Yes |
| `/v1/models` | OpenAI model listing | N/A | N/A |
| `/v1/messages/count_tokens` | Token counting | N/A | N/A |

## Providers (14+)

| Provider | Type | Auth Methods |
|----------|------|-------------|
| Anthropic | `anthropic` | API key, OAuth PKCE (Max/Pro) |
| OpenAI | `openai` | API key |
| Gemini | `gemini` | API key, OAuth PKCE (Pro) |
| Vertex AI | `vertex-ai` | Application Default Credentials |
| OpenRouter | `openrouter` | API key (200+ models) |
| Mistral | `openai` | API key (custom base_url) |
| Ollama | `openai` | None (local) |
| Groq | `openai` | API key |
| DeepSeek | `openai` | API key |
| Together | `openai` | API key |
| z.ai | `z.ai` | API key |
| MiniMax | `minimax` | API key |
| Kimi Coding | `kimi-coding` | API key |
| Zenmux | `zenmux` | API key |
| Any OpenAI-compatible | `openai` | API key + custom `base_url` |

## DLP (Data Loss Prevention)

| Scan Type | Description | Actions | Direction |
|-----------|-------------|---------|-----------|
| Secret scanning | API keys, tokens, PEM blocks, credentials (25 built-in rules + custom) | redact, block, warn | Request + Response |
| PII detection | Email, phone, credit card (Luhn), IBAN/BIC | redact, block, warn | Request + Response |
| Name pseudonymization | Reversible mapping (real names → consistent pseudonyms) | pseudonymize | Request (anonymize) / Response (de-anonymize) |
| Prompt injection | Pattern-based detection (custom + built-in) | block, warn | Request |
| URL exfiltration | Anti-EchoLeak: domain whitelist/blacklist filtering | block, warn | Response |
| Canary tokens | Watermark redacted secrets for leak traceability | inject | Request |
| Streaming DLP | Per-chunk SSE scanning with SPRT cross-boundary detection | redact, block | Streaming responses |
| Entropy detection | SPRT-based high-entropy content identification | flag | Streaming |

Additional DLP features:
- Per-session context (multi-turn conversation tracking)
- Hot-reloadable domain lists and rules
- Signed config verification (Merkle tree integrity)
- Homoglyph attack prevention (Unicode normalization)
- External rules files (TOML, hot-reloadable)

## Security

| Feature | Description | Config |
|---------|-------------|--------|
| Rate limiting | Per-tenant token bucket (RPS + burst) | `[security] rate_limit_rps` |
| Circuit breakers | Per-provider failure tracking (Closed/Open/HalfOpen) | `[security] circuit_breaker` |
| OWASP security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | `[security] security_headers` |
| Constant-time auth | Timing-attack-safe API key comparison (subtle crate) | Built-in |
| Credentials encryption | AES-256-GCM at rest for OAuth tokens and virtual keys | Automatic |
| Cross-platform permissions | Owner-only file permissions (Unix 0o600 + Windows DACL) | Automatic |
| SecretString wrapping | API keys wrapped in `secrecy::SecretString` — impossible to log accidentally | Built-in |
| CodeQL analysis | Automated security scanning (CI + local) | `.github/workflows/codeql.yml` |

## Regulatory Compliance

Grob maps its features to specific regulatory requirements. The table below shows which grob capability satisfies which article/control.

### EU AI Act

| Article | Requirement | Grob Feature | Config |
|---------|-------------|--------------|--------|
| **Art. 12** | Record-keeping (logging of AI system usage) | Signed audit log with model name, token counts, timestamps, hash chain | `[compliance] audit_model_name = true`, `audit_token_counts = true` |
| **Art. 14** | Human oversight (risk classification) | Per-request risk scoring with escalation webhook | `[compliance] risk_classification = true`, `escalation_webhook` |
| **Art. 15** | Accuracy, robustness, cybersecurity | Prompt injection detection, DLP, circuit breakers | `[dlp] injection = "block"` |
| **Art. 52** | Transparency obligations | `X-AI-Provider`, `X-AI-Model`, `X-AI-Generated` response headers | `[compliance] transparency_headers = true` |

**Preset**: `grob preset apply eu-ai-act` enables everything in one command.

### GDPR / RGPD

| Requirement | Grob Feature | Config |
|-------------|--------------|--------|
| Data minimization (Art. 5) | DLP redacts PII before it reaches the LLM provider | `[dlp] pii = "redact"` |
| Data residency (Art. 44-49) | GDPR routing mode restricts to EU-only providers | `[router] gdpr = true, region = "eu"` |
| Pseudonymization (Art. 4) | Name pseudonymization with reversible mapping | `[dlp] names = "pseudonymize"` |
| Right to erasure (Art. 17) | No PII stored — redacted before leaving the proxy | `[dlp] pii = "redact"` |
| Data breach notification (Art. 33) | Canary tokens detect data leaks | `[dlp] canary = true` |
| Audit trail (Art. 30) | Signed audit log with hash chain | `[security] audit_dir` |

**Preset**: `grob preset apply gdpr` enables EU-only routing + DLP.

### HDS / PCI DSS / SecNumCloud

| Control | Grob Feature | Code Reference |
|---------|--------------|----------------|
| Audit trail integrity | Hash-chained entries with ECDSA-P256 / Ed25519 / HMAC-SHA256 signatures | `src/security/audit_log.rs` |
| Merkle tree batch signing | Inclusion proofs for batch verification | `src/security/merkle.rs` |
| Access control | Per-tenant virtual keys with budget + rate limit + model allowlist | `src/auth/virtual_keys.rs` |
| Circuit breaker (PCA/PRA) | Provider availability with failure thresholds and auto-recovery | `src/security/circuit_breaker.rs` |
| Rate limiting | Per-tenant token bucket (NIS2 DoS protection) | `src/security/rate_limit.rs` |
| Data classification | Audit entry classification levels: NC, C1, C2, C3 | `src/security/audit_log.rs` |
| Credentials at rest | AES-256-GCM encryption for all stored secrets | `src/storage/encrypt.rs` |
| Key management | File-based key with owner-only permissions (cross-platform) | `src/auth/token_store.rs` |
| Security headers | OWASP-compliant HTTP response headers | `src/security/headers.rs` |

### SOC 2 / ISO 27001 / HIPAA

| Control area | Grob Feature | Status |
|-------------|--------------|--------|
| Access control | Virtual keys, JWT auth, rate limiting | Implemented |
| Audit logging | Signed, hash-chained, tamper-evident audit log | Implemented |
| Data protection | DLP (secrets, PII, injection), encryption at rest | Implemented |
| Availability | Circuit breakers, multi-provider failover, zero-downtime upgrades | Implemented |
| Monitoring | Prometheus, OpenTelemetry, live TUI, log export | Implemented |
| Incident response | Canary tokens, escalation webhooks, risk classification | Implemented |
| **Certification** | SOC 2 / ISO 27001 / HIPAA formal audits | **Not certified** (features are present, certification requires third-party audit) |

### NIS2 / DORA

| Requirement | Grob Feature |
|-------------|--------------|
| ICT risk management | Circuit breakers, adaptive provider scoring, spend budgets |
| Incident reporting | Signed audit log, escalation webhooks, canary tokens |
| Digital operational resilience | Multi-provider failover, zero-downtime upgrades, connection warmup |
| Third-party risk | Per-provider spend tracking, rate limiting, model allowlists |

### Compliance presets

| Preset | What it enables |
|--------|-----------------|
| `grob preset apply gdpr` | EU-only routing + DLP (PII redaction, pseudonymization) |
| `grob preset apply eu-ai-act` | GDPR + signed audit log + transparency headers + risk classification |

### What grob does NOT provide

| Item | Why |
|------|-----|
| SOC 2 / ISO 27001 / HIPAA certification | Requires third-party audit ($30-100k). Features are present, certification is a business process. |
| ANSSI qualification (SecNumCloud) | Requires dedicated infrastructure and audit. Grob can be deployed in a qualified environment. |
| Data residency guarantees | Grob filters providers by region tag, but does not control where providers process data. |
| End-to-end encryption | TLS to providers is standard HTTPS. Grob does not encrypt the LLM payload itself (the provider must see it to respond). |

### Implementation verification (audited 2026-03-18)

Every compliance claim was verified against the actual codebase:

| # | Feature | Status | Code Evidence |
|---|---------|--------|---------------|
| 1 | EU AI Act Art. 12 — record-keeping | Implemented | `audit_log.rs:122-130` model_name + tokens in signed entries |
| 2 | EU AI Act Art. 14 — risk scoring | Implemented | `risk.rs:20-30` scoring: injection=critical, blocked+PII=high |
| 3 | EU AI Act Art. 14 — escalation webhook | Implemented | `risk.rs:49-87` async POST to configured URL |
| 4 | EU AI Act Art. 15 — injection detection | Implemented | `prompt_injection.rs` 28 languages + anti-obfuscation |
| 5 | EU AI Act Art. 52 — transparency headers | Implemented | `middleware.rs:36-52` X-AI-Provider/Model/Generated |
| 6 | GDPR — region routing | Implemented | `helpers.rs` filters providers by region when `gdpr=true` |
| 7 | GDPR — PII redaction | Implemented | `pii.rs` credit cards (Luhn), IBANs (mod97), BICs |
| 8 | GDPR — name pseudonymization | Implemented | `names.rs` reversible HMAC-SHA256 mapping |
| 9 | GDPR — canary tokens | Implemented | `canary.rs` + `dfa.rs` canary injected on redaction |
| 10 | HDS/PCI — audit hash chain | Implemented | `audit_log.rs:344-374` SHA-256 chaining |
| 11 | HDS/PCI — classification NC/C1/C2/C3 | Implemented | `audit.rs` dynamic: injection=C3, PII=C2, DLP=C1, none=Nc |
| 12 | HDS/PCI — Merkle batch signing | Implemented | `merkle.rs` + `audit_log.rs:419-453` inclusion proofs |
| 13 | HDS/PCI — signing algorithms | Implemented | `audit_signer.rs` ECDSA-P256, Ed25519, HMAC-SHA256 |
| 14 | NIS2/DORA — escalation webhook | Implemented | Same as #3 |

## Authentication

| Method | Description | Config |
|--------|-------------|--------|
| None | No authentication (default) | `[auth] mode = "none"` |
| API key | Static key (Bearer or x-api-key header) | `[auth] mode = "api_key"` |
| JWT | RS256/HS256 with tenant extraction and JWKS refresh | `[auth] mode = "jwt"` |
| Virtual keys | Per-tenant keys with budget, rate limit, and model allowlist | `grob key create` |
| OAuth PKCE | Browser-based login for Anthropic Max, OpenAI, Gemini Pro | `auth_type = "oauth"` |

## Multi-Tenant Virtual Keys

| Feature | Description |
|---------|-------------|
| Key generation | `grob_` prefix + 32 hex chars, SHA-256 hashed at rest |
| Per-key budget | Monthly USD cap per virtual key |
| Per-key rate limit | RPS override per key |
| Model allowlist | Restrict accessible models per key |
| Key expiration | TTL in days |
| Revocation | Instant via `grob key revoke` |
| Tenant isolation | Spend tracking and rate limiting per tenant_id |

## Observability

| Feature | Description | Config |
|---------|-------------|--------|
| Prometheus metrics | `/metrics` endpoint (request count, latency, spend, cache stats) | Built-in |
| OpenTelemetry | OTLP trace export (gRPC) | `[otel] enabled = true` (feature `otel`) |
| Log export | Structured request logs to stdout, JSONL file, or HTTP webhook | `[log_export] enabled = true` |
| Live TUI | `grob watch` — real-time traffic inspector with DLP/fallback events | `grob watch` (feature `watch`) |
| SSE event stream | `GET /api/events` for programmatic monitoring | Built-in |
| Message tracing | Per-request trace IDs with structured logging | `[server.tracing] enabled = true` |
| Spend tracking | Persistent monthly spend per provider/model/tenant (redb) | Built-in |
| Budget alerts | Warning at configurable threshold (default 80%) | `[budget] warn_at_percent` |

## Operations

| Feature | Description |
|---------|-------------|
| Single binary | 6 MB container (`FROM scratch`), TLS bundled via rustls |
| Zero-downtime upgrades | SO_REUSEPORT + SIGUSR1 graceful drain |
| Native TLS + ACME | Built-in HTTPS with Let's Encrypt auto-certificates |
| Presets | One-command configuration (perf, medium, cheap, local, gdpr, eu-ai-act) |
| Setup wizard | Interactive first-run: tool selection, auth, compliance, budget |
| Config hot-reload | `POST /api/config/reload` — atomic swap without restart |
| Connection warmup | Pre-TLS handshake on startup for all providers |
| Record & replay | Capture live traffic → replay through mock backend |
| Health endpoints | `/health`, `/live`, `/ready` (Kubernetes-compatible) |
| Diagnostics | `grob doctor` — config, providers, storage, service checks |

## CLI Commands

| Command | Description |
|---------|-------------|
| `grob setup` | Interactive first-run wizard |
| `grob start [-d]` | Start server (foreground or detached) |
| `grob stop` | Stop server |
| `grob restart [-d]` | Restart server |
| `grob exec -- <cmd>` | Run command behind proxy (auto start/stop) |
| `grob watch` | Live TUI traffic inspector |
| `grob status` | Service status + spend summary |
| `grob spend` | Monthly spend breakdown by provider/model |
| `grob key create/list/revoke` | Virtual API key management |
| `grob validate` | Test all providers with real API calls |
| `grob doctor` | Diagnostic health checks |
| `grob preset list/apply/export` | Preset management |
| `grob connect [provider]` | Interactive credential setup |
| `grob env` | Environment variable status |
| `grob model` | Model and routing info |
| `grob init` | Create `.grob.toml` project config |
| `grob config-diff [target]` | Compare config vs preset |
| `grob upgrade` | Zero-downtime binary upgrade |
| `grob run` | Container mode (0.0.0.0, JSON logs, no PID) |
| `grob completions <shell>` | Generate shell completions |

## Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `dlp` | Yes | Data Loss Prevention |
| `oauth` | Yes | OAuth PKCE flows |
| `tap` | Yes | Webhook event emission |
| `compliance` | Yes | Signed audit logging |
| `mcp` | Yes | MCP tool matrix |
| `watch` | Yes | Live TUI dashboard |
| `tls` | No | TLS with rustls |
| `acme` | No | Let's Encrypt auto-certs |
| `otel` | No | OpenTelemetry export |
| `harness` | No | Record & replay testing |

## Architecture

- **Language**: Rust (tokio async runtime, axum HTTP framework)
- **Storage**: redb embedded KV store (no PostgreSQL, no Redis)
- **Allocator**: jemalloc (non-MSVC) for ~20% throughput improvement
- **Container**: 6 MB `FROM scratch`, rustls TLS bundled
- **Codebase**: ~29K lines of Rust, 520+ tests
- **Traits**: 7 core abstractions (DlpPipeline, RequestRouter, Tracer, SpendTracking, AuditWriter, EventTap, ProviderAvailability)
