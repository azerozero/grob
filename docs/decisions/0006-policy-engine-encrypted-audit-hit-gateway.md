# ADR-0006: Unified Policy Engine, Encrypted Audit Export, and HIT Gateway

## Status

Proposed

## Context and Problem Statement

Grob currently applies DLP rules, rate limits, routing, and budgets through separate, globally-scoped configurations. Enterprises need per-tenant, per-zone, per-compliance policies with encrypted audit trails where different auditors can only decrypt sessions they are authorized to see. Additionally, the HIT protocol (RFC-0001) defines a cryptographic authorization framework for AI agents that maps directly onto grob's existing infrastructure.

## Decision Drivers

- Multi-tenant deployments need different security postures per establishment (hospital A vs hospital B)
- Compliance auditors must access only their scope (PCI auditor sees PCI sessions, not all traffic)
- Full request/response content must be exportable for audit without exposing it to unauthorized parties
- Grob already implements 70% of a HIT Gateway (audit chain, rate limiting, credential isolation, JWT auth)
- The policy matching logic (tenant, zone, project, user, agent, compliance) is duplicated across features

## Considered Options

- **Option A**: Per-feature filtering (each feature gets its own match config)
- **Option B**: Unified policy engine with envelope encryption and HIT Gateway integration
- **Option C**: External policy engine (OPA/Cedar) with grob as enforcement point

## Decision Outcome

Chosen option: "Option B — Unified policy engine with age encryption and native HIT Gateway", because it eliminates config duplication, reuses existing grob infrastructure, and positions grob as the reference HIT implementation.

## Design

### 1. Policy Engine (`src/features/policies/`)

A single `PolicyMatcher` evaluates request context against policy rules. One match can trigger multiple effects.

```rust
pub struct RequestContext {
    pub tenant: Option<String>,
    pub zone: Option<String>,
    pub project: Option<String>,
    pub user: Option<String>,
    pub agent: Option<String>,
    pub compliance: Vec<String>,
    pub model: String,
    pub provider: String,
    pub route_type: String,
    pub dlp_triggered: bool,
    pub estimated_cost: f64,
}

pub struct Policy {
    pub name: String,
    pub match_rules: MatchRules,
    pub dlp: Option<DlpOverride>,
    pub rate_limit: Option<RateLimitOverride>,
    pub routing: Option<RoutingOverride>,
    pub budget: Option<BudgetOverride>,
    pub log_export: Option<LogExportOverride>,
    pub hit: Option<HitOverride>,
}
```

Match rules support glob patterns and list membership:

```rust
pub struct MatchRules {
    pub tenant: Option<GlobPattern>,
    pub zone: Option<GlobPattern>,
    pub project: Option<GlobPattern>,
    pub user: Option<GlobPattern>,
    pub agent: Option<GlobPattern>,
    pub compliance: Option<Vec<String>>,  // ANY match
    pub model: Option<GlobPattern>,
    pub provider: Option<GlobPattern>,
    pub dlp_triggered: Option<bool>,
    pub cost_above: Option<f64>,
    pub route_type: Option<String>,
}
```

Multiple policies can match a single request. Resolution: most-specific wins (most non-None fields). For conflicting values: most-restrictive wins (lowest rate limit, strictest DLP action, union of recipients).

### 2. Encrypted Audit Export

Full request/response content encrypted with age (envelope encryption, multi-recipient).

**Config:**

```toml
[log_export]
enabled = true
content = "encrypted"       # "none" | "plaintext" | "encrypted"

[log_export.auditors]
rssi = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
dpo = "age1xz2a5lnzmgk4qp3gqq5hre5r5m4lzg0sytwfkhjsspxe2s0a6fqnzlt7u"
pci-auditor = "age1yr5t0nplnzxcusqv4qlhm06d2kfr3hph8l5nwgvfx3daenqz5gysx4w57l"

[[log_export.access_policies]]
name = "healthcare-paris"
match = { tenant = "hospital-paris", compliance = ["gdpr", "hds"] }
recipients = ["rssi", "dpo"]

[[log_export.access_policies]]
name = "pci-scope"
match = { compliance = ["pci-dss"] }
recipients = ["rssi", "pci-auditor"]

[[log_export.access_policies]]
name = "security-incidents"
match = { dlp_triggered = true }
recipients = ["rssi"]

[[log_export.access_policies]]
name = "default"
match = {}
recipients = ["rssi"]
```

**Output format (JSONL to Splunk/SIEM):**

```json
{
  "request_id": "req_abc123",
  "timestamp": "2026-03-21T14:00:00Z",
  "model": "claude-sonnet-4-6",
  "provider": "anthropic",
  "tenant": "hospital-paris",
  "zone": "eu-west",
  "compliance": ["gdpr", "hds"],
  "input_tokens": 1200,
  "output_tokens": 800,
  "latency_ms": 1400,
  "cost_usd": 0.02,
  "status": "success",
  "dlp_actions": ["secret_redacted"],
  "content_recipients": ["rssi", "dpo"],
  "encrypted_content": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUx..."
}
```

Metadata stays in cleartext (indexable by Splunk). Content is an age-encrypted blob containing the full prompt + response. Only the listed recipients can decrypt it.

**Encryption flow (async, post-response):**

```
Request completes
    → Build LogEntry (metadata + content)
    → Evaluate access_policies → matched recipients = {rssi, dpo}
    → DEK = random 128-bit file key
    → Encrypt content with ChaCha20-Poly1305 (DEK)
    → Wrap DEK with X25519 for each recipient (2 stanzas)
    → age blob = header (2 stanzas + HMAC) + encrypted payload
    → Base64 encode → encrypted_content field
    → Emit to sinks (stdout, file, HTTP)
```

### 3. HIT Gateway Integration

Grob implements the HIT Gateway role from RFC-0001. Mapping:

| HIT Gateway function | Grob implementation |
|---------------------|---------------------|
| Signature verification | `src/auth/` JWT RS256/HS256 validation |
| Scope validation | Policy engine `MatchRules` |
| Risk scoring | DLP scan result + policy cost thresholds |
| Credential injection | Provider API keys (never in logs, never in prompts) |
| Receipt chain | `src/security/audit_log.rs` hash-chained ECDSA/Ed25519 |
| Velocity controls | `src/security/rate_limit.rs` per-tenant token bucket |
| Budget circuit breaker | `src/features/token_pricing/` spend tracking |

**HIT-specific additions:**

```toml
[[policies]]
name = "hit-high-risk"
match = { cost_above = 1.0, agent = "claude-code" }

[policies.hit]
require_quorum_above = 0.5
require_human_above = 0.8
max_risk = 0.9
```

The quorum voting and multi-sig co-signing from HIT RFC-0001 are deferred to a later phase. Phase 1 implements scope validation + risk scoring + receipt chain (already built).

### 4. Request Context Population

Where each field comes from:

| Field | Source |
|-------|--------|
| `tenant` | Virtual key tenant_id or JWT `tenant` claim |
| `zone` | Provider region tag from config |
| `project` | `X-Grob-Project` header or `.grob.toml` project name |
| `user` | JWT `sub` claim or virtual key owner |
| `agent` | `User-Agent` header or `X-Grob-Agent` header |
| `compliance` | Preset tags or explicit `compliance = [...]` in config |
| `model` | Requested model name |
| `provider` | Provider selected by router |
| `route_type` | Router classification (thinking, web_search, background, default) |
| `dlp_triggered` | DLP pipeline result |
| `estimated_cost` | Token pricing estimate |

### 5. Crate Dependencies

| Crate | Purpose | New? |
|-------|---------|------|
| `age` | Envelope encryption, multi-recipient, X25519 + ChaCha20-Poly1305 | Yes |
| `x25519-dalek` | Key wrapping (transitively via age) | Yes (transitive) |
| `ed25519-dalek` | Audit log signing | Already in tree |
| `glob` or `globset` | Pattern matching for policy rules | Yes |

### 6. Performance Impact

| Operation | Latency | When |
|-----------|---------|------|
| Policy matching (evaluate N rules) | ~1-5 µs | Hot path (per request) |
| age encrypt 5 KB content, 4 recipients | ~200 µs | Async (post-response) |
| age encrypt 150 KB content, 4 recipients | ~210 µs | Async (post-response) |

Policy matching is on the hot path but is a simple glob match over ~10 fields — negligible. Encryption is async and does not affect response latency.

### 7. Implementation Phases

| Phase | Scope | Effort |
|-------|-------|--------|
| **P1** | Policy engine trait + TOML config + match evaluation | 3-4d |
| **P2** | Encrypted log export (age, access_policies, sinks) | 3-4d |
| **P3** | Wire existing features to policy engine (DLP, rate limit, routing, budget) | 2-3d |
| **P4** | HIT scope validation + risk scoring integration | 2-3d |
| **P5** | HIT quorum voting + multi-sig (future) | TBD |

### Consequences

- Good, because one config surface replaces six separate filter systems
- Good, because auditors get cryptographically scoped access to session content
- Good, because grob becomes the reference HIT Gateway implementation
- Good, because age encryption is async with zero hot-path impact
- Bad, because policy resolution order adds complexity (most-specific-wins needs clear docs)
- Bad, because age adds a new dependency (~50 KB, pure Rust)

### Confirmation

- Unit tests: policy matching with overlapping rules, recipient resolution
- Integration test: encrypt → decrypt roundtrip with age CLI
- CI: `cargo deny check` passes with age crate license (MIT/Apache-2.0)
- Benchmark: policy evaluation < 10 µs for 20 rules
