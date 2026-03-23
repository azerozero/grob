# ADR-0006: Unified Policy Engine, Encrypted Audit Export, and HIT Gateway

## Status

Accepted

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

### 3. HIT Gateway — Per-Action Human Authorization

Grob implements the HIT Gateway role from RFC-0001 as a native policy section. The LLM cannot execute tools — it outputs `tool_use` JSON which the client (Claude Code, Aider) executes. Grob intercepts `tool_use` blocks in the LLM response stream **before** they reach the client.

**How interception works:**

```
LLM responds with tool_use → grob receives SSE chunks
    → grob detects tool_use block in response
    → policy engine evaluates: auto_approve / require_approval / deny
    → if require_approval: PAUSE stream (buffer SSE chunks)
        → notification to human (grob watch / webhook)
        → human approves → HIT signed → release stream
        → human denies → drop tool_use from response
    → if deny: drop tool_use, forward rest of response
    → receipt logged in audit chain
```

**Config (HIT section in unified policy):**

```toml
[[policies]]
name = "dev-standard"
match = { agent = "claude-code", user = "clement@*" }

[policies.hit]
auto_approve = ["Read", "Glob", "Grep", "LSP"]
require_approval = ["Edit", "Write", "Bash"]
deny = ["Bash(rm -rf*)", "Bash(curl*|sh)", "Write(*.env)", "Write(*.key)"]
auth_method = "yubikey"
flag_patterns = ["run this command", "paste.*terminal", "curl.*| sh", "sudo"]

[[policies]]
name = "trading"
match = { compliance = ["financial"], agent = "trading-bot" }

[policies.hit]
auto_approve = ["get_quote", "list_positions"]
require_approval = ["execute_trade"]
deny = ["execute_trade(amount_above=50000)", "transfer_funds", "delete_account"]
auth_method = "yubikey"

[[policies]]
name = "prod-infra"
match = { zone = "prod-*", compliance = ["pci-dss"] }

[policies.hit]
require_approval = ["Bash", "Write", "Edit"]
deny = ["Bash(kubectl delete*)", "Bash(docker rm*)"]
auth_method = "multisig"
required_signatures = 2
```

**Auth methods (configurable per policy):**

| auth_method | How | Security | Use case |
|-------------|-----|----------|----------|
| `prompt` | Text approval in `grob watch` (default) | Medium | Dev solo |
| `yubikey` | FIDO2 YubiKey hardware key (cross-platform) | High | Daily dev work |
| `yubikey` | FIDO2 hardware key touch | Very high | Financial, infra |
| `multisig` | N humans approve via webhook/watch | Maximum | Prod, high-value |
| `machine_key` | Automatic signature, no human | CI/CD only | Automated pipelines |
| `webhook` | POST to custom endpoint | Custom | Integration with approval systems |

**Per-action authorization token:**

```rust
pub struct HitAuthorization {
    pub request_id: String,
    pub tool_name: String,
    pub tool_input_hash: [u8; 32],  // SHA-256 of tool_use content
    pub decision: Decision,          // Approve | Deny
    pub auth_method: String,         // yubikey | multisig | openbao | ...
    pub signer: String,              // Who approved
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>,          // Ed25519 / ECDSA
}
```

Each authorization is an individual proof, hash-chained in the audit log.

**HIT Gateway mapping to existing grob infrastructure:**

| HIT Gateway function | Grob implementation | Status |
|---------------------|---------------------|--------|
| Scope validation | Policy engine `MatchRules` + `hit` section | New (this ADR) |
| Tool interception | SSE stream pause + tool_use detection | New (this ADR) |
| Auth methods | YubiKey / multisig / webhook / openbao | New (this ADR) + WI-8 |
| Credential injection | Provider API keys (agent never sees them) | Existing |
| Receipt chain | `src/security/audit_log.rs` hash-chained ECDSA/Ed25519 | Existing |
| Velocity controls | `src/security/rate_limit.rs` per-tenant token bucket | Existing |
| Budget circuit breaker | `src/features/token_pricing/` spend tracking | Existing |
| Risk scoring | DLP scan result (existing) + policy thresholds | Existing + new |

### 4. Cross-Referenced Risk Analysis

Every risk vector mapped to which grob layers cover it. If one layer misses, the next catches.

| Risk | DLP Req | DLP Resp | HIT gate | Policy | Audit | Covered |
|------|:-------:|:--------:|:--------:|:------:|:-----:|:-------:|
| Secret in prompt | REDACT | — | — | — | log | 2 layers |
| Secret in response | — | REDACT | — | — | log | 2 layers |
| PII in prompt | REDACT | — | — | — | log | 2 layers |
| Dangerous tool call | — | — | PAUSE/DENY | rules | receipt | 3 layers |
| Financial tool call | — | — | PAUSE+auth | budget | receipt | 3 layers |
| URL exfiltration (response) | — | BLOCK | — | — | log | 2 layers |
| URL exfiltration (tool_use) | — | — | PAUSE | deny pattern | receipt | 3 layers |
| Prompt injection (request) | BLOCK | — | — | — | log | 2 layers |
| Prompt injection (response) | — | DETECT | — | flag_patterns | log | 3 layers |
| Social engineering text | — | DETECT | — | flag_patterns | warn | 3 layers |
| Malicious generated code | — | REDACT secrets | PAUSE Write/Bash | deny patterns | log | 3 layers |
| Multi-turn context accumulation | REDACT (agent never sees real secrets) | — | — | — | log | Covered by DLP |
| DLP bypass (encoding) | SPRT entropy | SPRT entropy | — | — | log | 2 layers |
| Uninformed consent | — | — | consent display | auth_method | receipt | UX mitigation |
| Agent bypasses grob | — | — | — | — | — | Covered: agent has no API keys (credential injection) |
| Side-channel | — | — | — | — | — | Accepted: out of scope for HTTP proxy |

**Key insight**: The DLP makes context accumulation a non-issue. Secrets are redacted on the first turn — the agent only ever sees `[REDACTED]`. No session risk accumulator needed.

**Residual risks (accepted):**

| Risk | Why accepted |
|------|-------------|
| Malicious code logic (no secrets) | Human reviews code via HIT pause on Write/Bash. The diff is visible. |
| Uninformed consent | Auth methods like YubiKey force deliberate physical action. Consent display in grob watch shows clear summary. |
| Agent bypasses grob | Credential injection: the agent has no API keys without grob. No grob = no LLM access. |
| Side-channel | Theoretical. No HTTP proxy covers this. |

### 5. Request Context Population

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

### 6. Crate Dependencies

| Crate | Purpose | New? |
|-------|---------|------|
| `age` | Envelope encryption, multi-recipient, X25519 + ChaCha20-Poly1305 | Yes |
| `x25519-dalek` | Key wrapping (transitively via age) | Yes (transitive) |
| `ed25519-dalek` | Audit log signing | Already in tree |
| `globset` | Glob pattern matching for policy rules | Yes |

### 7. Performance Impact

| Operation | Latency | When |
|-----------|---------|------|
| Policy matching (evaluate N rules) | ~1-5 µs | Hot path (per request) |
| age encrypt 5 KB content, 4 recipients | ~200 µs | Async (post-response) |
| age encrypt 150 KB content, 4 recipients | ~210 µs | Async (post-response) |
| SSE stream pause (buffering) | 0 (memory only) | On tool_use detection |
| HIT auth verification | ~1 µs | On stream release |

Policy matching is on the hot path but is a simple glob match over ~10 fields — negligible. Encryption and stream buffering are async and do not affect response latency.

### 8. Implementation Phases

| Phase | Scope | Effort |
|-------|-------|--------|
| **P1** | Policy engine trait + TOML config + match evaluation | 3-4d |
| **P2** | Encrypted log export (age, access_policies, sinks) | 3-4d |
| **P3** | Wire existing features to policy engine (DLP, rate limit, routing, budget) | 2-3d |
| **P4** | HIT tool interception (SSE pause, auth methods, receipt signing) | 3-4d |
| **P5** | HIT quorum voting + multi-sig co-signing (future) | TBD |

### Consequences

- Good, because one config surface replaces six separate filter systems
- Good, because auditors get cryptographically scoped access to session content
- Good, because grob becomes the reference HIT Gateway implementation
- Good, because age encryption is async with zero hot-path impact
- Good, because DLP + HIT + credential injection provide defense-in-depth with no real gaps
- Bad, because policy resolution order adds complexity (most-specific-wins needs clear docs)
- Bad, because age adds a new dependency (~50 KB, pure Rust)
- Bad, because SSE stream pause adds buffering complexity to the streaming pipeline

### Confirmation

Implemented and verified:

- ✅ Unit tests: policy matching with overlapping rules, recipient resolution (`src/features/policies/matcher.rs`)
- ✅ Unit tests: tool_use detection in SSE stream — passthrough, auto-approve, deny, pause/release, machine_key, multisig, quorum, flag_patterns (`src/features/policies/stream.rs`)
- ✅ Unit tests: `HitAuthorization` hash chain and tamper detection (`src/features/policies/hit_auth.rs`)
- ✅ Unit tests: quorum strategy (majority, unanimous, timeout) (`src/features/policies/quorum.rs`)
- ✅ Unit tests: multisig collection (2-of-3, duplicate signer, broken chain, tamper) (`src/features/policies/multisig.rs`)
- ✅ `POST /api/hit/approve` endpoint wired — supports Simple, MultiSig, and Quorum entries
- ✅ Receipt logging: `HitAuthorization` written to audit chain after every approve/deny decision
- ✅ Tool input accumulation: all `input_json_delta` chunks buffered in `BufferingInput` state; receipts and deny-pattern evaluation use real tool input
- ✅ Deny arg-patterns work: `Bash(rm -rf*)` correctly evaluated against buffered input
- ✅ `tool_input_preview` populated in `HitApprovalRequest` events
- ✅ Integration test: end-to-end HIT flow — `tests/integration/hit_test.rs` (approve, deny, arg-pattern deny)
- ✅ Integration test: age encrypt → decrypt roundtrip — `src/features/log_export/encryption.rs` (single + multi-recipient, wrong-key rejection)
- ✅ CI: `cargo deny check` passes with age crate license (MIT/Apache-2.0)

Deferred / not yet implemented:
- ⏳ Benchmark: policy evaluation target < 10 µs for 20 rules (currently unverified)
- ⏳ TouchID / YubiKey biometric auth: types defined, falls back to `prompt` with a logged warning
- ⏳ True N-of-M multisig with cross-session persistence (currently in-memory per server restart)
