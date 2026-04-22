# Cucumber Requirements Traceability Matrix

Mapping of cucumber feature files in `tests/cucumber/features/` to the
requirements they exercise. This RTM covers the BDD/scenario layer.
The lower-level e2e RTM lives in [`tests/e2e/RTM.md`](../e2e/RTM.md).

**Techniques**: EP = Equivalence Partitioning, BVA = Boundary Value
Analysis, NEG = Negative Testing, FI = Fault Injection, PW = Pairwise.

## Index

| Feature file | Requirement area | Technique | Risk |
|--------------|------------------|-----------|------|
| `audit.feature` | Audit log integrity and redaction | EP, NEG | Critical |
| `decision_token.feature` | Decision-token transparent routing (ADR-0016) | EP | High |
| `dlp_output.feature` | DLP scanning on provider responses | EP | High |
| `dlp_streaming.feature` | DLP across SSE chunk boundaries | EP, BVA | Critical |
| `failover.feature` | Provider failover via Toxiproxy | FI | Critical |
| `hit_scoring.feature` | HIT Gateway risk scoring for tool calls | EP | High |
| `install.feature` | CLI install and basic usage through proxy | EP | Medium |
| `multi_client.feature` | Multi-client tenant isolation + enforcement | EP, NEG | High |
| `pledge_dlp_combo.feature` | Pledge + DLP defense in depth | EP | High |
| `pledge_profiles.feature` | Pledge tool-visibility profiles (ADR-0009) | EP | High |
| `rpc_providers.feature` | JSON-RPC provider state namespace | EP | Medium |
| `sokolsky.feature` | Sokolsky log backend access control (ADR-0017) | EP, NEG | High |
| `spend_concurrent.feature` | Spend tracking under concurrent load | BVA | High |
| `trace_roundtrip.feature` | End-to-end request trace propagation | EP | Medium |
| `wizard.feature` | Setup/doctor wizard lifecycle (ADR-0008) | EP, NEG | Medium |

## Detailed mapping

### Audit and compliance

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-AUDIT-01 | Audit entries are written for every request | `audit.feature` | EP | Critical |
| C-AUDIT-02 | Audit entries are encrypted at rest | `audit.feature` | EP | Critical |
| C-AUDIT-03 | Audit content is redacted where policy demands | `audit.feature` | EP | High |

### Routing and decision tokens

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-ROUTE-01 | Decision tokens flow transparently through dispatch | `decision_token.feature` | EP | High |
| C-ROUTE-02 | Provider failover happens under injected latency/errors | `failover.feature` | FI | Critical |

### DLP

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-DLP-01 | DLP inspects provider responses | `dlp_output.feature` | EP | High |
| C-DLP-02 | DLP detects secrets split across SSE chunks | `dlp_streaming.feature` | EP, BVA | Critical |
| C-DLP-03 | Pledge + DLP combine without gap | `pledge_dlp_combo.feature` | EP | High |

### Pledge / capability restriction

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-PLEDGE-01 | Pledge profiles control tool visibility | `pledge_profiles.feature` | EP | High |
| C-PLEDGE-02 | Pledge + DLP defense-in-depth (see C-DLP-03) | `pledge_dlp_combo.feature` | EP | High |

### HIT Gateway

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-HIT-01 | HIT Gateway scores tool calls by risk | `hit_scoring.feature` | EP | High |

### Multi-tenant / isolation

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-MT-01 | Per-client policy is enforced across requests | `multi_client.feature` | EP | High |
| C-MT-02 | Cross-tenant data does not leak | `multi_client.feature` | NEG | Critical |

### Observability

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-OBS-01 | Trace context is preserved end-to-end | `trace_roundtrip.feature` | EP | Medium |
| C-OBS-02 | JSON-RPC provider namespace returns live state | `rpc_providers.feature` | EP | Medium |
| C-OBS-03 | Sokolsky log backend respects role + plane ACLs | `sokolsky.feature` | EP, NEG | High |

### Spend / budget

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-SPEND-01 | Spend tracker is consistent under concurrency | `spend_concurrent.feature` | BVA | High |

### Wizard lifecycle

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-WIZ-01 | Wizard collects choices, recaps, then writes atomically | `wizard.feature` | EP | Medium |
| C-WIZ-02 | Wizard refuses to overwrite on validation failure | `wizard.feature` | NEG | Medium |

### CLI packaging

| ID | Requirement | Feature file | Technique | Risk |
|----|-------------|--------------|-----------|------|
| C-CLI-01 | CLI install path and basic commands work through the proxy | `install.feature` | EP | Medium |

## Maintenance

- When a new `*.feature` file lands in `tests/cucumber/features/`, add a
  row to the index and a requirement entry in the appropriate section.
- When a feature is deleted, strike it from the index and mark the
  requirement row deprecated rather than deleting the row — this keeps
  the audit trail for compliance reviews.
- The CI will eventually enforce feature-to-RTM coverage; until then,
  reviewers should check this file in every PR that touches
  `tests/cucumber/features/`.
