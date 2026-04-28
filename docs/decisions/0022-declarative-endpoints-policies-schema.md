---
status: proposed
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0018, ADR-0019, ADR-0020, ADR-0021]
---

# ADR-0022: Declarative `[[endpoints]]` and `[[policies]]` — Routing Schema Rebuild

## Context and Problem Statement

The current routing schema mixes three concerns inside `~/.grob/config.toml`:

1. **`[[providers]]`** — physical inventory: which API endpoint is reachable, with what credentials.
2. **`[[models]]` with nested `mappings`** — virtual-name routing: priority-ordered list of (provider, actual_model) pairs per virtual name.
3. **`[[tiers]]`** — overrides: when a request matches a tier (max_tokens, file_patterns, keywords), the provider list inside that tier replaces the priority chain.

This was acceptable when grob had ~3 providers and 1 routing axis. With ADR-0018's nature-inspired routing direction (multi-axis: cost, region, capacity, latency, quota), the existing schema can't express:

- "Route to the cheapest endpoint that has remaining capacity in EU region this hour."
- "Prefer endpoints with `cost_out_per_mtok < 0.50`."
- "When session_id matches `enterprise-*`, only consider endpoints with SLA tags."
- "Skip endpoints whose monthly quota is at 90%."

ADR-0019 (EMA) and ADR-0020 (hedging) and ADR-0021 (Thompson) all bolt onto the existing schema with `[router]` sub-tables, but the underlying model — `[[providers]] × [[models]] × [[tiers]]` — is the wrong primitive set for richer policies.

The strategic question is: do we keep accreting `[router.X]` subsections to the existing schema, or do we cut over to a clean primitive set that scales?

This ADR argues for the cut-over **with a 10-version auto-migration deprecation period** to protect the security-prevails audience that adopts grob mid-cycle.

## Decision Drivers

- **No production users yet** at the time of writing, but the security-prevails audience (defense, banks, OIV) is a likely early adopter cohort. Their change-management boards reject mid-flight schema breakage. A 10-version deprecation window gives them time to validate.
- **Maintenance burden**: keeping the old schema running in parallel for 10 minor releases doubles test surface, but the cost is bounded by the auto-migration path — operators don't write the legacy schema; the parser auto-converts on read.
- **Future-proofing**: the new primitives must accommodate WireGuard mesh routing (ADR-0014), Sokolsky multi-plane (ADR-0017), and EU AI Act compliance gating without further rebuilds.
- **Composition**: policies need to compose with ADR-0019 (EMA gating), ADR-0020 (hedging). The new schema must expose hooks where those primitives plug in.

## Considered Options

1. **Hard cut-over** (no backward compat, removed immediately). Rejected: any security-prevails adopter mid-flight gets locked out. Even with a migration tool, their compliance review cycle is months.
2. **Auto-migration with 10-version deprecation period (chosen).** Both schemas parse for 10 minor releases. On startup, legacy configs are auto-converted in memory and the operator gets a deprecation warning pointing at the migration tool. After 10 minor releases, the legacy parser is removed and configs that haven't migrated fail fast at startup with a clear error.
3. **Indefinite co-existence.** Rejected: never gets the maintenance burden off the project. Test surface grows forever.
4. **Stay on the old schema, push hard on `[router.*]` extensions.** Rejected: this is the path that produced the current sprawl.

## Decision Outcome

**Chosen: 10-version auto-migration period.**

- Release N (next minor): both schemas parse. New schema is preferred internally; legacy is auto-converted in memory. Migration tool `grob preset migrate-legacy` available standalone.
- Releases N..N+9 (10 minor versions): legacy continues to auto-migrate. Each startup emits a single warn-level log line per legacy config, surfacing the operator-friendly migration command. Deprecation banner in `grob preset list`. Each release notes the remaining number of versions until removal.
- Release N+10: legacy parser removed. Configs still in legacy format fail at startup with an actionable error: "your config uses the deprecated <feature>; run `grob preset migrate-legacy <path>` (deprecation announced in v<N>, see ADR-0022)".

This gives security-prevails adopters ~12-18 calendar months (assuming monthly minor releases) to migrate, which fits typical compliance review cycles.

### New schema

```toml
# ── Inventory: each endpoint = one (provider × model × region × …) deployment

[[endpoints]]
id = "anthropic-sonnet-46-us"
provider = "anthropic"
provider_type = "anthropic"        # was at provider level; now per-endpoint
oauth_provider = "anthropic-max"   # OAuth identity, if applicable
model = "claude-sonnet-4-6"
region = "us-east"
cost_in_per_mtok  = 3.00
cost_out_per_mtok = 15.00
context_window    = 200000
max_output_tokens = 32000
quota_monthly_tokens = 0           # 0 = unlimited
tags = ["claude-code-allowed", "interactive"]
# Compliance metadata — optional, used by security-prevails policies + linter
[endpoints.compliance]
trust_zone = "us-public-tier-1"
jurisdiction = "US"
data_classification = "internal"
certifications = ["SOC2-Type-II", "ISO-27001:2025"]
provider_risk_score = 2
sub_processors = ["AWS-US-East", "Cloudflare"]

[[endpoints]]
id = "deepseek-v4-flash-or"
provider = "openrouter"
provider_type = "openrouter"
api_key = "$OPENROUTER_API_KEY"
model = "deepseek/deepseek-v4-flash"
region = "us-west"
cost_in_per_mtok  = 0.14
cost_out_per_mtok = 0.28
context_window    = 1048576
tags = ["budget", "long-context"]
# Same compliance block — note CN sub-processor disclosed
[endpoints.compliance]
trust_zone = "us-public-tier-3"
jurisdiction = "US"               # OpenRouter is US-incorporated
data_classification = "internal"
certifications = []
provider_risk_score = 4           # higher because routes through DeepSeek (CN-hosted weights)
sub_processors = ["DeepSeek-CN", "OpenRouter-US"]

# … etc. for every (provider, model) pair the operator wants reachable.

# ── Provider-level metadata kept (auth scoping, circuit breaker, base URL):

[[providers]]
name = "anthropic"
auth_type = "oauth"
oauth_provider = "anthropic-max"
[providers.circuit_breaker]
max_fails = 3
fail_duration = "60s"

[[providers]]
name = "openrouter"
api_key = "$OPENROUTER_API_KEY"
base_url = "https://openrouter.ai/api/v1"
pass_through = true

# ── Routing: when-then rules. First matching policy wins.

[[policies]]
name = "anthropic-claude-code-passthrough"
when = { request.system_prompt_contains = "You are Claude Code, Anthropic's official CLI" }
select = { from_tag = "claude-code-allowed" }
order_by = ["priority", "ema_score DESC"]

[[policies]]
name = "rust-files-go-anthropic"
when = { request.file_pattern = "*.rs", request.tokens_below = 16000 }
select = { provider_in = ["anthropic"] }
order_by = ["priority"]

[[policies]]
name = "trivial-cheap-anywhere"
when = { request.max_tokens_below = 500 }
select = { from_tag_any = ["budget"] }
order_by = ["cost_out_per_mtok ASC", "ema_score DESC"]

[[policies]]
name = "long-context"
when = { request.input_tokens_above = 100000 }
select = { context_window_above = 131072 }
order_by = ["context_window DESC", "cost_out_per_mtok ASC"]

[[policies]]
name = "default"
# No 'when' = match any request that didn't match above.
select = { from_tag_any = ["interactive"] }
order_by = ["priority", "ema_score DESC"]

# Compliance-gated policy example (security-prevails deployments)
[[policies]]
name = "secret-data-strict-eu"
when = { request.headers.x-data-classification = "secret" }
select = {
  compliance.jurisdiction = "FR",
  compliance.data_classification_above = "confidential",
  compliance.certifications_contain = "SecNumCloud-3.2",
  compliance.provider_risk_score_below = 3,
  compliance.sub_processors_subset_of = ["AWS-EU-Frankfurt", "OVH-Roubaix", "Scaleway-Paris"],
}
order_by = ["compliance.provider_risk_score ASC", "priority"]

# ── Routing semantics layer (refers to ADR-0019, ADR-0020):

[router]
adaptive_scoring = "ema"           # ADR-0019

# Per-policy hedging override:
[router.policies.long-context]
hedge_after_ms = 3000              # ADR-0020
copies = 2

# Strict compliance lint mode (security-prevails)
[router.compliance]
strict = true
# When strict = true, every policy's `select` clause must reference at
# least one field from the configurable required_fields list.
required_fields = ["jurisdiction", "data_classification", "certifications"]
```

### Routing decision flow (replaces all of `resolve_provider_mappings` + tier short-circuit)

```
1. Parse request → extract features (model_name, file_pattern, max_tokens, …)
2. Walk [[policies]] top-to-bottom. First whose `when` matches → use it.
3. Apply `select` to filter [[endpoints]] to a candidate set.
4. Apply `order_by` to sort the candidate set.
5. Apply ADR-0019 EMA gate (skip endpoints below threshold).
6. Apply ADR-0021 Thompson sampling (if enabled) within the sorted set.
7. Dispatch to chosen endpoint. ADR-0020 hedge timer starts in parallel.
```

### Migration tool

`grob preset migrate-legacy <input.toml> <output.toml>` converts a v0.36 config in-place:

- For each `[[providers]]` with `models = [...]` → emit one `[[endpoints]]` per (provider, model) pair, defaults filled from a knowledge base shipped in the binary.
- For each `[[models]]` priority chain → emit a `[[policies]]` with `when = { request.model_name = "..." }` and `select = { provider_in = [...] }` ordered by the original priorities.
- For each `[[tiers]]` → emit a `[[policies]]` block with the tier's matchers as `when`.
- `[endpoints.compliance]` blocks are NOT auto-populated (the legacy schema has no compliance metadata); migrated configs land with empty compliance blocks. The diff report calls this out so security-prevails ops can fill them in manually.
- Print a diff report at the end: which signals were preserved, which require manual review (especially compliance blocks).

### Compliance metadata

The `[endpoints.compliance]` block is optional and only consulted by:

1. Policies whose `select` clause references `compliance.*` fields.
2. Hedging logic in ADR-0020 (the `compliance_isolation` flag matches on `compliance.trust_zone` + `compliance.jurisdiction` + `compliance.data_classification`).
3. The `grob policy validate --strict` linter (when `[router.compliance] strict = true`).

Audiences who don't need compliance metadata (trading bots, solo dev, ultra-cheap tier) can omit the block entirely — endpoints without a compliance block are treated as having all-default values (effectively: matched only by tag-based or unstructured policies).

#### Field semantics

| Field | Type | Purpose |
|---|---|---|
| `trust_zone` | string | Free-form zone identifier scoped to the operator's compliance taxonomy. Examples: `"eu-classified-air-gapped"`, `"eu-public-tier-1"`, `"us-public"`. No global registry — each deployment defines its own. |
| `jurisdiction` | string | ISO 3166 alpha-2 country code or supranational alias (`"EU"`, `"US"`, `"FR"`, `"CN"`). Used to gate prompts by data-residency law. |
| `data_classification` | enum | One of `"public"` < `"internal"` < `"confidential"` < `"secret"`. Ordered comparison supported via `_above` / `_below` selectors in policies. |
| `certifications` | array of strings | Free-form certification labels held by the provider for THIS endpoint. Examples: `"SecNumCloud-3.2"`, `"ISO-27001:2025"`, `"FedRAMP-High"`, `"SOC2-Type-II"`. Comparison via `_contains` / `_subset_of`. |
| `provider_risk_score` | int 1-5 | Internal risk score: 1 = lowest risk (e.g. on-prem self-hosted), 5 = highest (e.g. shared multi-tenant offshore). Operator-defined, no global standard. Comparison via `_above` / `_below`. |
| `sub_processors` | array of strings | Disclosed sub-processors the endpoint flows data through. Examples: `"AWS-EU-Frankfurt"`, `"DeepSeek-CN"`. Comparison via `_subset_of` / `_disjoint_from`. |

#### Policy operators on compliance fields

| Operator | Example | Semantics |
|---|---|---|
| exact match | `compliance.jurisdiction = "FR"` | string equality |
| `_above` | `compliance.data_classification_above = "internal"` | ordered enum: `confidential` or `secret` matches |
| `_below` | `compliance.provider_risk_score_below = 3` | numeric comparison: 1 or 2 matches |
| `_contains` | `compliance.certifications_contain = "SecNumCloud-3.2"` | array contains element |
| `_contains_all` | `compliance.certifications_contain_all = ["SecNumCloud-3.2", "ISO-27001:2025"]` | array contains all listed |
| `_subset_of` | `compliance.sub_processors_subset_of = ["AWS-EU-Frankfurt", "OVH-Roubaix"]` | every entry in the field is in the list (i.e. no surprise sub-processors) |
| `_disjoint_from` | `compliance.sub_processors_disjoint_from = ["DeepSeek-CN", "Tencent-CN"]` | no overlap (i.e. forbidden sub-processors absent) |

#### Audit log integration

When a policy with compliance selectors fires, the audit log entry includes:

```json
{
  "event": "request_routed",
  "policy_matched": "secret-data-strict-eu",
  "endpoint_id": "anthropic-sonnet-46-eu-classified",
  "compliance_match": {
    "jurisdiction": "FR",
    "data_classification": "secret",
    "certifications_required": ["SecNumCloud-3.2"],
    "certifications_present": ["SecNumCloud-3.2", "ISO-27001:2025"],
    "provider_risk_score_required_below": 3,
    "provider_risk_score_actual": 1,
    "sub_processors_required_subset_of": ["AWS-EU-Frankfurt", "OVH-Roubaix"],
    "sub_processors_actual": ["OVH-Roubaix"]
  }
}
```

This gives compliance teams a per-request proof that the routing decision satisfied the declared policy at the time it fired.

### CHANGELOG entries (across the deprecation window)

**Release N (deprecation announcement)**:

```markdown
### Added

- **Routing schema** (ADR-0022): new `[[endpoints]]` and `[[policies]]`
  primitives ship as the preferred routing config. Both schemas parse;
  legacy is auto-converted in memory at startup.

### Deprecated

- The legacy `[[models]]`, `[[tiers]]`, and per-provider `models = [...]`
  syntax are deprecated. Auto-migration runs at startup with a warn-level
  log line. Removal scheduled for the 10th minor release after this one.
  Run `grob preset migrate-legacy ~/.grob/config.toml` to convert in place.
```

**Releases N+1..N+9 (intermediate, repeat the deprecation banner)**:

```markdown
### Deprecated (reminder)

- Legacy routing schema removal in **K minor releases** (where K = 9, 8, 7…).
  Migration tool: `grob preset migrate-legacy`. See ADR-0022.
```

**Release N+10 (removal)**:

```markdown
### BREAKING

- **Legacy routing schema removed** (ADR-0022, deprecated since release N).
  Configs still using `[[models]]` / `[[tiers]]` / `models = [...]` fail at
  startup with an actionable error. Migration tool unchanged:
  `grob preset migrate-legacy ~/.grob/config.toml`. Operators who ignored
  the 9 prior deprecation warnings: please open an issue with your config
  and we will prioritize your manual conversion.
```

### Positive Consequences

- **Schema scales to multi-axis routing**: cost, region, capacity, SLA, tag-based filtering all expressible without further schema changes.
- **Policies are first-class**: operators can read `config.toml` and immediately see what routes where without tracing `[[providers]]` × `[[models]]` × `[[tiers]]` interactions.
- **Composes cleanly with ADR-0019, ADR-0020**: each routing primitive plugs in at well-defined hook points.
- **No mid-flight rug-pull for security adopters**: 10-version auto-migration (~12-18 calendar months) covers compliance review cycles. New adopters can write the new schema directly; legacy adopters are nudged on every startup.
- **Migration tool removes the manual conversion burden** when an operator chooses to migrate (or finally must, at the removal release).

### Negative Consequences

- **Double schema in the parser** for 10 minor releases: increased test surface during the deprecation window. Mitigated by the auto-migration path being a single-direction transformation (legacy → new), not a bidirectional bridge.
- **Verbose configs**: a preset that ships ~30 endpoints across 5 providers grows from ~200 LoC TOML to ~400 LoC. Operators may ship leaner configs with policies that match by tag rather than enumerating all providers.
- **Mental shift**: ops teams familiar with priority chains must learn the policy DSL. Mitigated by docs (`docs/how-to/policies.md`, examples folder).
- **DSL design risk**: the `when`/`select`/`order_by` grammar is a new language. Bugs in the matcher (silent-no-match) are operationally severe. Mitigated by exhaustive matcher tests and a `grob policy validate <config.toml>` linter.
- **Removal-day risk**: at release N+10, configs that ignored 9 deprecation warnings still break. Mitigated by the actionable error message and the migration tool remaining available indefinitely after removal.

## Implementation Notes

- New module `src/routing/policy/` containing parsers, matchers, and dispatchers.
- Migration tool: `src/preset/migrate_legacy.rs`, exposed via `grob preset migrate-legacy`.
- Old code paths to remove: `src/server/helpers.rs::resolve_provider_mappings`, `src/routing/classify::tier_match`, the legacy `[[tiers]]` parser.
- The 7 shipped presets (`perf`, `ultra-cheap`, `eu-eco`, `eu-pro`, `eu-max`, `gdpr`, `eu-ai-act`) must be rewritten to the new schema as part of this PR.
- Snapshot tests in `tests/enterprise/preset_snapshot_test.rs` regenerate against the new schema.

## Validation

- All 7 shipped presets compile and pass their existing snapshot tests after the rewrite.
- Migration tool round-trip: take a legacy config, convert, parse, dispatch the same request → same endpoint chosen.
- DSL matcher: 50+ unit tests covering `when` clauses (model_name, file_pattern, max_tokens, input_tokens, system_prompt_contains, tag-based, etc.).
- Linter `grob policy validate` catches: typos in tag references, unreachable policies (later policy that can never match because earlier policy's `when` is a superset), endpoints referenced by no policy.

## Migration

10-version auto-migration window:

- **Release N** (announcement): both schemas parse. Legacy is auto-converted in memory at startup with a single warn-level log line per config. Migration tool `grob preset migrate-legacy` available standalone for operators who want to convert their on-disk config explicitly.
- **Releases N+1..N+9**: legacy parser remains, deprecation warning repeats with the remaining version count. Each release notes the count in the CHANGELOG.
- **Release N+10**: legacy parser removed. Configs still in legacy format fail at startup with an actionable error. The migration tool itself remains shipped indefinitely for late adopters who need to convert an old archived config.

Auto-migration behavior on legacy startup:

```
[WARN grob::config] Your config uses the deprecated [[models]] / [[tiers]] schema.
                    Auto-migrating to [[endpoints]] / [[policies]] in memory for this run.
                    Run `grob preset migrate-legacy ~/.grob/config.toml` to convert in place.
                    Legacy schema will be REMOVED in 9 minor releases (see ADR-0022).
```

After conversion in place, the warning ceases.

## Configurability principle

**Everything in this ADR is configurable in `~/.grob/config.toml`.** Schema fields, policy operators, compliance dimensions, lint rules, defaults — all are operator-tunable. The binary ships sensible defaults but never imposes a particular taxonomy or threshold. Operators write configs that fit their compliance regime, their workload, their cost model.

Specifically configurable per deployment:

- **Policy precedence**: first-match-wins is the default order. Operators can set `priority = N` per policy to break out of file order; ties resolved by file order.
- **`data_classification` levels**: the default 4-level enum (`public` < `internal` < `confidential` < `secret`) is just a default. Operators redefine via `[router.compliance.data_classification_levels]`:
  ```toml
  # Custom 6-level for intelligence community
  [router.compliance.data_classification_levels]
  levels = ["unclassified", "fouo", "confidential", "secret", "top_secret", "ts_sci"]
  ```
- **`required_fields` for strict-mode lint**: configurable per deployment. A French defense customer might set `["jurisdiction", "certifications", "sub_processors"]`; a US fintech `["data_classification", "certifications"]`.
- **Tag namespace**: free-form forever. No global registry.
- **`trust_zone` taxonomy**: free-form. See *Trust zone naming guidance* below for industry-aligned conventions, but every deployment defines its own.
- **Cost source of truth**: `cost_in_per_mtok` is statically declared in config and refreshed on operator-driven config edits. The binary does NOT auto-refresh from upstream pricing APIs (provider price volatility means automated refresh would surprise the operator's cost forecasts). If operators want to script their own refresh, they edit the config and hot-reload.

## Trust zone naming guidance

`compliance.trust_zone` is free-form, but unstructured strings hurt audit readability. The recommended convention, verified against existing industry frameworks, is **`<framework>-<tier-or-version>` in lower-case kebab-case**, with geographic strings reserved for when residency — not certification — is the controlling axis.

### Recommended labels (industry-aligned, verified 2026-04)

| Label | Framework | Semantics | Source |
|---|---|---|---|
| `fedramp-high` | FedRAMP PMO | Endpoint authorized at FedRAMP High baseline. Three-tier scheme: `fedramp-low`, `fedramp-moderate`, `fedramp-high`. | [fedramp.gov](https://www.fedramp.gov/understanding-baselines-and-impact-levels/) |
| `il5` (also `il2`, `il4`, `il6`) | DoD SRG | Controlled unclassified for national-security systems. Bare numeric tier is the canonical form. | [DoD Cloud Computing SRG v1r4](https://public.cyber.mil/dccs/dccs-documents/) |
| `secnumcloud-3.2` | ANSSI (France) | ANSSI-qualified at the named SecNumCloud reference version. Issuer + version pattern. | [cyber.gouv.fr](https://cyber.gouv.fr/secnumcloud-pour-les-fournisseurs-de-services-cloud) |
| `c5:2020` | BSI (Germany) | BSI Cloud Computing Compliance Criteria Catalogue, year-tagged. | [BSI Kriterienkatalog C5](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Empfehlungen-nach-Angriffszielen/Cloud-Computing/Kriterienkatalog-C5/kriterienkatalog-c5_node.html) |
| `eu-data-residency`, `eea-only`, `uk-adequacy`, `third-country-sccs` | GDPR Art. 28 | Residency boundary, paired with adequacy-style suffix when sub-processors cross borders. | [Art. 28 GDPR](https://gdpr-info.eu/art-28-gdpr/), [EU Adequacy Decisions](https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en) |
| `pci-cde`, `hipaa-phi`, `itar`, `ear-ccl` | Sector-specific | PCI Cardholder Data Environment, HIPAA Protected Health Info, defense export controls. Kebab-case, lower-case. | [PCI SSC](https://www.pcisecuritystandards.org/document_library/), [HHS HIPAA](https://www.hhs.gov/hipaa/), [PMDDTC ITAR](https://www.pmddtc.state.gov/ddtc_public/), [BIS EAR](https://www.bis.doc.gov/) |
| `azuregovernment`, `azurechina`, `azureusgovernmentdod` | Azure Sovereign Clouds | Microsoft sovereign cloud labels (used as Azure regions). | [Azure Government](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-welcome) |
| `dmz`, `restricted`, `prod-pci`, `staging` | Kubernetes / Istio convention | Short kebab-case zone tags. Common in NetworkPolicy `namespaceSelector` and Istio `AuthorizationPolicy` `from.source`. | [K8s NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/), [Istio AuthZ](https://istio.io/latest/docs/reference/config/security/authorization-policy/) |

### Labels to AVOID for `trust_zone`

- **EU AI Act risk tiers** (`high-risk`, `limited-risk`, etc.) describe MODEL risk, not endpoint trust zone. Belong in a future model-classification field, not here.
- **ISO 27001** is a certification, not a zone. Belongs in `certifications`, not in `trust_zone`.
- **Banking-regulator tags** (`finma-outsourced`, `nydfs-500`) are ad-hoc — no standard exists yet. Operator may use them, but consistency is on the operator, not on a published spec.

### Pure-geography vs framework labels

If the controlling axis is **certification or compliance posture**, use a framework label (`fedramp-high`, `secnumcloud-3.2`).

If the controlling axis is **physical residency** (where data sits), use a geographic label aligned with the cloud provider's region taxonomy (`eu-west-1`, `francecentral`, `europe-west1`).

Don't mix the two semantics in one string. If both matter, declare both: `trust_zone = "fedramp-high"` AND `region = "us-gov-west-1"`. The schema supports it.

The audit log surfaces the literal string, so **consistency within a single deployment matters more than global uniformity**.

## Open Questions

- **Cross-deployment audit interop**: if customer A and customer B share an audit aggregator (e.g. SIEM), divergent `trust_zone` taxonomies make cross-tenant queries painful. No fix from grob's side — this is a SIEM-integration concern. Documented for awareness.
- **Migration verify-corpus authoring**: who maintains `tests/migration_corpus/`? Initial seed from the 7 shipped presets; operators contributing custom configs they want covered should be encouraged. Process TBD before the announcement release.

## Audience-specific notes

### Trading bots

The new schema wins on three trading-specific axes:

- **Region-aware routing**: market data feeds in eu-west-1 can be paired with LLM endpoints in the same region via `select = { region = "eu-west-1" }`, eliminating a 80-100ms transatlantic round-trip on every strategy decision.
- **Capacity-aware routing**: declared `quota_monthly_tokens` per endpoint lets policies skip endpoints near saturation before they 429.
- **Cost-based fallback**: `order_by = ["cost_out_per_mtok ASC"]` for non-critical batch decisions, distinct from interactive-trading policies that order by latency.

Recommended trust setup: shipped trading-policy templates in `presets/trading.toml` once the schema is in place.

### Security-prevails customers (defense, banks, OIV)

The 10-version auto-migration window covers compliance review cycles. Mitigations baked into this ADR:

- **Both schemas valid for ~12-18 calendar months** (10 minor releases at typical monthly cadence). Security teams have multiple validation cycles to test the new schema in staging against existing policies before the legacy parser is removed.
- **Auto-migration is deterministic and verifiable** — the in-memory transformation must produce byte-identical routing decisions vs the legacy parser on a deterministic test corpus. CI gates this via a `grob preset migrate-legacy --verify` invocation that runs against a corpus stored at `tests/migration_corpus/`.
- **Audit-trail continuity**: requests previously logged under `tier=trivial` continue to log under `policy=trivial-cheapest-first` (or whatever the migrated policy name is). The migration tool emits a `routing_signal_mapping.toml` artifact that the audit-log post-processor uses to reconcile pre-migration and post-migration traffic in compliance reports.
- **Structured `[endpoints.compliance]` block** (instead of a single `trust_zone` field): every endpoint declares 5 compliance dimensions in a typed sub-table — see *Compliance metadata* below.
- **Compliance lint mode**: `grob policy validate --strict` rejects any policy whose `select` clause does not gate on at least one compliance field (the operator chooses which fields are mandatory via a configurable list; see *Compliance metadata*). Default off; enable in security-prevails deployments via `[router.compliance] strict = true`.
