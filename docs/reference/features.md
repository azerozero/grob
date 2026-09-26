# Feature Matrix

Use this page to find a capability and its setup guide. Features can require
configuration or an optional build flag; their presence does not mean they are
active in your deployment. The current source version is in
[`Cargo.toml`](../../Cargo.toml).

## Core Proxy

| Capability | What it does | Setup and limits |
|------------|--------------|------------------|
| Routing | Select a logical model using configured rules and complexity tiers | [Routing order](routing.md) |
| Provider fallback | Try the model's configured providers in priority order | [Add a fallback](../how-to/configure.md#add-a-fallback-provider) |
| Circuit breakers | Temporarily skip a provider after repeated failures | [Security reference](security.md) |
| Adaptive scoring | Rank providers using observed latency and success | [Scoring configuration](configuration.md#security); opt-in, scores are not persisted |
| Context-window guard | Estimate request size before dispatch and return compact hints | [Error reference](errors.md#context_length_exceeded-400) |
| Response cache | Reuse eligible non-streaming responses | [Caching conditions](caching.md) |
| Fan-out | Send to several providers and select a response | [Selection and accounting limits](fan-out.md) |
| Region filtering | Filter provider mappings by configured region labels | [GDPR mode](routing.md#gdpr-region-filtering); `global` is an exception, labels do not prove residency |

## API Compatibility

| Client format | Endpoint | Details |
|---------------|----------|---------|
| Anthropic Messages | `/v1/messages` | [Compatibility](api-compatibility.md) |
| OpenAI Chat Completions | `/v1/chat/completions` | [Compatibility](api-compatibility.md) |
| OpenAI Responses | `/v1/responses` | [Compatibility](api-compatibility.md) |

Streaming and tool support depend on the provider and translated fields. Read the
[protocol fidelity matrix](protocol-fidelity.md) for preserved, translated and
unsupported behavior, and [conformance](conformance.md) for tested combinations.
Other HTTP endpoints are described in the [OpenAPI spec](../openapi.yaml).

## Providers

Anthropic, OpenAI, Gemini, Vertex AI, OpenRouter and other backends have
[setup recipes](../how-to/providers.md). An OpenAI-compatible service can use a
custom `base_url`. Provider credentials, supported models and account access
remain provider-specific; Grob does not grant a subscription or model entitlement.

## DLP (Data Loss Prevention)

| Protection | Scope | Guide |
|------------|-------|-------|
| Secret rules | Built-in and custom credential patterns | [Secret scanning](../how-to/dlp.md#how-to-enable-basic-secret-scanning) |
| Financial identifiers | Credit cards, IBAN and BIC detection | [PII configuration](../how-to/dlp.md#how-to-detect-pii-in-financial-data) |
| Configured names | Replace listed names with reversible pseudonyms | [Name rules](../how-to/dlp.md#how-to-anonymize-names) |
| Prompt injection | Pattern detection on configured input/output paths | [Injection controls](dlp-indirect-injection.md) |
| URL filtering | Detect response URLs outside the configured domain policy | [URL exfiltration](../how-to/dlp.md#how-to-prevent-url-exfiltration) |
| Canary tokens | Replace selected secrets with traceable fake values | [Custom rules](../how-to/dlp.md#how-to-add-custom-secret-rules) |
| Streaming scanning | Inspect response chunks with cross-chunk state | [DLP reference](dlp.md) |

DLP must be enabled. It detects supported patterns; it is not a guarantee that
all personal data, secrets or injection attempts are removed. Generic email and
phone detection is not provided by the financial-identifier scanner.

## Policy Engine

[Policies](../explanation/policies.md) apply configured rules to tenants, tools
and providers. The human-in-the-loop (HIT) gateway can require approval or deny
matched tool actions. Audit exports can use recipient-based encryption.
These controls need explicit policies and working dependencies; see the
[configuration reference](configuration.md#policies).

## Security

| Control | Configuration and boundary |
|---------|----------------------------|
| Client authentication | [Authentication reference](authentication.md); separate from provider OAuth |
| Virtual access keys | Per-identity permissions and limits; [key commands](cli.md#grob-key) |
| Rate limits | [Disabled by default](security.md#rate-limiting); configure rates and burst together |
| Stored credentials | [Encryption and key custody](../how-to/protect-credential-storage.md); not all stored data is encrypted |
| Memory protection | [Locking and deployment limits](../how-to/harden-memory.md) |
| Service credential replacement | [HTTP gateway with local or Vault authority](../how-to/route-service-credentials.md) |
| Security headers and request limits | [Security reference](security.md) |
| CI analysis | CodeQL, Semgrep, dependency and secret checks; results apply to the checked revision |

Secret wrappers reduce accidental exposure. Explicit access to a secret, process
compromise, traces and operator configuration still matter. See the
[threat model](../explanation/security.md).

## Regulatory Compliance

The following are technical capabilities that may contribute evidence to your
organization's review. They do not establish compliance, certification, data
residency or a right-to-erasure process.

### EU AI Act

Grob can add provider/model headers, enrich audit records and emit risk signals.
See [compliance configuration](configuration.md#compliance-eu-ai-act). Request
risk scores are not a legal classification of your AI system.

### GDPR / RGPD

DLP, configured-name pseudonyms and region filtering can support data controls.
Traces or log exports may still contain personal data; operators must define
retention, access and deletion procedures. Region labels alone do not establish
where a provider processes data.

### HDS / PCI DSS / SecNumCloud

Signed audit records, access control and encrypted credential storage can support
a security review. Their presence does not qualify Grob or the hosting environment.

### SOC 2 / ISO 27001 / HIPAA

Grob supplies technical controls, not an organizational audit or certification.
Review deployment, policies and evidence with the responsible specialists.

### NIS2 / DORA

Fallback, monitoring, audit records and escalation webhooks can support incident
handling. A webhook is not an incident notification to an authority. Reporting,
governance and supplier review remain organizational responsibilities.

### Compliance presets

`gdpr` and `eu-ai-act` are starting configurations. Inspect the selected providers,
DLP settings and audit destinations before applying a preset. See
[preset operations](operations.md#presets) and the [routing limits](routing.md#gdpr-region-filtering).

### What Grob does not provide

Grob does not certify your organization, verify a provider's residency, encrypt
model input from the provider that must process it, or remove all personal data
from every storage destination.

<a id="implementation-verification-audited-2026-03-18"></a>

### Implementation verification

The older dated implementation table was a source-review snapshot, not continuous
assurance. Use the linked behavior references, tests and CI results for the
revision you deploy. A successful check does not establish regulatory compliance.

## Authentication

Choose [incoming-client authentication](authentication.md) separately from
[provider credentials](../how-to/manage-secrets.md). API keys issued by Grob do
not replace provider credentials by themselves; the configured proxy supplies
those when dispatching requests.

## Multi-Tenant Virtual Keys

Virtual keys attach an identity, permitted models/providers and optional limits
to client requests. See [authentication](authentication.md#4-virtual-keys) for the
lifecycle and [replica consistency](../how-to/multi-replica-consistency.md) for
which limits and state are shared across processes.

## Observability

[Observability](observability.md) covers metrics, live traffic, tracing and log
export. OpenTelemetry requires the `otel` build feature. Protect monitoring
access and decide which request content, if any, may be retained.

## Operations

[Operations](operations.md) covers presets, reloads, upgrades and timeouts.
[Deployment](../how-to/deploy.md) covers containers, authentication and persistent
state. A standalone binary or scratch container does not require a separate
database; image size and native TLS support depend on the build.

## CLI Commands

Use `grob --help` for your installed binary and the [CLI reference](cli.md) for
command details. `grob doctor` checks local setup; `grob validate` makes real
provider calls and can consume quota.

## Feature Flags

The authoritative defaults are in [`Cargo.toml`](../../Cargo.toml), under `[features]`.
Optional `tls`, `acme`, `otel` and `harness` features require a build that includes
them. Compile-time availability and runtime activation are separate.

## Architecture

See the [architecture overview](../explanation/architecture.md) for request flow
and component responsibilities. Proposed designs, including the
[optional supervisor](../decisions/0033-advisory-model-supervisor.md), are not
current configuration options.
