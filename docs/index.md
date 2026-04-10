# Grob Documentation

Grob is a multi-provider LLM routing proxy. It sits between your AI coding assistant (Claude Code, Aider, Cline, etc.) and your LLM providers, routing requests with automatic failover, format translation, and spend tracking.

## Who is this for?

- **Developers** using AI coding assistants who want to route through multiple providers with automatic fallback
- **Teams** that need spend tracking, budget enforcement, and DLP scanning on LLM traffic
- **Operators** deploying LLM proxies in containers or on shared infrastructure

## How it works

```mermaid
flowchart TB
    clients["Claude Code / Aider / Cline"] --> grob["Grob<br/>(proxy on localhost:13456)"]
    grob --> a["Anthropic (priority 1)"]
    grob --> or["OpenRouter (priority 2, fallback)"]
    grob --> ol["Ollama (priority 3, local fallback)"]
```

Grob accepts requests in both Anthropic and OpenAI API formats, normalizes them, classifies by task type (thinking, web search, background, default), and dispatches to the best available provider. If one provider fails, the next in the priority chain is tried automatically.

## Quick navigation

### Getting started

| Level | Document | Time |
|-------|----------|------|
| First contact | [Getting Started](tutorials/getting-started.md) | 10 min |
| Quick reference | [Quick Start](QUICKSTART.md) | 2 min |

### Task-oriented guides

| Task | Guide |
|------|-------|
| Set up a provider | [Provider Setup](PROVIDERS.md) |
| Configure OAuth | [OAuth Setup](OAUTH_SETUP.md) |
| Configure DLP | [How to Configure DLP](how-to/dlp.md) |
| Configure options | [How to Configure Grob](how-to/configure.md) |
| Deploy in a container | [How to Deploy Grob](how-to/deploy.md) |
| Fix common problems | [Troubleshooting](TROUBLESHOOTING.md) |
| Contribute | [How to Contribute](how-to/contribute.md) |

### Reference

| Topic | Document |
|-------|----------|
| All config options | [Configuration Reference](CONFIGURATION.md) |
| CLI commands | [CLI Reference](reference/cli.md) |
| DLP engine | [DLP Reference](reference/dlp.md) |
| Routing engine | [Routing Reference](reference/routing.md) |
| Authentication | [Authentication Reference](reference/authentication.md) |
| Caching | [Caching Reference](reference/caching.md) |
| Fan-out racing | [Fan-out Reference](reference/fan-out.md) |
| Security middleware | [Security Reference](reference/security.md) |
| Storage backend | [Storage Reference](reference/storage.md) |
| Observability | [Observability Reference](reference/observability.md) |
| Operations | [Operations Reference](reference/operations.md) |
| Setup wizard | [Setup Wizard Reference](reference/setup-wizard.md) |
| Feature matrix | [Feature Matrix](reference/features.md) |
| Benchmarks | [Benchmarks](reference/benchmarks.md) |
| OWASP LLM Top 10 | [OWASP Coverage](reference/owasp-llm-top10.md) |
| Provider internals | [Provider Reference](reference/providers.md) |
| API compatibility | [API Compatibility Reference](reference/api-compatibility.md) |
| API endpoints | [OpenAPI Spec](openapi.yaml) |
| OpenAI compatibility | [OpenAI Compatibility](openai-compatibility.md) |
| Responses API | [Responses API Compatibility](responses-api-compatibility.md) |
| Error codes | [Error Reference](reference/errors.md) |

### Understanding Grob

| Topic | Document |
|-------|----------|
| Architecture | [Architecture Overview](ARCHITECTURE.md) |
| Security model | [Security Model](explanation/security.md) |
| Policy engine | [Policy Engine](explanation/policies.md) |
| Design philosophy | [Design Principles](design-principles.md) |
| Gemini specifics | [Gemini Integration](gemini-integration.md) |
| Design doc template | [Design Doc Template](design/000-template.md) |

### Architecture decisions (ADRs)

| ADR | Title |
|-----|-------|
| [0001](decisions/0001-static-config-no-hot-reload.md) | Static config, no hot reload |
| [0002](decisions/0002-custom-oauth-no-crate.md) | Custom OAuth, no crate |
| [0003](decisions/0003-regex-routing-engine.md) | Regex routing engine |
| [0004](decisions/0004-persistent-spend-tracking.md) | Persistent spend tracking |
| [0005](decisions/0005-anthropic-native-provider-trait.md) | Anthropic-native provider trait |
| [0006](decisions/0006-policy-engine-encrypted-audit-hit-gateway.md) | Policy engine, encrypted audit, HIT gateway |
| [0008](decisions/0008-wizard-lifecycle.md) | Wizard lifecycle |

## Version

Current release: **v0.35.1** -- see [CHANGELOG](../CHANGELOG.md) for history.
