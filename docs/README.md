# Grob Documentation

Start here: **[Documentation Index](index.md)**

## Tutorials (learning-oriented)

- [Getting Started](tutorials/getting-started.md) -- Install, configure, and run Grob end-to-end
- [Quick Start](tutorials/quickstart.md) -- Condensed version for experienced users

## How-to Guides (task-oriented)

- [How to Configure Grob](how-to/configure.md) -- Budgets, fallbacks, routing rules, tracing
- [How to Deploy Grob](how-to/deploy.md) -- Containers, Kubernetes, systemd, monitoring
- [How to Contribute](how-to/contribute.md) -- Development workflow, code style, CI
- [Provider Setup](how-to/providers.md) -- Per-provider configuration
- [OAuth Setup](how-to/oauth-setup.md) -- OAuth for Anthropic Pro/Max and Gemini Pro
- [Troubleshooting](how-to/troubleshooting.md) -- Common errors and fixes

## Reference (information-oriented)

- [Configuration Reference](reference/configuration.md) -- All TOML config options
- [CLI Reference](reference/cli.md) -- All commands and flags
- [Error Reference](reference/errors.md) -- HTTP status codes and error types
- [OpenAI Compatibility](reference/openai-compatibility.md) -- `/v1/chat/completions` endpoint
- [OpenAPI Specification](openapi.yaml) -- Full API in OpenAPI 3.0

## Explanation (understanding-oriented)

- [Architecture](explanation/architecture.md) -- Request flow, module layout, design decisions
- [Design Principles](explanation/design-principles.md) -- Philosophy and UX guidelines
- [Security Model](explanation/security.md) -- Threat model, defense layers, TLS
- [Gemini Integration](how-to/gemini-integration.md) -- Gemini and Vertex AI specifics
- [Architecture Decision Records](decisions/) -- ADRs for key design choices

## Monitoring

Grob exposes Prometheus metrics at `/metrics`. A Grafana dashboard is provided in [grafana-dashboard.json](grafana-dashboard.json).

## Documentation Completeness

See [DCI-REPORT.md](reference/dci-report.md) for the Documentation Completeness Index with scores, gaps, and improvement recommendations.
