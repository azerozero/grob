# Grob Documentation

Grob is a multi-provider LLM routing proxy. It sits between your AI coding assistant (Claude Code, Aider, Cline, etc.) and your LLM providers, routing requests with automatic failover, format translation, and spend tracking.

## Who is this for?

- **Developers** using AI coding assistants who want to route through multiple providers with automatic fallback
- **Teams** that need spend tracking, budget enforcement, and DLP scanning on LLM traffic
- **Operators** deploying LLM proxies in containers or on shared infrastructure

## How it works

```
Claude Code / Aider / Cline
        |
        v
      Grob (proxy on localhost:13456)
        |
        +---> Anthropic (priority 1)
        +---> OpenRouter (priority 2, fallback)
        +---> Ollama (priority 3, local fallback)
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
| Configure options | [How to Configure Grob](how-to/configure.md) |
| Deploy in a container | [How to Deploy Grob](how-to/deploy.md) |
| Fix common problems | [Troubleshooting](TROUBLESHOOTING.md) |
| Contribute | [How to Contribute](how-to/contribute.md) |

### Reference

| Topic | Document |
|-------|----------|
| All config options | [Configuration Reference](CONFIGURATION.md) |
| CLI commands | [CLI Reference](reference/cli.md) |
| API endpoints | [OpenAPI Spec](openapi.yaml) |
| OpenAI compatibility | [OpenAI Compatibility](openai-compatibility.md) |
| Error codes | [Error Reference](reference/errors.md) |

### Understanding Grob

| Topic | Document |
|-------|----------|
| Architecture | [Architecture Overview](ARCHITECTURE.md) |
| Design philosophy | [Design Principles](design-principles.md) |
| Gemini specifics | [Gemini Integration](gemini-integration.md) |
| Architecture decisions | [ADRs](decisions/) |

## Version

Current release: **v0.11.1** -- see [CHANGELOG](../CHANGELOG.md) for history.
