# E2E Test Suite — Black-Box Instructions

This directory contains the end-to-end test infrastructure for Grob. All tests
interact with a running Grob instance exclusively over HTTP. No source code
access is required or permitted here.

## Hard Rules

- **Never touch `src/`**. All assertions go through the HTTP interface only.
- Tests are **black-box only**: treat Grob as an opaque HTTP service.
- Container orchestration uses **`podman play kube`** exclusively. Docker Compose
  is not used anywhere in this tree.
- HTTP tests use **Hurl** (`.hurl` files). Filesystem/process assertions use
  plain **bash** scripts.
- JWTs are passed to Hurl as **variables** (e.g. `--variable jwt=...`), never
  hard-coded inside `.hurl` files.
- **Never commit real API keys**. Live keys are read from environment variables
  at runtime only (see below).

## Port Mapping

| Service           | Port  | Protocol | Image                     |
|-------------------|-------|----------|---------------------------|
| Grob proxy        | 13456 | HTTP     | localhost/grob:e2e        |
| VidaiMock         | 8100  | HTTP     | localhost/vidaimock:e2e    |
| Toxiproxy API     | 8474  | HTTP     | shopify/toxiproxy:latest  |
| anthropic-mock    | 9001  | TCP      | (toxiproxy → VidaiMock)   |
| openai-mock       | 9002  | TCP      | (toxiproxy → VidaiMock)   |
| gemini-mock       | 9003  | TCP      | (toxiproxy → VidaiMock)   |
| mock-jwks         | 8443  | HTTP     | nginx:alpine              |

All containers share the pod's network namespace, so they reach each other on
`127.0.0.1`.

VidaiMock serves all LLM provider formats (OpenAI, Anthropic, Gemini, Bedrock,
Vertex AI, Azure) on a single port. Toxiproxy sits in front for TCP-level fault
injection. VidaiMock also supports application-level chaos via request headers
(`X-Vidai-Chaos-Drop`, `--mode realistic` for TTFT/TPS simulation).

## Live Environment Variables

The following variables are read at runtime for live-provider tests only.
They **must not** be committed or logged.

```
GROB_SIEGE_ANTHROPIC_KEY   real Anthropic API key
GROB_SIEGE_OPENAI_KEY      real OpenAI API key
GROB_SIEGE_GEMINI_KEY      real Gemini API key
```

Live tests live under `tests/live/` and are skipped unless the corresponding
variable is set.

## Quick Start

```bash
just up            # start the pod + init Toxiproxy proxies
just generate-all  # generate auth tokens, age keys, pairwise matrix
just test          # run the full mock-backed suite
just down          # stop and remove the pod
```

## Directory Layout

```
e2e/
├── auth/           JWT generation scripts + JWKS fixture
│   ├── keys/       EC P-256 signing keypair (git-ignored)
│   └── tokens/     Generated JWT files (git-ignored)
├── config/
│   └── mock/       Grob config + Toxiproxy init
├── crypto/         age keypair generation
├── fixtures/       Shared request/response payloads
├── images/         Containerfiles (vidaimock)
├── kube/           Podman pod manifest
├── load/           k6 / hey load test scripts
├── pict/           PICT pairwise model + generated matrix
└── tests/          Hurl test suites by category
```

## Writing Tests

- One concern per `.hurl` file; group related assertions in the same file.
- Use `[Options]` to set per-entry variables or skip conditions.
- Reference shared fixtures from `../../fixtures/` with relative paths.
- Prefer `assert header` over `assert body` for routing/compliance checks.
- Auth header pattern: `Authorization: Bearer {{jwt}}`
- Static master key: `X-Grob-API-Key: grob-siege-master-key`
