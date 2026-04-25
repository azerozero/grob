# ADR-0007: OpenAI Compatibility — Dual Surface (Chat Completions + Responses)

## Status

Accepted (retroactive — records a decision already implemented in `src/server/openai_compat/` and `src/server/responses_compat/`).

## Context and Problem Statement

Grob is primarily an Anthropic-native proxy (see ADR-0005), but a significant
fraction of clients speak OpenAI wire formats. The OpenAI ecosystem itself
has two distinct surfaces: the legacy `/v1/chat/completions` API used by
most SDKs, and the newer `/v1/responses` API used by Codex CLI and the
Assistants / Realtime generations. A proxy that claims "OpenAI-compatible"
without covering both leaves either the SDK ecosystem or the Codex CLI
behind.

The question is how much of the OpenAI surface to translate, where the
translation lives, and whether to keep the two shapes unified or distinct
internally.

## Decision Drivers

- Client coverage: openai-python, langchain, LiteLLM, Continue, Cursor
  (Chat Completions) and Codex CLI, Responses SDK (Responses API).
- Single internal normal form: the dispatch pipeline (DLP, cache, route,
  provider loop) must not care which wire surface the request came in on.
- Streaming fidelity: SSE frames emitted back must match each surface's
  exact event grammar — Chat Completions uses `data: {chunk}` with
  `choices[].delta`, Responses uses `event: response.output_text.delta`
  style named events.
- Codex-specific behaviors (system prompt injection from the official
  Codex instructions) must not leak into the Chat Completions path.

## Considered Options

- **Chat Completions only**: translate only `/v1/chat/completions`;
  Codex CLI users use the native Anthropic SDK.
- **Responses only**: translate only `/v1/responses`; legacy clients
  keep their own proxies.
- **Dual surface, shared transform**: one compat module with a flag for
  the surface shape.
- **Dual surface, sibling modules**: `openai_compat/` and
  `responses_compat/` as peer modules under `src/server/`, each with its
  own `transform.rs` and `stream.rs`, converging on the same internal
  Anthropic-shaped request before dispatch.

## Decision Outcome

Chosen option: **Dual surface, sibling modules**.

Both `/v1/chat/completions` and `/v1/responses` are exposed. Each has its
own translation module (`src/server/openai_compat/`,
`src/server/responses_compat/`) that converts the incoming request into
the Anthropic-native shape consumed by the dispatch pipeline, and converts
the Anthropic response (or stream of events) back into the matching wire
format. Codex-specific behavior — notably injecting the official Codex
system prompt from `src/providers/openai/codex_instructions.md` — lives in the
OpenAI provider path (`src/providers/openai/`), not in the compat layer,
so it applies regardless of which surface the client used.

### Consequences

- Good, because the internal dispatch pipeline sees a single normal form
  and does not branch on wire surface.
- Good, because each compat module owns its streaming grammar end-to-end,
  which matches what snapshot tests in `src/server/openai_compat/snapshots/`
  verify.
- Good, because Codex CLI works without the user installing a separate
  proxy.
- Bad, because two surfaces means roughly double the transform and
  streaming code, and every new OpenAI feature (tool-call shapes,
  refusals, citations) has to be implemented twice.
- Bad, because the Responses API is still evolving; we accept periodic
  churn in `responses_compat/`.

### Confirmation

- Snapshot tests under `src/server/openai_compat/snapshots/` pin the
  exact wire format for Chat Completions.
- Integration tests for the Responses path exercise streaming event
  ordering.
- Clippy + fmt in CI enforce the module boundary (compat modules do not
  import from each other).
