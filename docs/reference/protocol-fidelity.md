# Protocol Fidelity Matrix

What grob preserves, transforms, and cannot carry when it translates a request
between the Anthropic canonical format and each provider's wire format. A gateway
can return `HTTP 200` with a valid stream and still corrupt the *meaning* of an
agent turn — a dropped tool argument or a stringified image looks fine on the
wire but breaks the agent. This matrix makes each such point explicit rather than
silent.

Scope: request-direction content translation. Response-direction streaming
fidelity (SSE event mapping, tool-call salvage) is covered by the harness tests.

## Legend

- **native** — passed through unchanged (no translation).
- **✅** — translated with the field preserved.
- **API-limited** — the target provider's wire format cannot carry it; the loss
  is the provider's constraint, not grob's. Flagged here so it is not silent.
- **by design** — intentionally not forwarded (documented reason).

## Message content

| Dimension | Anthropic `/v1/messages` | OpenAI `/chat/completions` | OpenAI `/responses` (Codex) | Gemini |
|---|---|---|---|---|
| Text | native | ✅ `text` part | ✅ `input_text` part | ✅ `text` part |
| Image (base64 / URL) | native | ✅ `image_url` (data URI) | ✅ `input_image` ([#476]) | ✅ `inline_data` |
| Tool call (`tool_use`) | native | ✅ `tool_calls` | ✅ `function_call` | ✅ `functionCall` |
| Thinking / reasoning | signature-sanitized¹ | by design² | reasoning store ([#465]) | as text |

¹ Non-Anthropic thinking signatures are stripped before send, else Anthropic
rejects them (`anthropic_sanitize.rs`).
² Chat Completions has no reasoning-history slot; the visible conversation
carries the context.

## Tool results (`tool_result`)

| Content | Anthropic | OpenAI Chat | OpenAI Responses (Codex) | Gemini |
|---|---|---|---|---|
| Text | native | ✅ `tool` message string | ✅ `function_call_output` string | ✅ `functionResponse` |
| **Image** | native | **API-limited**³ | **✅ `input_image` part ([#488])** | **API-limited (unverified)**³ |

³ The Chat Completions `tool` role and Gemini `functionResponse.response` are
string/JSON-object shaped and do not carry image parts, so a tool that returns an
image (screenshot, computer-use, an MCP vision tool) is rendered as the text
`[Image]` on those paths. The Responses path **does** accept `input_image` in
`function_call_output` (verified against the ChatGPT Codex backend), so [#488]
forwards the pixels there. The Chat/Gemini variants are marked unverified because
grob has no standing test credential for those backends; if a target model
accepts multimodal tool output, injecting the image as a following `user` message
is the known workaround and can be added per-path.

## Provider errors

grob forwards the **verbatim upstream HTTP status** (never a flattened 502/500)
and, since [#489], the provider's own error body **structured** under
`error.upstream_error` — so a client can branch on the provider's `type`/`code`
instead of re-parsing a string. See [`error.rs`](../../src/server/error.rs).

## Cross-turn state

- **prompt_cache_key** — derived from the reusable request prefix so agent-loop
  turns share a cache node (`derive_prompt_cache_key`).
- **encrypted reasoning** — the Codex backend's `encrypted_content` is stored and
  replayed ahead of its tool call across turns when `codex.reasoning_continuity`
  is enabled ([#465]).

## Keeping this honest

This matrix is a claim, and claims rot. The per-release agent-conformance suite
tracked in the fidelity backlog is what should prove each ✅ semantically (not
just `HTTP 200`) at every tag; until then, treat unverified rows as such.

[#465]: https://github.com/azerozero/grob/pull/465
[#476]: https://github.com/azerozero/grob/pull/476
[#488]: https://github.com/azerozero/grob/pull/488
[#489]: https://github.com/azerozero/grob/pull/489
