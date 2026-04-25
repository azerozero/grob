# Use grob_hint to override request complexity

Skip the heuristic classifier when the client already knows how complex
a request is. `grob_hint` declares a complexity tier for a single
request, bypassing scoring and feeding directly into provider selection.

Three surfaces are equivalent and supported:

| Surface | Best for |
|---------|----------|
| `X-Grob-Hint` HTTP header | curl, scripts, any HTTP client |
| `metadata.grob_hint` request body field | SDK clients (Anthropic, OpenAI) |
| `grob_hint` MCP tool | MCP-native agents that cannot set headers |

## Valid hint values

- `trivial` — fast lookup, short answer, no reasoning
- `medium` — standard reasoning, moderate context
- `complex` — deep reasoning, multi-step, tool use, large context

Anything else is rejected with `400 Bad Request`.

## Priority order

When several hint surfaces are set on the same request, the first match
wins:

1. `X-Grob-Hint` header
2. `metadata.grob_hint` body field
3. MCP one-shot slot (set via `grob_hint` tool, consumed on next dispatch)

If none are set, the heuristic classifier scores the request from
observable signals (max_tokens, tools, context size, keywords, system
prompt length).

## Use the X-Grob-Hint header

Cleanest path for shell scripts and `curl`. Add a single header:

```sh
curl http://localhost:13456/v1/messages \
  -H 'Content-Type: application/json' \
  -H 'X-Grob-Hint: complex' \
  -d '{
    "model": "claude-sonnet-4",
    "max_tokens": 4096,
    "messages": [{"role": "user", "content": "Refactor this monorepo build pipeline."}]
  }'
```

The hint is consumed for this request only. The next request without
the header falls back to scoring.

## Use metadata.grob_hint in the body

Some SDKs forbid custom headers but allow arbitrary `metadata` fields.
Drop the hint there — Grob reads it before forwarding the request:

```json
{
  "model": "claude-sonnet-4",
  "max_tokens": 1024,
  "metadata": {
    "grob_hint": "trivial"
  },
  "messages": [{"role": "user", "content": "What time zone is UTC+1?"}]
}
```

Grob strips `metadata.grob_hint` before forwarding to the upstream
provider, so no provider-specific metadata schema is contaminated.

## Use the grob_hint MCP tool

For MCP clients (Claude Code, Cursor, custom agents) that cannot set
custom HTTP headers and don't shape the request body directly. Call
the tool **before** the request you want to influence:

```json
{
  "method": "tools/call",
  "params": {
    "name": "grob_hint",
    "arguments": {"complexity": "complex"}
  }
}
```

The hint is stored in a one-shot slot on the server and consumed by
the next dispatch from the same MCP session. After consumption the slot
is cleared automatically — you must call `grob_hint` again to influence
a subsequent request.

## When to use each surface

- **Header** — quick experiments, batch scripts, profiling.
- **Metadata** — production SDK clients where you control the request
  body but not the transport.
- **MCP tool** — agentic clients that operate through MCP and don't
  craft HTTP requests directly. Useful when an agent's planner has
  already classified the task and wants to avoid re-running the
  scorer on the proxy.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Hint ignored | Spelled wrong; only `trivial`/`medium`/`complex` are accepted |
| Hint applied to the wrong request | MCP one-shot slot was consumed earlier; call `grob_hint` again |
| Header passed through to provider | Should not happen — file an issue with the request trace |

## Further reading

- [Auto-tune routing with trace analysis](auto-tune-routing.md) — when to
  rely on the scorer instead of pinning hints.
