# Auto-tune routing with trace analysis

Use the request trace log to identify routing patterns, then adjust
scoring weights and prompt rules via `grob_configure` without restarting
the proxy.

## Prerequisites

- grob running with tracing enabled (`[tracing] enabled = true`)
- MCP tool access to `grob_configure` (Claude Code, Cursor, or any MCP client)
- At least a few hundred traced requests in `~/.grob/trace.jsonl`

## Enable tracing

Add the following to `~/.grob/config.toml` if not already present:

```toml
[tracing]
enabled = true
path = "~/.grob/trace.jsonl"
max_size_mb = 50
max_files = 3
```

Reload the config:

```sh
curl -X POST http://localhost:13456/api/config/reload
```

## Analyze the trace log

Each request line in `trace.jsonl` contains the routing decision:

```json
{ "ts": "2026-04-11T14:32:00Z", "dir": "req", "id": "a1b2c3d4",
  "model": "claude-sonnet-4-5-20250514", "provider": "anthropic",
  "route_type": "default", "tool_count": 3, "is_stream": true }
```

The matching response line carries latency and token counts:

```json
{ "ts": "2026-04-11T14:32:08Z", "dir": "res", "id": "a1b2c3d4",
  "latency_ms": 8200, "input_tokens": 4500, "output_tokens": 1200 }
```

Use `jq` to extract patterns. For example, find requests that used more
than 4000 input tokens but were routed to the default model:

```sh
jq -s '
  group_by(.id) | map(select(length == 2))
  | map({id: .[0].id, route: .[0].route_type,
         input: .[1].input_tokens, latency: .[1].latency_ms})
  | map(select(.input > 4000 and .route == "default"))
  | sort_by(-.latency)
' ~/.grob/trace.jsonl
```

## Identify tuning opportunities

Common patterns to look for:

| Signal | What it means | Action |
|--------|---------------|--------|
| High-token requests routed to expensive model | Scoring weights too low for `max_tokens` | Raise `max_tokens` weight or lower `complex_threshold` |
| Simple requests hitting complex tier | Keywords triggering false positives | Add a prompt rule to catch them earlier |
| Consistent route type with high latency | Provider is slow for that pattern | Add a `[[tiers]]` entry to redirect to a faster provider |
| Tool-heavy requests on default model | Tool signal underweighted | Raise `tools` weight |

## Adjust prompt rules via grob_configure

Read the current router config:

```
grob_configure action=read section=router
```

Add a prompt rule that catches code-review requests and routes them to
the thinking model:

```
grob_configure action=update section=router key=prompt_rules value=[
  {"pattern": "(?i)(review|pr|pull.request)", "route": "think"}
]
```

The change takes effect immediately (hot-reload). Prompt rules are
evaluated in order; the first match wins.

## Adjust scoring thresholds

The complexity scorer uses five weighted signals. Default weights are
all `1.0` with thresholds at `2.0` (medium) and `5.0` (complex):

| Signal | Points | Weight key |
|--------|--------|------------|
| `max_tokens` < 500 / < 4000 / >= 4000 | 0 / 1 / 3 | `max_tokens` |
| Tools present | 3 | `tools` |
| Context size (messages + tokens) | 0 / 1 / 3 | `context_size` |
| Keywords in last message | 0 / 1 / 2 | `keywords` |
| Long system prompt (>= 500 est. tokens) | 2 | `system_prompt` |

To make tool-heavy requests more likely to score as complex, raise the
`tools` weight. To ignore keyword matching entirely, set its weight to
`0.0`. These are configured in `[[tiers]]` scoring config (see the
configuration reference).

## Iterate

1. Collect traces for a representative period (a few hours to a day).
2. Run the `jq` analysis to find misrouted or slow requests.
3. Adjust one parameter at a time via `grob_configure`.
4. Monitor the next batch of traces to confirm improvement.
5. Once satisfied, persist the changes to `config.toml`.

Trace rotation (`max_size_mb`, `max_files`) ensures old data is pruned
automatically. Enable `compress = true` to keep more history in less
disk space.

## Further reading

- [Configuration reference](../reference/configuration.md) -- full list of config keys
- [Observability reference](../reference/observability.md) -- Prometheus metrics and SSE stream
- [Complexity scoring](../explanation/complexity-scoring.md) -- how the heuristic works
