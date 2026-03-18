# Fan-Out Reference

Fan-out dispatches the same request to multiple providers in parallel and selects the best response according to a configurable strategy. It is an alternative to the default sequential fallback strategy.

## Enabling Fan-Out

Set `strategy = "fan_out"` on a model definition and add a `[models.fan_out]` section:

```toml
[[models]]
name = "multi-provider"
strategy = "fan_out"

[models.fan_out]
mode = "fastest"

[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "claude-sonnet-4-20250514"

[[models.mappings]]
priority = 2
provider = "openai"
actual_model = "gpt-4o"

[[models.mappings]]
priority = 3
provider = "gemini"
actual_model = "gemini-2.5-pro"
```

## Modes

### `fastest` (default)

Races all providers concurrently using `select_all`. Returns the first successful response and drops (cancels) the remaining in-flight requests.

If a provider fails, the race continues with the remaining futures. If all providers fail, the request returns an error.

```toml
[models.fan_out]
mode = "fastest"
count = 2          # Optional: only race the first N mappings (by priority)
```

### `best_quality`

Waits for all providers to respond, then sends every response to a **judge model** that picks the best one.

The judge receives a prompt containing all candidate responses and the configured criteria. It replies with a single number (1-N) indicating its choice. If the judge fails or is unavailable, the first successful response is returned as a fallback.

```toml
[models.fan_out]
mode = "best_quality"
judge_model = "claude-haiku"                  # Default if omitted
judge_criteria = "Pick the most accurate, complete, and well-structured response"  # Default if omitted
```

The judge prompt format:

```
You are a response quality judge. Given N candidate responses to the same prompt,
select the BEST one based on this criteria: <judge_criteria>

Reply with ONLY the number (1-N) of the best response. Nothing else.

--- Response 1 ---
<response text>

--- Response 2 ---
<response text>
...
```

The judge request uses `max_tokens = 10` and `stream = false` for minimal overhead.

### `weighted`

Waits for all providers to respond, then scores each response using a composite formula:

```
score = output_tokens * (1 / (1 + latency_secs))
```

The response with the highest score wins. This formula favors responses that are both comprehensive (more output tokens) and fast (lower latency).

Example scores for the same prompt:

| Provider | Output Tokens | Latency | Score |
|----------|--------------|---------|-------|
| fast-high | 200 | 500ms | 133.3 |
| mid-mid | 100 | 2000ms | 33.3 |
| slow-low | 50 | 5000ms | 8.3 |

```toml
[models.fan_out]
mode = "weighted"
```

## Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"fastest"` | One of: `fastest`, `best_quality`, `weighted` |
| `judge_model` | string | `"claude-haiku"` | Model name for the judge (best_quality mode only) |
| `judge_criteria` | string | `"Pick the most accurate, complete, and well-structured response"` | Selection criteria sent to the judge |
| `count` | integer | all mappings | Limit fan-out to the first N mappings (sorted by priority) |

## Pipeline Integration

Fan-out runs as Step 6 of the dispatch pipeline, after DLP input scanning, cache lookup, and routing. The flow:

1. DLP scans the input request.
2. Cache key is computed (fan-out responses are not cached).
3. Router classifies the request and selects a model name.
4. Provider mappings are resolved and sorted by priority.
5. Cache is checked (skipped for streaming).
6. If the resolved model has `strategy = fan_out`, the fan-out handler takes over.
7. All selected providers receive the request in parallel.
8. The mode-specific selection logic picks the winner.
9. DLP scans the output response.
10. Cost is recorded for every provider that was called (not just the winner).

## Cost Tracking

Fan-out records spend for **every provider that returned a response**, since all providers consumed tokens. The cost for each provider is calculated independently based on the actual model and token counts.

## Full Example

```toml
[[models]]
name = "consensus"
strategy = "fan_out"

[models.fan_out]
mode = "best_quality"
judge_model = "claude-haiku"
judge_criteria = "Pick the response with the fewest factual errors and clearest reasoning"
count = 3

[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "claude-sonnet-4-20250514"

[[models.mappings]]
priority = 2
provider = "openai"
actual_model = "gpt-4o"

[[models.mappings]]
priority = 3
provider = "deepseek"
actual_model = "deepseek-chat"

[[models.mappings]]
priority = 4
provider = "gemini"
actual_model = "gemini-2.5-pro"
# count=3 means this 4th mapping is excluded
```
