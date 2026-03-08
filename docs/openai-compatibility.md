# OpenAI API Compatibility

Grob exposes a `/v1/chat/completions` endpoint for tools that speak the OpenAI API format (Aider, Cline, Continue, etc.).

All requests are translated to Grob's canonical format internally, routed through the same provider/fallback logic, then translated back. Provider-specific extension fields are preserved for lossless roundtrips.

## Endpoint

**POST** `/v1/chat/completions`

## Supported features

- Text message completions
- System messages
- Multi-turn conversations
- Image inputs (base64 and URL)
- Streaming (`stream: true`) with SSE
- Tool/function calling (translated to Anthropic tool_use format)
- `tool_choice` (`auto`, `none`, `required`, named function)
- Parameters: `temperature`, `top_p`, `stop`, `max_tokens`
- Extension fields preserved for lossless roundtrip: `response_format`, `reasoning_effort`, `seed`, `frequency_penalty`, `presence_penalty`, `parallel_tool_calls`, `user`, `logprobs`, `top_logprobs`, `service_tier`

## Limitations

| Feature | Status |
|---------|--------|
| `n` (multiple completions) | Not supported (always 1 choice) |
| `response_format` (JSON mode) | Captured but not enforced by Anthropic backend |
| `logprobs` | Captured but not returned by Anthropic backend |

## Request format

```json
{
  "model": "default",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ],
  "max_tokens": 1024
}
```

The `model` field maps to a Grob model name (e.g., `default`, `claude-opus-thinking`). If the model name doesn't match a configured model, Grob uses `auto_map_regex` to route it.

## Response format

```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1234567890,
  "model": "default",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I help you today?"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 20,
    "completion_tokens": 10,
    "total_tokens": 30
  }
}
```

## Finish reason mapping

| Anthropic `stop_reason` | OpenAI `finish_reason` |
|--------------------------|------------------------|
| `end_turn` | `stop` |
| `max_tokens` | `length` |
| `stop_sequence` | `stop` |
| `tool_use` | `tool_calls` |

## Error format

Errors follow OpenAI's format:

```json
{
  "error": {
    "message": "Error description",
    "type": "error_type",
    "code": "error_code"
  }
}
```
