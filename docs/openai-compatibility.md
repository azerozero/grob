# OpenAI API Compatibility

Grob exposes a `/v1/chat/completions` endpoint for tools that speak the OpenAI API format (Aider, Cline, Continue, etc.).

All requests are translated to Anthropic format internally, routed through the same provider/fallback logic, then translated back.

## Endpoint

**POST** `/v1/chat/completions`

## Supported features

- Text message completions
- System messages
- Multi-turn conversations
- Image inputs (base64 and URL)
- Streaming (`stream: true`) with SSE
- Tool/function calling (translated to Anthropic tool_use format)
- Parameters: `temperature`, `top_p`, `stop`, `max_tokens`

## Limitations

| Feature | Status |
|---------|--------|
| `response_format` (JSON mode) | Not supported |
| `n` (multiple completions) | Not supported |
| `logprobs` | Not supported |
| `tool_choice` | Not yet supported |

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
