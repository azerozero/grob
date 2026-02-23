# OpenAI API Compatibility

This document describes the `/v1/chat/completions` endpoint which provides limited OpenAI API compatibility.

> **Note**: The primary use case for this proxy is Claude Code (Anthropic client) connecting to various backends via `/v1/messages`. The `/v1/chat/completions` endpoint is secondary and has limited functionality.

## `/v1/chat/completions` Endpoint

**Method:** POST

**Supported Features:**
- Text message completions (non-streaming only)
- System messages
- Multi-turn conversations
- Image inputs (base64 and URL)
- Basic parameters: temperature, top_p, stop, max_tokens

**Not Supported:**
- Streaming (`stream: true` returns an error)
- Tool/function calling
- Cache tokens in usage statistics

## Request Format

```json
{
  "model": "gpt-4",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ],
  "max_tokens": 1024
}
```

## Response Format

```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1234567890,
  "model": "gpt-4",
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

## Unsupported Parameters

| Parameter | Status | Notes |
|-----------|--------|-------|
| `stream` | Not supported | Returns error; use `/v1/messages` instead |
| `tools` | Not supported | Use `/v1/messages` with OpenAI backends |
| `tool_choice` | Not supported | Use `/v1/messages` with OpenAI backends |
| `response_format` | Not supported | JSON mode not available |
| `seed` | Not supported | Reproducibility not guaranteed |
| `logprobs` | Not supported | - |
| `n` | Not supported | Only single completion returned |
| `presence_penalty` | Not supported | - |
| `frequency_penalty` | Not supported | - |

## Finish Reason Mapping

| Anthropic `stop_reason` | OpenAI `finish_reason` |
|-------------------------|------------------------|
| `end_turn` | `stop` |
| `max_tokens` | `length` |
| `stop_sequence` | `stop` |
| `tool_use` | `tool_calls` |

## Error Handling

Errors are returned in OpenAI-compatible format:

```json
{
  "error": {
    "message": "Error description",
    "type": "error_type",
    "code": "error_code"
  }
}
```

## Backend Providers

The `/v1/chat/completions` endpoint works with all configured backend providers:

- Anthropic
- OpenAI-compatible providers (OpenRouter, Groq, DeepInfra, etc.)
- Gemini
