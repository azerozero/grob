# OpenAI API Compatibility

Grob exposes a `/v1/chat/completions` endpoint for tools that speak the OpenAI API format (Aider, Cline, Continue, etc.).

All requests are translated to Grob's canonical format internally, routed through the same provider/fallback logic, then translated back. Provider-specific extension fields are preserved for lossless roundtrips.

## Endpoint

**POST** `/v1/chat/completions`

## Supported features

- Text message completions
- System messages (extracted to Anthropic `system` field)
- Multi-turn conversations
- Image inputs (base64 data URIs and plain URLs)
- Streaming (`stream: true`) with SSE
- Tool/function calling (translated to Anthropic `tool_use` format)
- `tool_choice` (`auto`, `none`, `required`, named function)
- Parameters: `temperature`, `top_p`, `stop`, `max_tokens`
- Extension fields preserved for lossless roundtrip: `response_format`, `reasoning_effort`, `seed`, `frequency_penalty`, `presence_penalty`, `parallel_tool_calls`, `user`, `logprobs`, `top_logprobs`, `service_tier`

## Limitations

| Feature | Status |
|---------|--------|
| `n` (multiple completions) | Not supported (always 1 choice) |
| `response_format` (JSON mode) | Captured but not enforced by Anthropic backend |
| `logprobs` | Captured but not returned by Anthropic backend |
| Thinking blocks | Silently dropped in response translation |
| Image blocks in response | Silently dropped in response translation |

## Translation pipeline

```
OpenAI request ──► transform_openai_to_canonical ──► CanonicalRequest
                                                         │
                                                    (dispatch pipeline)
                                                         │
OpenAI response ◄── transform_canonical_to_openai ◄── ProviderResponse
```

For streaming, the `AnthropicToOpenAIStream` state machine converts Anthropic SSE events into OpenAI-format `chat.completion.chunk` events on the fly.

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

## Message role mapping

| OpenAI role | Canonical handling |
|-------------|-------------------|
| `system` | Extracted into top-level `system` field (not sent as a message) |
| `user` | Mapped to canonical user message; multi-part content preserved |
| `assistant` | Mapped to canonical assistant message; `tool_calls` become `tool_use` blocks |
| `tool` | Mapped to `tool_result` block inside a user message; consecutive tool results are merged |

## Image handling

Images in user messages are supported via the `image_url` content part type.

**Base64 data URIs** (`data:image/jpeg;base64,...`) are parsed into Anthropic `base64` image source blocks. Supported media types: `image/jpeg`, `image/png`, `image/gif`, `image/webp`. Unknown types default to `image/png`.

**Plain URLs** (`https://...`) are preserved as `url`-type image sources.

## Tool calling

### Request (OpenAI to canonical)

OpenAI tools (function definitions) are translated to Anthropic `Tool` format:

| OpenAI field | Canonical field |
|--------------|-----------------|
| `tools[].function.name` | `tools[].name` |
| `tools[].function.description` | `tools[].description` |
| `tools[].function.parameters` | `tools[].input_schema` |

`tool_choice` mapping:

| OpenAI value | Canonical value |
|--------------|-----------------|
| `"auto"` | `{"type": "auto"}` |
| `"none"` | `{"type": "auto"}` |
| `"required"` | `{"type": "any"}` |
| `{"type": "function", "function": {"name": "X"}}` | `{"type": "tool", "name": "X"}` |

### Response (canonical to OpenAI)

`tool_use` content blocks in the response are translated to `tool_calls`:

| Canonical field | OpenAI field |
|-----------------|--------------|
| `tool_use.id` | `tool_calls[].id` |
| `tool_use.name` | `tool_calls[].function.name` |
| `tool_use.input` (JSON) | `tool_calls[].function.arguments` (serialized string) |

The `finish_reason` is set to `"tool_calls"` when the stop reason is `tool_use`.

### Assistant messages with tool calls (roundtrip)

When an assistant message contains both `content` text and `tool_calls`, the canonical form uses a block-based message with separate `text` and `tool_use` content blocks. Tool call arguments are parsed from JSON strings; malformed arguments fall back to an empty JSON object.

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

## Streaming

When `stream: true` is set, the response is delivered as server-sent events (SSE). Each Anthropic SSE event is translated to an OpenAI `chat.completion.chunk` event.

### Event mapping

| Anthropic event | OpenAI chunk | Content |
|-----------------|-------------|---------|
| `message_start` | First chunk | `delta.role = "assistant"` |
| `content_block_start` (type: `tool_use`) | Tool call start | `delta.tool_calls[].id`, `.type`, `.function.name` |
| `content_block_delta` (type: `text_delta`) | Text chunk | `delta.content = "..."` |
| `content_block_delta` (type: `input_json_delta`) | Tool args fragment | `delta.tool_calls[].function.arguments = "..."` |
| `message_delta` | Final chunk | `finish_reason` set |
| `message_stop` | Stream end | `data: [DONE]` |

Other Anthropic events (e.g. `content_block_stop`, `ping`) are silently skipped.

### Example streaming response

```
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","created":1234567890,"model":"default","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}

data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","created":1234567890,"model":"default","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}

data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","created":1234567890,"model":"default","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

## Extension fields

These fields are captured from the OpenAI request and stored in `RequestExtensions` for lossless provider roundtrips. They are forwarded to providers that support them (e.g., OpenAI, Gemini) but may be ignored by Anthropic backends.

| Field | Type | Description |
|-------|------|-------------|
| `response_format` | object | Structured output format (`json_schema`, `json_object`) |
| `reasoning_effort` | string | Reasoning effort hint for o-series models |
| `seed` | integer | Deterministic sampling seed |
| `frequency_penalty` | float | Penalises tokens by existing frequency |
| `presence_penalty` | float | Penalises tokens that have already appeared |
| `parallel_tool_calls` | boolean | Allow multiple tool calls in one turn |
| `user` | string | End-user identifier for abuse monitoring |
| `logprobs` | boolean | Enable per-token log-probabilities |
| `top_logprobs` | integer | Number of most-likely tokens to return log-probs for |
| `service_tier` | string | Requested service tier |

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

## Source files

| File | Purpose |
|------|---------|
| `src/server/openai_compat/mod.rs` | Module root, re-exports |
| `src/server/openai_compat/types.rs` | Request/response struct definitions |
| `src/server/openai_compat/transform.rs` | Bidirectional format conversion |
| `src/server/openai_compat/stream.rs` | SSE stream translator (Anthropic to OpenAI) |
| `src/server/handlers.rs` | HTTP handler wiring the endpoint |
