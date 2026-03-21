# OpenAI Responses API Compatibility

Grob exposes a `/v1/responses` endpoint for tools that use the OpenAI Responses API format (Codex CLI, OpenAI SDK with Responses mode, etc.).

All requests are translated to Grob's canonical format internally, routed through the same provider/fallback logic, then translated back. Streaming uses named SSE events (e.g. `event: response.output_text.delta`) instead of the `data: {...}` format used by Chat Completions.

## Endpoint

**POST** `/v1/responses`

## Supported features

- Text and structured input (plain string or typed items)
- System instructions (extracted to canonical `system` field)
- Multi-turn conversations with function call history
- Streaming (`stream: true`) with named SSE events
- Tool/function calling (flat format, no nested `function` wrapper)
- Reasoning configuration (`reasoning.effort`)
- Parameters: `temperature`, `top_p`, `max_output_tokens`
- Extension fields preserved for lossless roundtrip: `parallel_tool_calls`, `service_tier`

## Limitations

| Feature | Status |
|---------|--------|
| `previous_response_id` | Accepted but ignored (grob is stateless) |
| `store` | Accepted but ignored |
| Thinking blocks in response | Silently dropped |
| Image blocks in response | Silently dropped |
| Image inputs | Not supported (only `input_text` content parts) |
| `tool_choice` | Not supported (always auto) |

## Translation pipeline

See [API Compatibility Reference — Responses pipeline](reference/api-compatibility.md#translation-pipeline-1) for the full diagram.

For streaming, the `AnthropicToResponsesStream` state machine converts Anthropic SSE events into Responses API named-event SSE events on the fly.

## Request format

### Simple text input

```json
{
  "model": "default",
  "instructions": "You are a helpful assistant.",
  "input": "Hello!",
  "stream": false
}
```

### Structured input with function calls

```json
{
  "model": "default",
  "input": [
    {
      "type": "message",
      "role": "user",
      "content": "List the files"
    },
    {
      "type": "function_call",
      "id": "call_1",
      "name": "ls",
      "arguments": "{\"path\":\".\"}"
    },
    {
      "type": "function_call_output",
      "call_id": "call_1",
      "output": "file1.rs\nfile2.rs"
    }
  ],
  "tools": [
    {
      "type": "function",
      "name": "ls",
      "description": "List directory contents",
      "parameters": {
        "type": "object",
        "properties": {
          "path": { "type": "string" }
        }
      }
    }
  ]
}
```

The `model` field maps to a Grob model name (e.g., `default`, `claude-opus-thinking`). If the model name doesn't match a configured model, Grob uses `auto_map_regex` to route it.

## Input types

### Input format

The `input` field accepts either a plain string or an array of typed items:

| Input type | Description |
|------------|-------------|
| `string` | Treated as a single user message |
| `array` of items | Structured conversation with messages, function calls, and outputs |

### Input item types

| Item type | Description | Canonical mapping |
|-----------|-------------|-------------------|
| `message` | Conversation message with `role` and `content` | User/assistant message; system role merged into `system` field |
| `function_call` | Tool invocation by the assistant | Assistant message with `tool_use` content block |
| `function_call_output` | Result of a function call | User message with `tool_result` content block |

### Content format

Message content accepts either a plain string or an array of typed parts:

| Content type | Description |
|--------------|-------------|
| `string` | Plain text content |
| `array` of parts | Typed content parts (currently only `input_text` is supported) |

## Tool calling

### Request (Responses to canonical)

Responses API tools use a flat format (no nested `function` wrapper). Grob also accepts the Chat Completions nested format as a fallback.

**Flat format (preferred):**

| Responses field | Canonical field |
|-----------------|-----------------|
| `tools[].name` | `tools[].name` |
| `tools[].description` | `tools[].description` |
| `tools[].parameters` | `tools[].input_schema` |

**Nested fallback:**

| Responses field | Canonical field |
|-----------------|-----------------|
| `tools[].function.name` | `tools[].name` |
| `tools[].function.description` | `tools[].description` |
| `tools[].function.parameters` | `tools[].input_schema` |

### Response (canonical to Responses)

`tool_use` content blocks in the canonical response are translated to `function_call` output items:

| Canonical field | Responses field |
|-----------------|-----------------|
| `tool_use.id` | `function_call.call_id` |
| `tool_use.name` | `function_call.name` |
| `tool_use.input` (JSON) | `function_call.arguments` (serialized string) |

Text and function call outputs are interleaved in the order they appear. If the model produces text followed by a function call, the text is emitted as a `message` output item before the `function_call` output item.

### Function call merging (request)

Consecutive `function_call` items from the same assistant turn are merged into a single assistant message with multiple `tool_use` blocks. Consecutive `function_call_output` items are merged into a single user message with multiple `tool_result` blocks.

## Response format

```json
{
  "id": "resp_abc123",
  "object": "response",
  "created_at": 1234567890,
  "model": "default",
  "output": [
    {
      "type": "message",
      "id": "msg_xyz",
      "role": "assistant",
      "content": [
        {
          "type": "output_text",
          "text": "Hello! How can I help you today?"
        }
      ],
      "status": "completed"
    }
  ],
  "status": "completed",
  "usage": {
    "input_tokens": 20,
    "output_tokens": 10,
    "total_tokens": 30
  }
}
```

### Output item types

| Type | Description |
|------|-------------|
| `message` | Text response from the assistant |
| `function_call` | Tool invocation requested by the model |

## Streaming

When `stream: true` is set, the response is delivered as named SSE events. Unlike Chat Completions (which uses `data: {...}` format), the Responses API uses `event: <name>\ndata: <json>` format.

### Event mapping

| Anthropic event | Responses event | Description |
|-----------------|----------------|-------------|
| `message_start` | `response.created` | Stream begins, response object with `status: "in_progress"` |
| `content_block_start` (text) | `response.output_item.added` + `response.content_part.added` | New text message item |
| `content_block_start` (tool_use) | `response.output_item.added` | New function call item |
| `content_block_delta` (text_delta) | `response.output_text.delta` | Text content fragment |
| `content_block_delta` (input_json_delta) | `response.function_call_arguments.delta` | Function arguments fragment |
| `content_block_stop` (text) | `response.content_part.done` + `response.output_item.done` | Text item completed |
| `content_block_stop` (tool_use) | `response.function_call_arguments.done` + `response.output_item.done` | Function call completed |
| `message_stop` | `response.completed` + `data: [DONE]` | Stream ends |

Other Anthropic events (e.g. `ping`, `message_delta`) are silently skipped.

### Example streaming response

```
event: response.created
data: {"id":"resp_abc123","object":"response","model":"default","status":"in_progress","output":[]}

event: response.output_item.added
data: {"output_index":0,"item":{"id":"msg_xyz","type":"message","role":"assistant","content":[],"status":"in_progress"}}

event: response.content_part.added
data: {"output_index":0,"content_index":0,"part":{"type":"output_text","text":""}}

event: response.output_text.delta
data: {"output_index":0,"content_index":0,"delta":"Hello"}

event: response.output_text.delta
data: {"output_index":0,"content_index":0,"delta":"!"}

event: response.content_part.done
data: {"output_index":0,"content_index":0}

event: response.output_item.done
data: {"output_index":0,"item":{"id":"msg_xyz","status":"completed"}}

event: response.completed
data: {"id":"resp_abc123","status":"completed"}

data: [DONE]
```

## Reasoning configuration

The `reasoning` field maps to `RequestExtensions.reasoning_effort`:

```json
{
  "model": "default",
  "input": "Solve this problem step by step.",
  "reasoning": {
    "effort": "high"
  }
}
```

| Effort value | Description |
|-------------|-------------|
| `"low"` | Minimal reasoning |
| `"medium"` | Balanced reasoning |
| `"high"` | Deep reasoning (extended thinking) |

The effort value is forwarded to providers that support it. Anthropic backends map this to the thinking/extended-thinking configuration.

## Comparison with Chat Completions endpoint

| Aspect | `/v1/chat/completions` | `/v1/responses` |
|--------|------------------------|-----------------|
| Input format | `messages` array with roles | `input` (string or items) + `instructions` |
| Tool format | Nested `function` wrapper | Flat format (name, description, parameters) |
| System prompt | `system` role message | `instructions` field |
| Token limit | `max_tokens` | `max_output_tokens` |
| Streaming format | `data: {...}` chunks | Named `event: ...` SSE events |
| Response structure | `choices[].message` | `output[]` items |
| Multi-turn state | Stateless | `previous_response_id` (accepted but ignored) |

## Source files

| File | Purpose |
|------|---------|
| `src/server/responses_compat/mod.rs` | Module root, re-exports |
| `src/server/responses_compat/types.rs` | Request/response struct definitions |
| `src/server/responses_compat/transform.rs` | Bidirectional format conversion |
| `src/server/responses_compat/stream.rs` | SSE stream translator (Anthropic to Responses named events) |
| `src/server/handlers.rs` | HTTP handler wiring the endpoint |
