# How to Call Grob from Python

Send requests to a local Grob proxy using the official `anthropic` and `openai` Python SDKs. The proxy listens on `http://[::1]:13456` (IPv6 localhost) by default and accepts both Anthropic `/v1/messages` and OpenAI `/v1/chat/completions` traffic.

## Install

```bash
pip install anthropic openai
```

## Run the script

The recommended entry point is `grob exec`. It auto-starts the proxy, sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL`, and stops the server when the script exits.

```bash
grob exec -- python script.py
```

If Grob already runs, point the SDK at the proxy via `base_url`. The `api_key` argument is a placeholder header — Grob authenticates with the upstream provider via OAuth or stored secrets, so any non-empty string works.

## Anthropic SDK, non-streaming

```python
from anthropic import Anthropic

client = Anthropic(
    base_url="http://[::1]:13456",
    api_key="grob-local",  # placeholder; Grob handles real auth
)

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=256,
    messages=[{"role": "user", "content": "Summarize the Rust borrow checker in one sentence."}],
)
print(message.content[0].text)
```

## OpenAI SDK, streaming

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://[::1]:13456/v1",
    api_key="grob-local",
)

stream = client.chat.completions.create(
    model="gpt-5.4",
    messages=[{"role": "user", "content": "Stream a haiku about caching."}],
    stream=True,
)
for chunk in stream:
    delta = chunk.choices[0].delta.content
    if delta:
        print(delta, end="", flush=True)
```

## See also

- [OpenAI Compatibility](../reference/openai-compatibility.md)
- [API Compatibility Reference](../reference/api-compatibility.md)
- [Node SDK guide](sdk-node.md)
