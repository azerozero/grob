# How to Call Grob from Python

Send requests to a local Grob proxy using the official `anthropic` and `openai` Python SDKs. The proxy listens on `http://[::1]:13456` (IPv6 localhost) by default and accepts both Anthropic `/v1/messages` and OpenAI `/v1/chat/completions` traffic.

## Install

Use a Python environment where you can install packages. Configure Grob first
with the [getting-started tutorial](../tutorials/getting-started.md).

```bash
python3 -m pip install anthropic openai
```

## Run the script

Save one of the examples below as `script.py`. `grob exec` starts the proxy when
needed, sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL`, and stops an instance it
started when the script exits. An already-running instance stays running.

```bash
grob exec -- python3 script.py
```

The examples read those base URLs, so a custom host or port also works. For a
separately managed proxy, set the matching base-URL variable yourself.

`api_key` authenticates your script **to Grob**; the provider credentials are
managed separately by Grob. On an explicitly unauthenticated local proxy, the
`grob-local` placeholder satisfies the SDK. If Grob requires authentication,
set `GROB_API_KEY` to a Grob virtual key (or another credential accepted by your
configured auth mode). `grob exec` does not set this key. See
[Authentication](../reference/authentication.md).

Both SDKs can request the same Grob model: choose one listed by `grob model` and
set `GROB_MODEL` if it differs from the example's `claude-sonnet-4-6`. The request
uses real provider capacity and may incur charges.

## Anthropic SDK, non-streaming

```python
import os
from anthropic import Anthropic

client = Anthropic(
    base_url=os.environ.get("ANTHROPIC_BASE_URL", "http://[::1]:13456"),
    api_key=os.environ.get("GROB_API_KEY", "grob-local"),
)

message = client.messages.create(
    model=os.environ.get("GROB_MODEL", "claude-sonnet-4-6"),
    max_tokens=256,
    messages=[{"role": "user", "content": "Summarize the Rust borrow checker in one sentence."}],
)
print(message.content[0].text)
```

## OpenAI SDK, streaming

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url=os.environ.get("OPENAI_BASE_URL", "http://[::1]:13456/v1"),
    api_key=os.environ.get("GROB_API_KEY", "grob-local"),
)

stream = client.chat.completions.create(
    model=os.environ.get("GROB_MODEL", "claude-sonnet-4-6"),
    max_tokens=256,
    messages=[{"role": "user", "content": "Stream a haiku about caching."}],
    stream=True,
)
for chunk in stream:
    if not chunk.choices:
        continue
    delta = chunk.choices[0].delta.content
    if delta:
        print(delta, end="", flush=True)
```

## See also

- [API Compatibility](../reference/api-compatibility.md)
- [Provider Setup](../how-to/providers.md)
- [Node SDK guide](sdk-node.md)
