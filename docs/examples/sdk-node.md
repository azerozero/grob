# How to Call Grob from Node.js

Send requests to a local Grob proxy using the official `@anthropic-ai/sdk` and `openai` Node SDKs. The proxy listens on `http://[::1]:13456` (IPv6 localhost) by default and accepts both Anthropic `/v1/messages` and OpenAI `/v1/chat/completions` traffic.

## Install

Use a Node.js project with a supported Node.js release. Configure Grob first
with the [getting-started tutorial](../tutorials/getting-started.md).

```bash
npm install @anthropic-ai/sdk openai
```

## Run the script

Save one of the examples below as `script.mjs`. `grob exec` starts the proxy when
needed, sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL`, and stops an instance it
started when the script exits. An already-running instance stays running.

```bash
grob exec -- node script.mjs
```

The examples read those base URLs, so a custom host or port also works. For a
separately managed proxy, set the matching base-URL variable yourself.

`apiKey` authenticates your script **to Grob**; the provider credentials are
managed separately by Grob. On an explicitly unauthenticated local proxy, the
`grob-local` placeholder satisfies the SDK. If Grob requires authentication,
set `GROB_API_KEY` to a Grob virtual key (or another credential accepted by your
configured auth mode). `grob exec` does not set this key. See
[Authentication](../reference/authentication.md).

Both SDKs can request the same Grob model: choose one listed by `grob model` and
set `GROB_MODEL` if it differs from the example's `claude-sonnet-4-6`. The request
uses real provider capacity and may incur charges.

## Anthropic SDK, non-streaming

```javascript
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  baseURL: process.env.ANTHROPIC_BASE_URL ?? "http://[::1]:13456",
  apiKey: process.env.GROB_API_KEY ?? "grob-local",
});

const message = await client.messages.create({
  model: process.env.GROB_MODEL ?? "claude-sonnet-4-6",
  max_tokens: 256,
  messages: [{ role: "user", content: "Summarize the Rust borrow checker in one sentence." }],
});
console.log(message.content[0].text);
```

## OpenAI SDK, streaming

```javascript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: process.env.OPENAI_BASE_URL ?? "http://[::1]:13456/v1",
  apiKey: process.env.GROB_API_KEY ?? "grob-local",
});

const stream = await client.chat.completions.create({
  model: process.env.GROB_MODEL ?? "claude-sonnet-4-6",
  max_tokens: 256,
  messages: [{ role: "user", content: "Stream a haiku about caching." }],
  stream: true,
});

for await (const chunk of stream) {
  const delta = chunk.choices[0]?.delta?.content;
  if (delta) {
    process.stdout.write(delta);
  }
}
```

## See also

- [API Compatibility](../reference/api-compatibility.md)
- [Provider Setup](../how-to/providers.md)
- [Python SDK guide](sdk-python.md)
