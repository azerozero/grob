# Getting Started with Grob

Install Grob, connect an Anthropic account, and run Claude Code through the proxy.
Choose a subscription login or an API key below. The initial subscription preset
uses one provider; fallback requires additional mappings.

## In a hurry

With Homebrew, Claude Code already installed, and an Anthropic Pro or Max
subscription:

```bash
brew install azerozero/tap/grob   # or: curl -fsSL https://raw.githubusercontent.com/azerozero/grob/main/scripts/install.sh | sh
grob preset apply perf
grob exec -- claude
```

A terminal prompt guides you through OAuth if no usable token is stored. After
that, `grob status`, `grob spend`, and
`grob doctor` tell you what is happening. The rest of this page explains each
step and covers the API-key path.

## Prerequisites

- macOS or Linux. The prebuilt releases and shell installer target these platforms.
- Claude Code installed and available as `claude`. Grob does not install your AI tool.
- An Anthropic Pro/Max subscription or an Anthropic API key for this tutorial.
  For other providers or a local Ollama instance, see [Provider Setup](../how-to/providers.md).
- Homebrew, or `curl` for the install script. A Rust toolchain is only needed to
  [build from source](../how-to/contribute.md).

## Step 1: Install Grob

Grob ships as a standalone binary. On macOS or Linux, choose one method:

**Option A: Install script (recommended)**

```bash
curl -fsSL https://raw.githubusercontent.com/azerozero/grob/main/scripts/install.sh | sh
```

**Option B: Homebrew (macOS / Linux)**

```bash
brew install azerozero/tap/grob
```

The install script fetches the latest release binary for your platform from
[GitHub Releases](https://github.com/azerozero/grob/releases). Container users
can pull `ghcr.io/azerozero/grob:latest` instead.

Verify the installation:

```bash
grob --help
```

You should see a list of available commands.

## Step 2: Choose how Grob authenticates

Use **one** of these paths. An API key and a subscription login are separate
credentials; exporting an API key does not change an OAuth preset.

### Option A: Anthropic subscription

Inspect and apply the `perf` preset:

```bash
grob preset info perf
grob preset apply perf
```

This creates `~/.grob/config.toml` with Anthropic OAuth and no fallback provider.
On the first interactive launch, follow the authentication prompt and complete
the browser login. An existing valid token can be reused.

### Option B: Anthropic API key

Set your provider key in the same terminal that will start Grob, then run the
interactive setup wizard:

```bash
export ANTHROPIC_API_KEY="replace-with-your-provider-key"
grob setup
```

Choose Claude Code. The wizard detects `ANTHROPIC_API_KEY` and uses API-key
authentication. For a simple first run, choose no fallback or custom endpoint,
then choose a budget and review the recap before saving. You do not need a
Pro/Max subscription for this path. Provider usage is billed to the API account.

Do not apply `perf` afterward: that would replace your provider configuration
with its OAuth settings. To change authentication later, use
`grob setup --edit auth`.

### Other configurations

`grob preset list` lists available presets, and `grob preset info <name>` shows
their providers and required credentials. See [Provider Setup](../how-to/providers.md)
for other accounts and [How to Configure](../how-to/configure.md) for routing
and budget settings.

## Step 3: Start Grob and launch your tool

`grob exec` starts the proxy when needed, sets the tool's base URLs, and launches
your tool. It stops a proxy that it started when the tool exits; an existing
instance keeps running.

```bash
grob exec -- claude
```

For a proxy that stays running between sessions, use separate commands:

```bash
grob start -d
ANTHROPIC_BASE_URL='http://[::1]:13456' claude
grob stop
```

(The default bind address is `::1`, IPv6 localhost. For an IPv4-only system, configure `[server] host = "127.0.0.1"` before starting and use `http://127.0.0.1:13456`.)

The initial configuration uses local access without an inbound API key. If you
enable Grob authentication later, your client also needs its own Grob credential;
`grob exec` sets URLs, not authentication headers. See
[Authentication](../reference/authentication.md).

## Step 4: Verify it works

In another terminal, check Grob's status:

```bash
grob status
```

Check the `Service`, `Address` and `Preset` lines. The service should be running
at your configured listener address; the preset depends on the setup path you
chose. If it is stopped, keep the coding tool open while checking status.

Run a diagnostic check:

```bash
grob doctor
```

This checks configuration, local credential readiness, storage, and the local
service. It does not prove that a provider will accept a request. For an optional
end-to-end check, `grob validate` sends real requests to configured providers and
can incur charges.

## Step 5: Check your spend

After some usage, check what it cost:

```bash
grob spend
```

This shows a breakdown by provider and model for the current month.

## What just happened?

When you ran `grob exec -- claude`:

1. Grob loaded `~/.grob/config.toml`
2. It started an HTTP server on `[::1]:13456` (IPv6 localhost)
3. It set `ANTHROPIC_BASE_URL=http://[::1]:13456` so Claude Code sends requests to Grob
4. For each request, Grob classified the task type (thinking, default, web search, background)
5. It selected the configured model for that task type and tried its provider mappings
6. If a provider failed and another eligible mapping existed, it tried the next one
7. Responses were streamed back to Claude Code, with spend tracking and DLP scanning when enabled

## Next steps

- **Customize your config**: Edit `~/.grob/config.toml` directly -- see [Configuration Reference](../reference/configuration.md)
- **Add more providers**: See [Provider Setup](../how-to/providers.md) for setup recipes
- **Set a budget**: Add `[budget] monthly_limit_usd = 50.0` to your config -- see [How to Configure](../how-to/configure.md)
- **Understand the architecture**: Read the [Architecture Overview](../explanation/architecture.md)
- **Fix problems**: Check [Troubleshooting](../how-to/troubleshooting.md)
