# CLI Reference

## Global options

| Option | Env var | Description |
|--------|---------|-------------|
| `-c, --config <PATH\|URL>` | `GROB_CONFIG` | Path or URL to config file (default: `~/.grob/config.toml`) |
| `--version` | | Print version |
| `--help` | | Print help |

## Commands

### `grob start`

Start the routing proxy.

| Flag | Description |
|------|-------------|
| `-p, --port <PORT>` | Override listen port |
| `-d, --detach` | Run in background (daemon mode) |

```bash
grob start -d           # Start in background
grob start -d -p 9000   # Start on a different port
```

### `grob stop`

Stop a running instance. Finds the PID via the `/health` endpoint and sends SIGTERM (Unix) or taskkill (Windows).

### `grob restart`

Stop and start the service.

| Flag | Description |
|------|-------------|
| `-d, --detach` | Run in background |

### `grob status`

Check service status. Shows whether the server is running, active preset, loaded models, and current spend summary.

### `grob spend`

Show current month's spend breakdown by provider and model, with budget status.

### `grob model`

Display configured models with their provider mappings and priorities.

### `grob validate`

Test all configured providers with real API calls. Reports success, failure, and latency for each provider/model pair.

### `grob doctor`

Run diagnostic checks: config validation, environment variables, provider connectivity, OAuth token status.

### `grob exec`

Launch a command behind the Grob proxy. Automatically starts Grob if not running, sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` to point at the proxy, runs the command, and stops Grob when it exits.

Alias: `grob launch`

| Flag | Description |
|------|-------------|
| `-p, --port <PORT>` | Override listen port |
| `--no-stop` | Keep Grob running after the command exits |

```bash
grob exec -- claude              # Launch Claude Code
grob exec -- aider               # Launch Aider
grob exec --no-stop -- my-tool   # Keep proxy running after exit
grob -- claude                   # Shorthand (trailing args)
```

### `grob run`

Run in container/foreground mode. Binds to `0.0.0.0`, outputs JSON logs, no PID file, supports graceful shutdown via SIGTERM.

| Flag | Env var | Description |
|------|---------|-------------|
| `-p, --port <PORT>` | `GROB_PORT` | Listen port |
| `--host <HOST>` | `GROB_HOST` | Bind address |
| `--log-level <LEVEL>` | `GROB_LOG_LEVEL` | Log level |
| `--json-logs` | `GROB_JSON_LOGS` | JSON log format |

### `grob preset`

Manage presets.

| Subcommand | Description |
|------------|-------------|
| `grob preset list` | Show available presets (built-in + user) |
| `grob preset info <name>` | Show providers, models, and required env vars |
| `grob preset apply <name>` | Apply a preset (backs up current config to `.bak`) |
| `grob preset export <name>` | Save current config as a reusable preset |
| `grob preset install <source>` | Install presets from a git repo or local path |
| `grob preset sync` | Sync presets from configured remote |

### `grob env`

Check which environment variables are required by configured providers.

### `grob connect`

Interactive credential setup for providers. Without arguments, checks all providers. With a provider name, sets up that specific provider.

```bash
grob connect              # Check all providers
grob connect anthropic    # Set up Anthropic credentials
```

### `grob init`

Create a per-project `.grob.toml` file in the current directory with router overrides.

### `grob config-diff`

Compare local config against a preset or remote config URL.

```bash
grob config-diff medium                           # Compare against preset
grob config-diff https://example.com/grob.toml    # Compare against remote
```

### `grob upgrade`

Zero-downtime upgrade using SO_REUSEPORT. Spawns a new process on the same port, waits for health check, then signals the old process to drain.

### `grob completions`

Generate shell completions for the specified shell.

```bash
grob completions zsh > ~/.zfunc/_grob
grob completions bash > /etc/bash_completion.d/grob
grob completions fish > ~/.config/fish/completions/grob.fish
```

### `grob setup-completions`

Automatically install shell completions for the current shell (detects zsh, bash, or fish).

### `grob harness` (requires `--features harness`)

Record & replay sandwich testing harness. Requires building with the `harness` feature flag.

| Subcommand | Description |
|------------|-------------|
| `grob harness record -o <path>` | Prints instructions for recording traffic via `GROB_HARNESS_RECORD` env var |
| `grob harness replay -t <tape>` | Replay recorded traffic through grob with a mock backend |

Replay flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --tape <PATH>` | (required) | Path to `.tape.jsonl` file |
| `-u, --target <URL>` | `http://[::1]:13456` | Grob target URL |
| `-c, --concurrency <N>` | `10` | Maximum concurrent requests |
| `-q, --qps <N>` | `0` (unlimited) | Target queries per second |
| `--mock-port <PORT>` | `0` (ephemeral) | Mock backend port |
| `--mock-latency-ms <MS>` | `50` | Simulated latency |
| `--error-rate <RATE>` | `0.0` | Fraction of mock errors (0.0-1.0) |
| `--duration <SECS>` | `0` (no limit) | Maximum replay duration |

```bash
# Build with harness feature
cargo build --features harness

# Record traffic
GROB_HARNESS_RECORD=traffic.tape.jsonl grob start

# Replay against a running grob instance
grob harness replay -t traffic.tape.jsonl -c 20 --qps 50
```
