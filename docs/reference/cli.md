# CLI Reference

## Global options

| Option | Env var | Description |
|--------|---------|-------------|
| `-c, --config <PATH\|URL>` | `GROB_CONFIG` | Path or URL to config file (default: `~/.grob/config.toml`) |
| `--version` | | Print version |
| `--help` | | Print help |

Shorthand: `grob -- <cmd>` is equivalent to `grob exec -- <cmd>`.

## Commands

### `grob start`

Start the routing proxy. In foreground mode, the server blocks until Ctrl+C. In detached mode, it spawns a background daemon and exits.

| Flag | Description |
|------|-------------|
| `-p, --port <PORT>` | Override listen port |
| `-d, --detach` | Run in background (daemon mode) |

```bash
grob start              # Start in foreground
grob start -d           # Start in background
grob start -d -p 9000   # Start on a different port
```

Prints model upgrade hints (e.g., deprecated model names) and missing credential warnings at startup.

### `grob stop`

Stop a running instance. Finds the PID via the `/health` endpoint and sends SIGTERM (Unix) or taskkill (Windows). Cleans up stale PID files.

### `grob restart`

Stop any running instance and start a new one.

| Flag | Description |
|------|-------------|
| `-d, --detach` | Run in background |

```bash
grob restart -d         # Restart as daemon
```

### `grob status`

Check service status. Displays:

- Whether the server is running (with PID)
- Bind address and port
- Active preset name
- Project overlay path (if `.grob.toml` exists)
- Router configuration (default, think, background, websearch models)
- GDPR mode and region (if enabled)
- All providers with auth status and region tags
- All models with provider mappings and strategy labels
- Current month spend vs budget

### `grob spend`

Show current month's spend breakdown by provider and model, with budget status. Displays:

- Total spend vs global budget limit (with percentage)
- Per-provider spend with provider-level budgets
- Per-model spend with model-level budgets
- Remaining global budget
- Subscription providers are labeled accordingly

### `grob model`

Display configured models and their router assignments (default, think, websearch, background) and enabled providers.

### `grob validate`

Test all configured providers with real API calls. Initializes the full provider registry and runs a validation request against each model mapping. Reports success, failure, and latency.

```bash
grob validate
```

### `grob doctor`

Run 11 diagnostic checks:

1. Config file existence
2. Config version
3. Provider credentials (count with/without keys)
4. Model configuration
5. Service health (`/health` endpoint)
6. Port availability (if service not running)
7. DLP status
8. Security settings (rate limit, circuit breaker)
9. Storage backend (redb)
10. Missing environment variables
11. Podman availability

```bash
grob doctor
```

### `grob exec`

Launch a command behind the Grob proxy. Automatically starts Grob if not running, sets environment variables to point at the proxy, runs the command, and stops Grob when it exits.

Alias: `grob launch`

| Flag | Description |
|------|-------------|
| `-p, --port <PORT>` | Override listen port |
| `--no-stop` | Keep Grob running after the command exits |

Environment variables set for the child process:

| Variable | Value |
|----------|-------|
| `ANTHROPIC_BASE_URL` | `http://<host>:<port>` |
| `OPENAI_BASE_URL` | `http://<host>:<port>/v1` |
| `ANTHROPIC_URL` | `http://<host>:<port>/v1` |
| `OPENAI_URL` | `http://<host>:<port>/v1` |

```bash
grob exec -- claude              # Launch Claude Code
grob exec -- aider               # Launch Aider
grob exec -- opencode            # Launch OpenCode
grob exec --no-stop -- my-tool   # Keep proxy running after exit
grob -- claude                   # Shorthand (trailing args)
```

### `grob run`

Run in container/foreground mode. Binds to `::` (all interfaces), outputs JSON logs, no PID file, supports graceful shutdown via SIGTERM/SIGUSR1.

| Flag | Env var | Description |
|------|---------|-------------|
| `-p, --port <PORT>` | `GROB_PORT` | Listen port |
| `--host <HOST>` | `GROB_HOST` | Bind address |
| `--log-level <LEVEL>` | `GROB_LOG_LEVEL` | Log level |
| `--json-logs` | `GROB_JSON_LOGS` | JSON log format |

```bash
grob run --port 8080 --json-logs    # Container-friendly invocation
```

### `grob preset`

Manage configuration presets.

| Subcommand | Description |
|------------|-------------|
| `grob preset list` | Show available presets (built-in + installed) |
| `grob preset info <name>` | Show providers, models, env vars, router config, and requirements |
| `grob preset apply <name> [-r\|--reload]` | Apply a preset (backs up current config). With `--reload`, hot-reloads the running server. |
| `grob preset export <name>` | Save current config as a reusable preset (strips `[server]`, replaces API keys with env var references) |
| `grob preset install <source>` | Install presets from a git repo or local path |
| `grob preset sync` | Sync presets from configured remote |

```bash
grob preset list
grob preset info perf
grob preset apply medium --reload
grob preset export my-setup
grob preset install https://github.com/org/presets.git
```

### `grob key`

Manage virtual API keys for multi-tenant deployments.

#### `grob key create`

Create a new virtual API key.

| Flag | Description |
|------|-------------|
| `-n, --name <NAME>` | Human-readable key name (required) |
| `-t, --tenant <TENANT>` | Tenant identifier (required) |
| `-b, --budget <USD>` | Monthly budget in USD (optional) |
| `-r, --rate-limit <RPS>` | Rate limit in requests per second (optional) |
| `-a, --allowed-models <M1,M2>` | Comma-separated allowed model names (optional) |
| `-e, --expires <DAYS>` | Key expiration in days from now (optional) |

```bash
grob key create -n "team-alpha" -t "alpha" -b 100.0 -r 10
grob key create -n "ci-bot" -t "ci" -a "claude-haiku-4-5,gpt-4o" -e 30
```

The full key is shown once at creation and cannot be retrieved afterward.

#### `grob key list`

List all virtual API keys.

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format instead of table |

```bash
grob key list
grob key list --json
```

#### `grob key revoke`

Revoke a virtual API key by UUID or prefix.

```bash
grob key revoke <uuid>
grob key revoke grob-ak-xxxx    # Prefix match
```

### `grob watch` (requires `--features watch`)

Live traffic inspector TUI. Connects to the running server's SSE endpoint (`/api/events`) and displays a ratatui dashboard with provider health, live request stream, and DLP alerts.

```bash
grob watch
```

Keyboard: `q` to quit, `p` to pause/resume.

### `grob env`

Check which environment variables are required by configured providers. Shows whether each variable is set or missing.

```bash
grob env
```

### `grob connect`

Interactive credential setup for providers. Without arguments, checks all providers. With a provider name, sets up that specific provider only.

```bash
grob connect              # Check all providers
grob connect anthropic    # Set up Anthropic credentials
```

### `grob init`

Create a per-project `.grob.toml` file in the current directory. The overlay file can override router models, budget limits, and prompt rules without changing the global config.

```bash
grob init
```

### `grob config-diff`

Compare local config against a preset or remote config. Defaults to comparing against the active preset.

```bash
grob config-diff                  # Compare against active preset
grob config-diff medium           # Compare against a specific preset
```

Reports section-level differences for `[router]`, `[[providers]]`, and `[[models]]`.

### `grob setup`

Interactive first-run setup wizard (auto-triggered when no `config.toml` exists). Guides through:

1. Tool selection (Claude Code, Codex CLI, Forge, Aider, Continue.dev, Cursor)
2. Provider authentication (OAuth vs API key per provider)
3. Fallback provider (OpenRouter)
4. Compliance mode (Standard, DLP only, GDPR, EU AI Act, Enterprise security, Local-only)
5. Monthly budget cap
6. Provider status validation

### `grob upgrade`

Zero-downtime upgrade using SO_REUSEPORT (Unix). Spawns a new process on the same port, waits for the new process to pass health check, then signals the old process to drain via SIGUSR1.

```bash
grob upgrade
```

On Windows, a brief interruption occurs (stop-then-start) because SO_REUSEPORT is unavailable.

### `grob completions`

Generate shell completions for the specified shell.

```bash
grob completions zsh > ~/.zfunc/_grob
grob completions bash > /etc/bash_completion.d/grob
grob completions fish > ~/.config/fish/completions/grob.fish
```

### `grob setup-completions`

Automatically install shell completions for the current shell (detects zsh, bash, or fish).

```bash
grob setup-completions
```

### `grob harness` (requires `--features harness`)

Record & replay sandwich testing harness.

| Subcommand | Description |
|------------|-------------|
| `grob harness record -o <path>` | Print instructions for recording traffic via `GROB_HARNESS_RECORD` env var |
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
