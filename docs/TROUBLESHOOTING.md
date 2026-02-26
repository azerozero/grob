# Troubleshooting

Common errors and how to fix them.

---

## Connection refused

**Symptom:** `Connection refused` or `ECONNREFUSED` when calling `http://[::1]:13456/v1/messages`.

**Cause:** Grob is not running.

**Fix:**

```bash
# Check status
grob status

# Start the service
grob start -d

# Or start and launch your tool in one step
grob exec -- claude
```

If `grob status` reports "running" but connections still fail, the PID file may be stale:

```bash
grob stop
grob start -d
```

If you changed the host/port in config, make sure your client points to the right address. The default is `[::1]:13456` (IPv6 localhost).

---

## All providers failed

**Symptom:** HTTP 502 response with `"All providers failed for model ..."`.

**Causes and fixes:**

1. **Missing API keys.** Check that the required environment variables are set:

   ```bash
   grob doctor     # Shows config, providers, env vars, connectivity
   grob validate   # Tests each provider with a real API call
   ```

2. **Wrong API key.** Verify your key is valid by calling the provider directly:

   ```bash
   curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" \
     https://api.anthropic.com/v1/messages \
     -d '{"model":"claude-sonnet-4-20250514","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
   ```

3. **Circuit breaker open.** After repeated failures, the circuit breaker blocks requests to a provider for 30 seconds. Check the `/metrics` endpoint:

   ```bash
   curl -s http://[::1]:13456/metrics | grep circuit_breaker
   ```

   Wait 30 seconds for half-open probes, or restart the service to reset all breakers:

   ```bash
   grob restart -d
   ```

4. **Provider outage.** If one provider is down, Grob automatically falls through to the next mapping by priority. If ALL providers for a model are down, you will see this error. Check provider status pages.

---

## Budget exceeded

**Symptom:** HTTP 429 response with `"Budget exceeded"`.

**Cause:** Monthly spend has reached the configured limit.

**Check current spend:**

```bash
grob spend
```

**Fix options:**

1. Increase the budget in `~/.grob/config.toml`:

   ```toml
   [budget]
   monthly_limit_usd = 50.0
   ```

2. Set to 0 to disable the budget cap:

   ```toml
   [budget]
   monthly_limit_usd = 0.0
   ```

3. Reload config without restarting:

   ```bash
   curl -X POST http://[::1]:13456/api/config/reload
   ```

Spend resets automatically at the start of each calendar month.

---

## Rate limited (429)

**Symptom:** HTTP 429 with `"Rate limit exceeded. Please slow down."` and a `Retry-After` header.

**Cause:** Too many requests per second from the same tenant/API key/IP.

**Default limits:** 100 requests/second with a burst of 200.

**Fix options:**

1. Wait for the `Retry-After` duration and retry.

2. Increase the rate limit in config:

   ```toml
   [security]
   rate_limit_rps = 200
   rate_limit_burst = 400
   ```

3. Disable the security middleware entirely (not recommended for production):

   ```toml
   [security]
   enabled = false
   ```

Note: This is the Grob-level rate limit. Upstream providers have their own rate limits. If you see `429` responses from the provider itself, those are reported as provider errors, not Grob rate-limit errors. The metric `grob_ratelimit_hits_total` tracks upstream provider throttling, while `grob_ratelimit_rejected_total` tracks Grob-level rejections.

---

## Circuit breaker open

**Symptom:** Requests to a specific provider are immediately rejected. Logs show `"Circuit breaker 'provider_name' transitioning Closed -> Open"`.

**Cause:** The provider accumulated 5 consecutive failures. The circuit breaker enters Open state for 30 seconds, then transitions to HalfOpen and probes with limited requests.

**Behavior:**

| State | Description |
|-------|-------------|
| Closed | Normal operation. Requests pass through. |
| Open | 5+ consecutive failures. Requests fail fast for 30 seconds. |
| HalfOpen | After timeout. Allows up to 3 probe requests. 3 successes = Closed, 1 failure = Open. |

**Check circuit breaker state:**

```bash
curl -s http://[::1]:13456/metrics | grep grob_circuit_breaker_state
# 0 = Closed, 1 = Open, 2 = HalfOpen
```

**Fix:**

- Wait for the 30-second timeout. Grob will automatically probe and recover.
- If the provider is back online and you want to reset immediately, restart the service:

  ```bash
  grob restart -d
  ```

- To disable the circuit breaker (not recommended):

  ```toml
  [security]
  circuit_breaker = false
  ```

---

## Port already in use

**Symptom:** `"Failed to bind to [::1]:13456: Address already in use"`.

**Cause:** Another Grob instance (or another process) is already listening on that port.

**Fix:**

1. Check what is using the port:

   ```bash
   lsof -i :13456
   ```

2. If it is a stale Grob process, stop it:

   ```bash
   grob stop
   # or force kill:
   kill $(lsof -t -i :13456)
   ```

3. Or run on a different port:

   ```bash
   grob start -d -p 9000
   ```

   Then update your client to point at the new port.

The OAuth callback server also binds to `127.0.0.1:1455`. If that port is taken, OAuth flows will not work, but the main proxy will still function.

---

## Config parse error on startup

**Symptom:** `"Failed to parse config"` or `"TOML parse error"` on startup.

**Fix:**

1. Validate your config file:

   ```bash
   grob doctor
   ```

2. Start fresh from a preset:

   ```bash
   grob preset apply perf
   ```

   This backs up your current config to `config.toml.bak` before overwriting.

---

## Diagnostic commands

When in doubt, run the full diagnostic suite:

```bash
grob doctor     # Check config, providers, env vars, connectivity
grob validate   # Test every provider+model with real API calls
grob status     # Service status, loaded models, active preset
grob spend      # Monthly spend and budget
```
