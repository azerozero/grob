# Troubleshooting

Common errors and how to fix them.

Start with `grob doctor` for local configuration and credential diagnostics.
Use `grob validate` only when you want real provider calls; it may consume quota.
For the status returned by an API call, also check the [error reference](../reference/errors.md).

---

## Connection refused

**Symptom:** `Connection refused` or `ECONNREFUSED` when calling `http://[::1]:13456/v1/messages`.

**Possible causes:** Grob is not running, or the client uses a different listener address or port.

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

If you changed the host/port in config, make sure your client points to the right address. The default is `[::1]:13456` (IPv6 localhost). Use `grob exec` instead of setting `ANTHROPIC_BASE_URL` manually to avoid host/port mismatches.

---

## All providers failed

**Symptom:** No provider returns a usable response. The final status can reflect
the last provider error, including 401, 429 or 5xx; it is not always 502.

**Causes and fixes:**

1. **Missing API keys.** Check that the required environment variables are set:

   ```bash
   grob doctor     # Checks local config, credentials and service status
   grob validate   # Tests each provider with a real API call
   ```

2. **Wrong or expired credential.** Check the provider named in the error.
   Follow [provider setup](providers.md) for API keys or
   [OAuth setup](oauth-setup.md) for browser authentication. A successful local
   credential check does not prove that the provider accepts the credential.

3. **Circuit breaker open.** After repeated failures, the circuit breaker blocks requests to a provider for 30 seconds. Check the `/metrics` endpoint:

   ```bash
   curl --fail --silent --globoff 'http://[::1]:13456/metrics' | grep circuit_breaker
   ```

   Wait 30 seconds for half-open probes, or restart the service to reset all breakers:

   ```bash
   grob restart -d
   ```

4. **Provider outage.** If one provider is down, Grob automatically falls through to the next mapping by priority. If ALL providers for a model are down, you will see this error. Check provider status pages.

---

## Budget exceeded

**Symptom:** HTTP 402 response with `"Budget exceeded"`.

**Cause:** Monthly spend has reached the configured limit.

**Check current spend:**

```bash
grob spend
```

**Fix options:**

1. Check which limit was exceeded (global, provider, model or identity).
   Increase the relevant limit only if the extra spend is intended. For example:

   ```toml
   [budget]
   monthly_limit_usd = 50.0
   ```

2. Reload with an administrative credential. Set `GROB_ADMIN_TOKEN` below to a
   configured administrator token; it is not a provider API key:

   ```bash
   curl --fail-with-body --globoff -X POST 'http://[::1]:13456/api/config/reload' \
     -H "Authorization: Bearer $GROB_ADMIN_TOKEN"
   ```

Spend resets automatically at the start of each calendar month.

---

## Rate limited (429)

**Symptom:** HTTP 429 with `"Rate limit exceeded. Please slow down."` and a `Retry-After` header.

**Cause:** Too many requests per second from the same tenant/API key/IP.

The Grob request limiter is disabled by default (`rate_limit_rps = 0`). A
preset, tenant override or policy can enable a limit. Check the active settings.

**Fix options:**

1. Wait for the `Retry-After` duration and retry.

2. Increase the rate limit in config:

   ```toml
   [security]
   rate_limit_rps = 200
   rate_limit_burst = 400
   ```

Provider throttling can also reach the client as HTTP 429 after retries and
fallbacks. Increasing Grob's local limit will not fix a provider quota. Use the
error body and the metrics `grob_ratelimit_hits_total` (upstream) and
`grob_ratelimit_rejected_total` (local) to distinguish them.

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
curl --fail --silent --globoff 'http://[::1]:13456/metrics' | grep grob_circuit_breaker_state
# 0 = Closed, 1 = Open, 2 = HalfOpen
```

**Fix:**

- Wait for the 30-second timeout. Grob will automatically probe and recover.
- If the provider is back online and you want to reset immediately, restart the service:

  ```bash
  grob restart -d
  ```

If metrics are protected, include the separate metrics bearer token described
in the [deployment guide](deploy.md#protect-metrics-with-a-bearer-token).

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
   ```

   Identify the owning process before stopping anything else; another application
   may be using this port.

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

2. Fix the TOML field and line named in the error, then retry. Compare the setting
   with the [configuration reference](../reference/configuration.md).

Apply a preset only if you intend to replace the current routing and provider
configuration. `grob preset apply <name>` saves a `config.toml.backup` when a
current configuration exists; it is not a repair command for a typo.

---

## Diagnostic commands

When in doubt, run the full diagnostic suite:

```bash
grob doctor     # Check local config, credentials, environment and service
grob validate   # Test every provider+model with real API calls
grob status     # Service status, loaded models, active preset
grob spend      # Monthly spend and budget
```
