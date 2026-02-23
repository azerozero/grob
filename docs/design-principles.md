# Grob Design Principles

Grob's design philosophy is **"Simplify complex AI routing"**.

Our goal is to minimize the complexity developers face when using multiple AI providers, making every aspect of configuration, monitoring, and management intuitive.

---

## 1. Our Design Philosophy

### Simplicity First
- Hide complex AI routing logic from users, exposing only essential configurations.
- Aim for "minimum steps to desired outcome" in CLI and configuration.
- Keep technical complexity internal, user experience simple.

### Developer-First Experience
- Use terminology and structures familiar to developers.
- Config files (TOML) should be readable without documentation.
- Error messages clearly communicate "what went wrong" and "how to fix it".

### Performance as UX
- ~5MB memory, <1ms routing overhead is not just performance metrics -- it's user experience.
- Fast responses build trust, lightweight resource usage simplifies deployment.

---

## 2. CLI & Configuration Principles

### Value first, cost later
**Get users productive first, expose advanced settings later.**

- Presets (`grob preset apply medium`) give a working setup in one command.
- Manual config editing is for fine-tuning, not for getting started.
- Required vs optional fields are clearly distinguished in config comments.

### Easy to understand
**Users should instantly understand what each config option does.**

- Use concrete terminology: "Provider", "Model mapping", "Routing rule".
- Avoid abstract jargon like "Inference endpoint configuration".
- Every config section has comments explaining its purpose.

### Progressive disclosure
- `grob preset apply` for quick start.
- `~/.grob/config.toml` for customization.
- Advanced options (prompt_rules, tracing, budget) documented but not required.

---

## 3. Writing Principles

### Concise = Remove meaningless words
- Bad: "We are showing you a list of currently configured Providers"
- Good: "Provider list"

### Technical but not jargon
- Good: "Provider" -- Familiar term to developers
- Good: "Model mapping" -- Clear meaning
- Bad: "Inference endpoint configuration" -- Unnecessarily complex

### Action-oriented CLI output
- Good: `grob start`, `grob status`, `grob spend`
- Good: Error messages that suggest a fix: `"No providers configured. Run 'grob preset apply medium' to get started."`

---

## 4. Metrics and Monitoring

### Performance metrics as operational feedback
- Prometheus metrics at `/metrics` for integration with existing monitoring.
- `grob status` shows key health info at a glance.
- `grob spend` shows cost breakdown by provider and model.

### Error tracking
- Track error rate and response time per Provider.
- Rate limit warnings logged when remaining quota is low.

---

## 5. Error Handling

### Every error should explain what and how
- What went wrong (clear error type).
- How to fix it (actionable suggestion).
- HTTP errors use standard status codes with JSON error bodies.

### Fail gracefully
- Provider failures trigger automatic fallback to next mapping.
- Budget exhaustion returns HTTP 402 with clear message.
- Rate limits are logged and the next provider is tried.

---

## 6. Configuration Validation

- Validate TOML config before starting the server.
- Invalid config shows clear error message with line number.
- Smart defaults: sensible timeout, port, log level out of the box.

---

## References

### Project Documentation
- [Configuration Reference](./CONFIGURATION.md) - All config options
- [Provider Setup](./PROVIDERS.md) - Per-provider setup guides
