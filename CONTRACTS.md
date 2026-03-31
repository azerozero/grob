# CONTRACTS.md — Functional Intentions & Behavioral Contracts

> This file records the **intended behavior** of critical functions and APIs.
> It is the reference against which code is compared to detect **silent semantic drift**:
> changes that compile, pass tests, but violate the original intention.
>
> **Maintained by:** grob maintainers
> **Read by:** Claude Code (autophagy scan), code reviewers, QA
> **Update policy:** Update this file when a drift is intentional (new requirement).
> Never update it to match a bug — fix the code instead.

---

## dispatch(ctx, request)

**Module:** `src/server/dispatch/mod.rs`
**Intention:** Execute the full request pipeline in a strict, ordered sequence: DLP input scan, MCP tool calibration, pledge filtering, cache lookup, routing, provider mapping resolution, tool layer processing, cache hit check, fan-out (if configured), and finally the provider fallback loop. Returns either a streaming or complete response.

**Invariants:**
- INV-1 (Pipeline order): Steps must execute in the documented order (DLP -> MCP -> pledge -> cache key -> route -> resolve mappings -> tool layer -> cache hit -> fan-out -> provider loop). No step may be skipped except when gated by feature flags.
- INV-2 (DLP before provider): DLP input scanning must always complete before any data is sent to an external provider. A DLP block must prevent the request from reaching any provider.
- INV-3 (Fallback exhaustion): The provider loop must try all available mappings in order before returning an error. Circuit-broken providers are skipped, not retried.
- INV-4 (Atomic routing): The routing decision is computed once and used for all provider attempts within a single dispatch. Re-routing mid-dispatch is not allowed.

**Preconditions:**
- `ctx` contains a valid `AppState` snapshot and request metadata
- `request` is a well-formed `CanonicalRequest` (parsed from Anthropic or OpenAI format)

**Postconditions:**
- On success: returns `DispatchResult` (Streaming, Complete, or FanOut)
- On failure: returns `AppError` with a specific error variant
- DLP events are emitted for every DLP action taken
- Spend is recorded after successful provider response

**Boundary behavior:**
- No providers available: returns `AppError` (after exhausting all fallbacks)
- DLP blocks request: returns error before any provider is contacted
- Cache hit on non-streaming: returns immediately without contacting provider

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- Any provider call that happens before `scan_dlp_input`
- Any routing decision that changes after step 3
- Provider loop that does not iterate over all available mappings

---

## Router::route(request)

**Module:** `src/router/mod.rs`
**Intention:** Classify an incoming request into a route type and resolve the target model name by evaluating rules in strict priority order: WebSearch > Background > AutoMap > Subagent > PromptRules > Think > Default.

**Invariants:**
- INV-1 (Priority order): A higher-priority rule always wins. If a request matches both WebSearch and Think, WebSearch is returned.
- INV-2 (Determinism): Given the same request and config, `route()` always returns the same `RouteDecision`.
- INV-3 (Auto-map mutation): Auto-mapping mutates `request.model` in place. This mutation must only happen if no higher-priority rule matched, and must happen before prompt-rule evaluation.
- INV-4 (Single match): Exactly one route type is returned per call. The function never returns multiple matches.

**Preconditions:**
- `request` is a valid `CanonicalRequest` with a model name
- Router is initialized with compiled regexes from config

**Postconditions:**
- Returns a `RouteDecision` with `model_name`, `route_type`, and optional `matched_prompt`
- If auto-mapping matched, `request.model` is mutated to the default model

**Boundary behavior:**
- No rules match: returns `RouteType::Default` with the original (or auto-mapped) model name
- Invalid regex in config: the rule is skipped at construction time (logged as warning), never evaluated

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- Rule evaluation order changed (e.g., Think evaluated before PromptRules)
- Auto-map that does not mutate `request.model`
- New route type added but not in priority chain

---

## transform_openai_to_canonical(openai_req)

**Module:** `src/server/openai_compat/transform.rs`
**Intention:** Convert an OpenAI `/v1/chat/completions` request into the internal `CanonicalRequest` format, preserving all semantically meaningful fields. System messages become `SystemPrompt`, tool messages are merged into user messages when consecutive.

**Invariants:**
- INV-1 (Roundtrip fidelity): `transform_canonical_to_openai(provider_response)` must produce a valid OpenAI response for any `CanonicalRequest` produced by this function. No field may be silently dropped that would change the LLM's behavior.
- INV-2 (Role mapping): OpenAI "system" -> `SystemPrompt`, "user" -> user message, "assistant" -> assistant message (with tool_calls), "tool" -> user message with `ToolResult` blocks.
- INV-3 (Consecutive tool merge): Consecutive "tool" role messages are merged into a single user message with multiple `ToolResult` blocks, not scattered across separate messages.
- INV-4 (Memory safety): Pre-allocation is capped at 1024 to prevent memory exhaustion from malicious input.

**Preconditions:**
- `openai_req` is a deserialized `OpenAIRequest` (may contain any valid OpenAI message roles)

**Postconditions:**
- Returns `Ok(CanonicalRequest)` with all messages converted
- Unsupported roles are skipped with a warning log

**Boundary behavior:**
- Empty messages array: returns a valid `CanonicalRequest` with no messages
- No system message: `system` field is `None`
- Tool message without `tool_call_id`: uses empty string as ID

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- New OpenAI field not mapped to canonical (silently dropped)
- Tool message merge logic that breaks on non-consecutive tool messages
- `unwrap()` on optional fields instead of graceful fallback

---

## transform_canonical_to_openai(anthropic_resp, model)

**Module:** `src/server/openai_compat/transform.rs`
**Intention:** Convert a `ProviderResponse` (Anthropic format) to an `OpenAIResponse`, translating content blocks, stop reasons, and token usage.

**Invariants:**
- INV-1 (Content preservation): All `Text` blocks become the `content` string (joined with newlines). All `ToolUse` blocks become `tool_calls`. Thinking/image blocks are dropped.
- INV-2 (Stop reason mapping): `end_turn` -> `stop`, `max_tokens` -> `length`, `stop_sequence` -> `stop`, `tool_use` -> `tool_calls`. Unknown reasons map to `stop`.
- INV-3 (Usage accuracy): `total_tokens` must equal `input_tokens + output_tokens`. No tokens are lost or invented.

**Preconditions:**
- `anthropic_resp` is a valid `ProviderResponse`

**Postconditions:**
- Returns a valid `OpenAIResponse` with exactly one choice (index 0)

**Boundary behavior:**
- No text blocks: `content` is `None`
- No tool_use blocks: `tool_calls` is `None`
- Empty content blocks: returns an empty choice

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- New content block type added to `ProviderResponse` but not handled here
- `total_tokens` computed differently from `input + output`
- Stop reason that is not mapped (falls through to default)

---

## SpendTracker::check_budget(provider, model, global_limit, provider_limit, model_limit)

**Module:** `src/features/token_pricing/spend.rs`
**Intention:** Check whether any spend limit (model, provider, or global) has been reached. Returns `Err(BudgetError)` if any limit is exceeded.

**Invariants:**
- INV-1 (Evaluation order): Model limit is checked first, then provider limit, then global limit. This ensures the most specific limit is reported when multiple are exceeded.
- INV-2 (Non-blocking): Budget check reads current spend but does not record or modify anything.
- INV-3 (Threshold semantics): The check uses `>=` (greater-than-or-equal), meaning the exact limit value is already considered exceeded.
- INV-4 (Zero global bypass): A `global_limit` of `0.0` means no global limit (skipped, not "zero budget").

**Preconditions:**
- Spend data is loaded and reflects the current month

**Postconditions:**
- On `Ok(())`: no limit exceeded
- On `Err(BudgetError)`: message identifies which limit (model/provider/global) was hit

**Boundary behavior:**
- `model_limit` is `None`: model budget check is skipped
- `provider_limit` is `None`: provider budget check is skipped
- `global_limit` is `0.0`: global budget check is skipped
- New month: spend data auto-resets before check (via `reset_if_new_month`)

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- Check order changed (e.g., global before model)
- `>` used instead of `>=` (off-by-one at boundary)
- `global_limit == 0.0` treated as "zero budget" instead of "no limit"

---

## ModelPricing::calculate(input_tokens, output_tokens)

**Module:** `src/features/token_pricing/mod.rs`
**Intention:** Compute the USD cost for a request based on per-million-token pricing.

**Invariants:**
- INV-1 (Formula): `cost = (input_tokens * input_per_million + output_tokens * output_per_million) / 1_000_000`
- INV-2 (Non-negative): Cost is always >= 0.0 for non-negative inputs
- INV-3 (Determinism): Same inputs always produce the same cost (no rounding, no randomness)

**Preconditions:**
- `input_per_million` and `output_per_million` are non-negative
- `input_tokens` and `output_tokens` are u32 (non-negative by type)

**Postconditions:**
- Returns `f64` representing USD cost

**Boundary behavior:**
- Zero tokens: returns 0.0
- Very large token counts (u32::MAX): result is valid f64, no overflow

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- Integer division before float conversion (truncation)
- Rounding applied to intermediate or final result
- Cache pricing not accounted for (if cache tokens should be priced differently)

---

## CircuitBreaker::can_execute()

**Module:** `src/security/circuit_breaker.rs`
**Intention:** Determine whether a request should be allowed through to a provider based on the circuit breaker's current state.

**Invariants:**
- INV-1 (State machine): Three states only: Closed (allow all), Open (reject unless timeout elapsed), HalfOpen (allow up to `half_open_max_calls`).
- INV-2 (Timeout transition): When Open and timeout has elapsed, transitions to HalfOpen and allows the request.
- INV-3 (HalfOpen limit): In HalfOpen, allows at most `half_open_max_calls` requests. The counter increments before returning `true`.
- INV-4 (Closed always allows): In Closed state, `can_execute()` always returns `true`.

**Preconditions:**
- Circuit breaker has been initialized with config (failure_threshold, success_threshold, timeout, half_open_max_calls)

**Postconditions:**
- Returns `true` if the request is allowed, `false` otherwise
- May transition state from Open to HalfOpen (side effect)
- Increments `half_open_calls` counter in HalfOpen state (side effect)

**Boundary behavior:**
- Newly created: starts in Closed (always allows)
- Timeout is zero: Open immediately transitions to HalfOpen on next check

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- State transition that bypasses the `transition_to()` method
- `half_open_calls` not incremented on HalfOpen allow
- Closed state that rejects requests

---

## reload_config(state)

**Module:** `src/server/config_api.rs`
**Intention:** Hot-reload the server configuration by atomically swapping the reloadable state (config, router, provider registry) without restarting the server. In-flight requests continue using the old snapshot.

**Invariants:**
- INV-1 (Atomicity): The swap from old to new state is a single write-lock assignment. No intermediate state is visible to readers.
- INV-2 (Non-reloadable preservation): Token store, grob store, event bus, and other persistent state are NOT replaced. Only `ReloadableState` changes.
- INV-3 (Error safety): If config parsing or provider initialization fails, the old config remains active. No partial reload.
- INV-4 (Snapshot isolation): Requests that started before the reload continue using the old `Arc<ReloadableState>` snapshot (reference counting).

**Preconditions:**
- Server is running with valid initial config
- Config source (file, env, CLI) is accessible

**Postconditions:**
- On success: new config is active for all subsequent requests
- On failure: old config remains active, error response returned
- Background validation task is spawned after successful reload

**Boundary behavior:**
- Config file missing: returns error, old config preserved
- Provider initialization fails: returns error, old config preserved
- Concurrent reload requests: serialized by write lock

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- Any persistent state (token_store, grob_store) being replaced during reload
- Partial state update (e.g., router updated but registry not)
- Missing error handling that allows partial reload

---

## DlpEngine::sanitize_request_checked(request)

**Module:** `src/features/dlp/mod.rs` (via trait in `src/traits.rs`)
**Intention:** Scan an outgoing request for secrets, PII, and prompt injections. Sanitize (redact/canary) in place, and return an error if the request must be blocked entirely (injection or URL exfiltration detected).

**Invariants:**
- INV-1 (Block semantics): If an injection or URL exfiltration is detected and blocking is enabled, returns `Err(DlpBlockError)`. The request must NOT proceed to any provider.
- INV-2 (In-place mutation): Secrets and PII are redacted/replaced in the request object itself. The original content is not preserved.
- INV-3 (Non-amplification): DLP processing never adds content to the request beyond canary tokens replacing existing secrets. The request payload can only shrink or stay the same size (modulo canary token length).

**Preconditions:**
- DLP engine is configured and `scan_input` is enabled
- Request contains text content to scan

**Postconditions:**
- On `Ok(())`: request may be modified (secrets redacted) but is safe to send
- On `Err(DlpBlockError)`: request must be rejected

**Boundary behavior:**
- Empty request content: no-op, returns `Ok(())`
- DLP disabled: function is never called (checked at call site)

**Known drifts:**
- (none recorded yet)

**Red flags to detect:**
- Block error returned but request still sent to provider
- Content added to request during sanitization (amplification)
- Scan skipped for certain message roles or content types
