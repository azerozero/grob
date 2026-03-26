# SBTM Exploratory Testing Charters

Session-based test management charters for high-risk areas of Grob.
Each charter is a standalone 60-minute exploration session.

## Charter 1: Multi-Tenant Isolation Under Concurrent Load

**Area:** Dispatch pipeline, policy engine, audit log
**Risk:** Tenant A's request leaks into tenant B's response, logs, or spend tracking. Shared caches return cross-tenant data.
**Duration:** 60 min
**Mission:** Fire concurrent requests from two distinct tenant JWTs (hospital_eu, team_perf) using k6 or parallel curl loops. Vary payloads so each tenant's content is fingerprinted (e.g., tenant A sends "ALPHA-MARKER", tenant B sends "BETA-MARKER"). Inspect responses, audit logs, and spend endpoint to verify no cross-contamination. Try edge cases: same model, same prompt, simultaneous arrival.
**Oracles:** Response bodies must never contain the other tenant's marker. Audit log entries must reference the correct tenant. Spend records must attribute costs to the issuing tenant only. x-grob-tenant header in response must match the requesting JWT's tenant claim.

## Charter 2: DLP False Positives and Negatives

**Area:** DLP pipeline (redact + block modes)
**Risk:** Real secrets pass through undetected (false negative). Clean text gets blocked or mangled (false positive). Partial redaction leaks enough context to reconstruct the secret.
**Duration:** 60 min
**Mission:** Submit prompts containing AWS keys, credit card numbers, IBANs, JWTs, and SSH private keys in varied formats: base64-encoded, split across lines, embedded in code blocks, surrounded by look-alike strings. Also send clean prompts that contain patterns close to secrets (e.g., strings starting with "AKIA" but invalid, 16-digit numbers that are not credit cards). Test both redact and block modes. Confirm redaction is complete (not just first occurrence).
**Oracles:** Real secrets must not appear in provider-bound requests or responses. Clean text must pass through unmodified (check response body character-for-character). Block mode must return the DLP error response, not silently drop the request.

## Charter 3: Streaming Resilience

**Area:** SSE streaming path, provider connection management
**Risk:** Mid-stream disconnection causes hung connections, partial JSON in the response, or silent data loss. Slow producers cause timeouts that propagate incorrectly.
**Duration:** 60 min
**Mission:** Use Toxiproxy to inject latency (slow_close, latency toxic) on the provider upstream during active streams. Send streaming requests and kill the client mid-stream (close the TCP connection after receiving partial chunks). Send requests through a provider proxy with bandwidth toxic set to 1 KB/s. Monitor grob's connection count and memory usage before and after. Verify that grob does not accumulate zombie connections.
**Oracles:** Grob must return well-formed SSE events (each chunk is valid JSON). After client disconnect, grob must not continue buffering from the provider indefinitely. Health endpoint must remain responsive during and after disruptions. No panic or error 500 on subsequent requests.

## Charter 4: Provider Failover Under Degraded Conditions

**Area:** Router, provider registry, circuit breaker
**Risk:** Partial failures (HTTP 500 on some requests, 200 on others) cause the circuit breaker to flap. Failover to a secondary provider returns a different response format. Recovery after all providers come back online is not automatic.
**Duration:** 60 min
**Mission:** Use Toxiproxy to create degraded conditions: primary returns 500 50% of the time (reset_peer toxic with probability), secondary is slow (2s latency). Verify grob routes to the secondary. Then restore primary and verify traffic shifts back. Test the sequence: all healthy -> primary down -> secondary down -> both up. Monitor x-ai-provider response header to track routing decisions. Check that circuit breaker state transitions (closed -> open -> half-open -> closed) happen at the configured thresholds.
**Oracles:** No request should get a 502 while at least one provider is healthy. x-ai-provider header must reflect the actual provider used. Response format must be consistent regardless of which provider served it. After recovery, requests must eventually return to the primary (not stay stuck on the fallback).

## Charter 5: JWT Edge Cases

**Area:** Auth middleware, JWKS refresh, JWT validation
**Risk:** Clock skew causes valid tokens to be rejected or expired tokens to be accepted. Malformed tokens crash the parser. Tokens with unusual claims bypass policy checks.
**Duration:** 60 min
**Mission:** Generate JWTs with: nbf 30 seconds in the future (clock skew), exp exactly now (boundary), extremely long subject claims (10KB), nested JSON objects in custom claims, UTF-8 characters in claim values (emoji, CJK, RTL text), algorithm "none" in header, RS256 token presented to an ES256 validator, token with trailing whitespace, token with three dots (empty signature). Also test JWKS rotation: swap the signing key while requests are in flight and verify grob picks up the new key after refresh.
**Oracles:** Expired tokens must always return 401. Tokens signed with wrong algorithm must return 401. Algorithm "none" must be rejected. Oversized tokens must not cause OOM or slow responses (check response time stays under 500ms). Valid tokens with unusual but legal claims must succeed. JWKS rotation must be picked up within the configured refresh interval.
