# security

> Cross-cutting safety net: rate limits, circuit breakers, signed audit log, security headers, FIPS/TEE attestation.

## Purpose
Implements compliance-driven primitives shared across the dispatch pipeline: per-tenant token-bucket rate limiting, per-provider circuit breaking, append-only signed audit trails, hardening HTTP headers, FIPS detection, TEE sealing, and provider risk scoring. Owns the building blocks; `server` and `dispatch` decide when to call them.

## Public API
| Item | Location | Used by |
|------|----------|---------|
| `RateLimiter`, `RateLimitConfig`, `RateLimitKey` | `rate_limit.rs` | server middleware |
| `CircuitBreakerRegistry`, `CircuitState` | `circuit_breaker.rs` | dispatch, providers |
| `AuditLog`, `AuditEntry`, `AuditEvent`, `AuditConfig`, `RiskLevel`, `Classification`, `SigningAlgorithm` | `audit_log.rs` | dispatch, server, policies |
| `AuditSigner` (trait), `EcdsaP256Signer`, `Ed25519Signer`, `HmacSha256Signer` | `audit_signer.rs` | `AuditLog` ctor |
| `MerkleTree`, `ProofStep`, `Side` | `merkle.rs` | batched audit signing |
| `apply_security_headers`, `SecurityHeadersConfig`, `FrameOption`, `ReferrerPolicy` | `headers.rs` | server middleware |
| `FipsStatus`, `detect_fips`, `enforce_fips` | `fips.rs` | server startup |
| `TeeStatus`, `TeeBackend`, `SealedKey`, `enforce_tee`, `detect_tee`, `get_attestation_report`, `attestation_for_audit`, `derive_sealed_key` | `tee.rs` | startup, audit |
| `SecurityOutcome`, `assess_risk`, `EscalationEvent`, `maybe_escalate` | `risk.rs` | dispatch post-process |
| `ProviderScorer`, `ScorerConfig` | `provider_scorer.rs` | routing decisions |
| `JwtValidationCache`, `JwtCacheEntry`, `jwt_validation_cache` | `cache.rs` | `auth::jwt` |

## Owns
- Token-bucket rate limiter with per-tenant tracking (HDS/SecNumCloud/NIS2).
- Three-state circuit breaker (closed/open/half-open) registry per provider.
- Append-only audit log with per-entry or Merkle-batched signatures (ECDSA-P256, Ed25519, HMAC-SHA256).
- HTTP security headers middleware (HSTS, CSP, X-Frame-Options, Referrer-Policy).
- FIPS 140-3 mode detection and enforcement modes.
- TEE backends (SEV-SNP, TDX, SGX) for attestation and key sealing.
- JWT validation result cache (moka) keyed by token hash.

## Depends on
- `crate::cli::{ComplianceConfig, EnforcementMode, TeeConfig, FipsConfig}` for configuration.
- `aws-lc-rs` / `ring` for signing primitives.
- `tokio::sync::RwLock`, `moka` for in-memory state.

## Non-goals
- DLP scanning (see `features::dlp`).
- Policy decisions (see `features::policies`).
- Spend tracking (see `features::token_pricing`).
- Routing logic (see `routing/`). The passive circuit breaker in `routing::circuit_breaker` is distinct from this module's active per-endpoint registry.

## Tests
- `tests/integration/security_test.rs` exercises rate limiter and headers end-to-end.
- `tests/integration/compliance_test.rs` covers audit log signing and verification.
- `tests/enterprise/property_audit_test.rs` proptest invariants on the Merkle tree.

## Related ADRs
- [ADR-0006](../../docs/decisions/0006-policy-engine-encrypted-audit-hit-gateway.md) — Encrypted audit log + HIT Gateway.
- [ADR-0017](../../docs/decisions/0017-sokolsky-log-backend.md) — Append-only log backend.
- [ADR-0018](../../docs/decisions/0018-nature-inspired-routing.md) — Notes on the per-endpoint passive breaker living in `routing/`.
