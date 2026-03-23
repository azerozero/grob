# ADR-0007: HIT Gateway — Federated Multi-Enterprise Authorization (WI-9)

## Status

Proposed

## Context and Problem Statement

ADR-0006 defined the HIT Gateway for single-tenant tool authorization. Real-world
deployments in regulated industries (finance, healthcare, defense) require approval
from multiple independent organizations before an AI agent can execute sensitive
actions. No single party should be able to unilaterally authorize a cross-domain
operation.

Use cases:

- **Financial clearing**: trading firm + clearing house + regulator each sign before
  `execute_trade` runs.
- **Healthcare data exchange**: hospital A + pharma B + DPO must co-authorize access
  to patient-linked AI output.
- **Defense contracting**: prime contractor + sub-contractor + government agency
  must all approve before AI touches classified scope.

## Decision Drivers

- Cross-domain approvals must be verifiable **offline** — the receiving grob cannot
  call back to each enterprise at verification time.
- Each enterprise controls its own signing keys — no shared secret, no central CA
  required (though OpenBao PKI is supported as an option).
- The proof format must be portable and inspectable by auditors without grob.
- Must compose with WI-8 (yubikey, openbao, grob_peer, hit_chain).
- Minimize new grob code by reusing existing primitives.

## Considered Options

- **Option A**: Centralized approval service (single party collects all signatures)
- **Option B**: Federated Ed25519/ECDSA receipts with JWKS key distribution (chosen)
- **Option C**: W3C Verifiable Credentials full implementation
- **Option D**: SPIFFE/SPIRE workload identity mesh

## Decision Outcome

Chosen option: "Option B — Federated Ed25519/ECDSA receipts with JWKS endpoints",
because it reuses the existing `HitAuthorization` + `AuditSigner` infrastructure,
requires no central coordinator, and is inspectable by any party with access to the
public keys.

## Design

### 1. Cryptographic signing of HIT receipts

Today `HitAuthorization` is SHA-256 hash-chained (tamper-evident but not signed).
WI-9 adds an Ed25519/ECDSA signature per receipt so each enterprise's approval is
independently verifiable:

```rust
pub struct HitAuthorization {
    // existing fields unchanged
    pub hash: String,
    pub previous_hash: Option<String>,

    // WI-9 additions
    pub signature: Option<Vec<u8>>,      // Ed25519 / ECDSA-P256
    pub signer_key_id: Option<String>,   // URI: "https://grob.corp/keys/2026-Q1"
}
```

The signing key is the same `AuditSigner` already used for the audit log —
no new crypto primitive needed.

### 2. Key distribution — `/.well-known/grob-keys.json`

Each grob exposes a JWKS endpoint:

```json
GET /.well-known/grob-keys.json
{
  "keys": [
    {
      "kid": "grob-corp-a-2026-Q1",
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url public key>",
      "use": "sig",
      "exp": 1767225600
    }
  ]
}
```

Alternatives supported: OpenBao PKI (cert chain), DNS TXT record.

### 3. New `auth_method = "federated_multisig"`

```toml
[[policies]]
match = { compliance = ["finance", "clearing"] }

[policies.hit]
auth_method        = "federated_multisig"
required_signatures = 3

[[policies.hit.trusted_signers]]
domain   = "trading-firm.example"
key_uri  = "https://grob.trading-firm.example/.well-known/grob-keys.json"
role     = "counterparty"

[[policies.hit.trusted_signers]]
domain   = "clearing-house.example"
key_uri  = "https://grob.clearing-house.example/.well-known/grob-keys.json"
role     = "counterparty"

[[policies.hit.trusted_signers]]
domain   = "regulator.gov"
key_uri  = "https://grob.regulator.gov/.well-known/grob-keys.json"
role     = "regulator"
required = true    # cette signature est obligatoire indépendamment du quorum
```

### 4. Proof format — `HitProofChain`

The `Vec<HitAuthorization>` forwarded in the `X-Grob-HIT-Chain` header becomes
a portable proof bundle:

```rust
pub struct HitProofChain {
    /// Ordered list of authorizations, each signed by its issuing grob.
    pub authorizations: Vec<HitAuthorization>,
    /// SHA-256 of the full authorizations vec (integrity check for the bundle).
    pub chain_hash: String,
    /// When this proof was assembled.
    pub issued_at: DateTime<Utc>,
    /// Proof validity window (replay protection).
    pub ttl_secs: u64,
}
```

This format is structurally compatible with SCITT (IETF draft) — a future
migration path exists without changing the wire format.

### 5. Verification flow

```
grob-shared receives request + X-Grob-HIT-Chain header

1. Deserialize HitProofChain
2. Check chain_hash integrity
3. Check issued_at + ttl_secs (not expired, not from the future)
4. For each HitAuthorization in the chain:
   a. Verify SHA-256 hash chain (existing: auth.verify())
   b. Resolve signer_key_id → fetch JWKS (cached, TTL = key exp)
   c. Verify Ed25519/ECDSA signature
   d. Check signer domain is in trusted_signers config
5. Count valid signatures per role
6. Check required = true signers are present
7. Check total valid >= required_signatures
8. If all pass → resolve approval oneshot → stream resumes
```

### 6. Topology support

| Topology | How |
|----------|-----|
| Chain (A → B → C → LLM) | Each hop appends its receipt, last hop verifies the full chain |
| Star (all → central → LLM) | Central grob collects receipts from all peers via `/api/hit/approve` |
| DAG (A, B → merge → LLM) | Merge grob waits for receipts from A and B before verifying |
| Cross-enterprise | Each enterprise runs its grob, receipts forwarded in header |

### 7. Relation to WI-8

| WI | Scope | Signing |
|----|-------|---------|
| WI-8b yubikey | Local, single party | HMAC challenge-response |
| WI-8c openbao | Single domain, delegated to Vault | Vault token validation |
| WI-8d grob_peer | Two grob instances, shared secret | HMAC-SHA256 |
| WI-8e hit_chain | Multi-hop same domain | Hash chain + optional HMAC |
| **WI-9 federated_multisig** | **Multi-enterprise, cross-domain** | **Ed25519/ECDSA per enterprise** |

### 8. What is NOT in scope for WI-9

- Full W3C Verifiable Credentials DID resolution
- On-chain anchoring (blockchain notarization)
- Real-time revocation (CRL/OCSP) — keys expire via `exp` in JWKS
- Consensus protocol between grob nodes (not needed: approval is sequential)

## Consequences

- Good: offline verifiable — auditors can verify the proof chain without grob
- Good: no central coordinator — each enterprise is sovereign
- Good: reuses AuditSigner (Ed25519/ECDSA already implemented)
- Good: SCITT-compatible format — future standardization path
- Bad: JWKS key distribution adds an HTTP dependency at verification time
  (mitigated by caching with TTL = key expiry)
- Bad: key rotation requires config update on all relying grob instances
  (mitigated by JWKS versioning via `kid`)

## Implementation Phases

| Phase | Scope |
|-------|-------|
| P1 | Sign HitAuthorization with AuditSigner; expose `/.well-known/grob-keys.json` |
| P2 | `federated_multisig` auth_method + JWKS verification |
| P3 | `HitProofChain` + `X-Grob-HIT-Chain` header forwarding |
| P4 | `required = true` signer enforcement + role-based quorum |
