# Requirements Traceability Matrix

Mapping of features to e2e test files. Each row links a verifiable requirement
to one or more test files, the testing technique used, and the assessed risk.

**Techniques**: EP = Equivalence Partitioning, BVA = Boundary Value Analysis,
NEG = Negative Testing, PW = Pairwise Combinatorial, FI = Fault Injection,
FUZZ = Fuzz / Malformed Input.

## Authentication

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-AUTH-01 | JWT validation (valid) | auth/90, policies/B1 | EP | High |
| F-AUTH-02 | JWT rejection (expired) | auth/92, negative/N4 | EP, BVA | High |
| F-AUTH-03 | JWT rejection (tampered) | auth/95, negative/N2 | NEG | Critical |
| F-AUTH-04 | JWT rejection (wrong issuer) | auth/93 | NEG | High |
| F-AUTH-05 | JWT rejection (wrong audience) | auth/94 | NEG | High |
| F-AUTH-06 | JWT rejection (self-signed) | negative/N0 | NEG | Critical |
| F-AUTH-07 | JWT rejection (algo-none) | negative/N1 | NEG | Critical |
| F-AUTH-08 | No auth header returns 401 | auth/91, policies/B0 | EP | High |
| F-AUTH-09 | API key authentication | auth/98 | EP | High |
| F-AUTH-10 | Tenant isolation (hospital) | auth/96, policies/B4 | EP | High |
| F-AUTH-11 | Tenant isolation (perf) | auth/97, policies/B5 | EP | High |
| F-AUTH-12 | Forged tenant rejection | negative/N3 | NEG | Critical |
| F-AUTH-13 | JWT replay (expired reuse) | negative/N4 | NEG | High |
| F-AUTH-14 | API key brute force | negative/N6 | NEG | High |

## Authorization / Policies

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-AUTHZ-01 | No-policy clean passthrough | policies/B1 | EP | Medium |
| F-AUTHZ-02 | Policy + DLP redact mode | policies/B2 | EP | High |
| F-AUTHZ-03 | Policy + DLP block mode | policies/B3, policies/B4 | EP | High |
| F-AUTHZ-04 | Rate limit enforcement | policies/B5 | BVA | Medium |
| F-AUTHZ-05 | Cross-tenant budget isolation | negative/N8 | NEG | High |
| F-AUTHZ-06 | Header injection (tenant) | negative/N5 | NEG | Critical |

## Routing / Failover

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-ROUTE-01 | Default model routing | happy/02 | EP | High |
| F-ROUTE-02 | Provider failover (primary down) | failover/10 | FI | Critical |
| F-ROUTE-03 | Rate limit failover (429) | failover/11 | FI | High |
| F-ROUTE-04 | Cascade all providers down | failover/12 | FI | High |
| F-ROUTE-05 | Timeout / slow provider | failover/13 | FI | Medium |
| F-ROUTE-06 | Mid-stream failure | failover/14 | FI | High |
| F-ROUTE-07 | Anthropic native format | happy/05 | EP | Medium |
| F-ROUTE-08 | Tool calling | happy/04 | EP | Medium |

## Circuit Breaker

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-CB-01 | Not open below threshold | circuit-breaker/50 | BVA | Medium |
| F-CB-02 | Opens at failure threshold | circuit-breaker/51 | BVA | High |
| F-CB-03 | Fail-fast when open | circuit-breaker/52 | EP | High |
| F-CB-04 | Half-open probe | circuit-breaker/53 | EP | Medium |
| F-CB-05 | Recovery to closed | circuit-breaker/54 | EP | Medium |
| F-CB-06 | Relapse back to open | circuit-breaker/55 | EP | Medium |

## DLP

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-DLP-01 | AWS key detection | secu/31 | EP | Critical |
| F-DLP-02 | JWT token detection | secu/32 | EP | Critical |
| F-DLP-03 | DLP redact mode | policies/B2, pairwise/PW-02 | EP, PW | High |
| F-DLP-04 | DLP block mode | policies/B3, policies/B4, pairwise/PW-03 | EP, PW | High |

## Budget

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-BUDGET-01 | Global spend limit | budget/41 | BVA | High |
| F-BUDGET-02 | Provider spend limit | budget/42 | BVA | High |
| F-BUDGET-03 | Model spend limit | budget/43 | BVA | High |
| F-BUDGET-04 | 80% warning threshold | budget/40 | BVA | Medium |
| F-BUDGET-05 | Cross-tenant budget isolation | negative/N8 | NEG | High |

## Cache

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-CACHE-01 | Cache hit | cache/45 | EP | Medium |
| F-CACHE-02 | Cache miss (temperature > 0) | cache/46 | EP | Medium |

## Security

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-SEC-01 | No provider key in errors | secu/30, negative/N7 | NEG | Critical |
| F-SEC-02 | CRLF injection blocked | secu/33, negative/N10 | NEG | Critical |
| F-SEC-03 | Path traversal blocked | secu/34, negative/N11 | NEG | Critical |
| F-SEC-04 | Header injection (tenant) | negative/N5 | NEG | Critical |
| F-SEC-05 | Body size limit enforced | negative/N9 | BVA | High |

## Compliance / Audit

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-AUDIT-01 | Audit files created | audit/A0 | EP | High |
| F-AUDIT-02 | Audit not plaintext | audit/A1 | EP | High |
| F-AUDIT-03 | Audit signature valid | audit/A2 | EP | Critical |
| F-AUDIT-04 | RSSI decrypt works | audit/A3 | EP | High |
| F-AUDIT-05 | DPO decrypt works | audit/A4 | EP | High |
| F-AUDIT-06 | Intruder decrypt fails | audit/A5 | NEG | Critical |
| F-AUDIT-07 | Entry contains model | audit/A6 | EP | Medium |
| F-AUDIT-08 | Entry contains tokens | audit/A7 | EP | Medium |
| F-AUDIT-09 | Entry contains tenant | audit/A8 | EP | Medium |

## Input Validation

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-INPUT-01 | Malformed JSON rejected | fuzz/20 | FUZZ | High |
| F-INPUT-02 | Wrong content type rejected | fuzz/21 | FUZZ | Medium |
| F-INPUT-03 | Wrong HTTP method rejected | fuzz/22 | FUZZ | Medium |
| F-INPUT-04 | Giant headers rejected | fuzz/23 | BVA | Medium |
| F-INPUT-05 | Deep nesting rejected | fuzz/24 | BVA | Medium |
| F-INPUT-06 | Encoding edge cases handled | fuzz/25 | FUZZ | Low |

## Streaming

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-STREAM-01 | SSE format + headers | happy/03 | EP | High |
| F-STREAM-02 | Mid-stream failure handling | failover/14 | FI | High |

## Config

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-CONF-01 | Health endpoint | happy/01 | EP | Medium |

## Pairwise Combinatorial

| ID | Feature | Test Files | Technique | Risk |
|----|---------|-----------|-----------|------|
| F-PW-01 | Valid JWT + up + disabled DLP | pairwise/PW-01 | PW | Medium |
| F-PW-02 | Valid JWT + up + redact DLP | pairwise/PW-02 | PW | Medium |
| F-PW-03 | Valid JWT + up + block DLP | pairwise/PW-03 | PW | Medium |
| F-PW-04 | Valid JWT + primary down + disabled DLP | pairwise/PW-04 | PW | Medium |

## Summary

| Category | Requirements | Test Files | Risk Critical | Risk High |
|----------|-------------|-----------|---------------|-----------|
| Authentication | 14 | 16 | 4 | 8 |
| Authorization | 6 | 7 | 1 | 3 |
| Routing / Failover | 8 | 8 | 1 | 4 |
| Circuit Breaker | 6 | 6 | 0 | 2 |
| DLP | 4 | 7 | 2 | 2 |
| Budget | 5 | 5 | 0 | 4 |
| Cache | 2 | 2 | 0 | 0 |
| Security | 5 | 7 | 4 | 1 |
| Compliance / Audit | 9 | 9 | 2 | 5 |
| Input Validation | 6 | 6 | 0 | 1 |
| Streaming | 2 | 2 | 0 | 1 |
| Config | 1 | 1 | 0 | 0 |
| **Total** | **68** | **76** | **14** | **31** |
