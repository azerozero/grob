# HIT Quorum Voting & Multi-Sig Co-Signing

Design specification for future HIT Gateway enhancements. Not yet implemented.

## Quorum Voting

When a tool_use action falls in the `require_approval` range but no human is available, N independent LLM agents can vote on the action.

### Flow

```
tool_use detected → risk = medium → quorum triggered
    → N voters receive: tool_name, input, context, risk score
    → each votes: APPROVE | DENY | ESCALATE
    → majority → execute or deny
    → any ESCALATE → escalate to human
    → timeout → deny (fail-closed)
```

### Config

```toml
[policies.hit.quorum]
strategy = "majority"           # "majority" | "unanimous" | "weighted"
min_voters = 3
required_approvals = 2
require_diverse_providers = true # Different LLM providers for each voter
voter_timeout = "5s"
on_failure = "escalate_human"   # "deny" | "escalate_human"
```

### Anti-collusion

- Different LLM providers (distinct failure modes)
- Isolated voter prompts (no inter-voter communication)
- No shared context beyond decision-relevant facts
- Temporal jitter (random 0-500ms delays)
- Any ESCALATE vote → entire decision escalates to human

## Multi-Sig Co-Signing

For high-stakes operations (e.g., >$10k transactions, production infrastructure), M-of-N human co-signing is required.

### Flow

```
tool_use detected → risk = high → multisig triggered
    → initiator signs first HIT
    → notification sent to N co-signers (webhook / grob watch)
    → each reviews consent_display and signs
    → at M signatures → action approved
    → timeout → auto-deny
```

### Config

```toml
[policies.hit]
auth_method = "multisig"
required_signatures = 2
total_signers = 3
required_roles = ["finance", "security"]
timeout = "15m"
escalation_on_timeout = "reject"
```

### Authorization Channels

| Channel | Security | Latency |
|---------|----------|---------|
| `grob watch` CLI prompt | High | Instant |
| Push notification + biometric | High | ~2s |
| Hardware key (YubiKey) touch | Very high | ~1s |
| Webhook (Slack/Teams) | Medium | ~5s |

### Delegation

Delegated HITs receive the **intersection** of all signers' permissions. Sub-HITs can only narrow scope, never widen it.

## Implementation Notes

- Quorum voters use the existing provider dispatch pipeline (grob routes to different LLMs)
- Multi-sig uses the HIT authorization hash chain (each signer adds a linked receipt)
- Both integrate with the unified policy engine match rules
- No new crates required — reuses existing Ed25519/ECDSA signing infrastructure
