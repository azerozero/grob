# Verify hedge cancellation billing

Hedged requests are not implemented yet. Use this protocol before enabling or
shipping any provider-specific hedge config. The goal is to classify what the
provider bills when Grob cancels the losing leg of a speculative duplicate
request.

## Preconditions

- Use a paid account where usage and invoices are visible.
- Run the test on a non-production API key.
- Disable response caching.
- Use a deterministic prompt and `temperature = 0`.
- Use a streaming request so cancellation can happen after the upstream request
  has started.
- Run every provider separately; do not infer one provider's behavior from
  another provider's billing model.

## Classification

| Value | Meaning | Hedging default |
|---|---|---|
| `full_refund` | Cancelled leg is not billed beyond negligible connection overhead | allowed |
| `partial_refund` | Cancelled leg is billed up to generated tokens or a chunk boundary | allowed with extra-cost metric |
| `no_refund` | Cancelled leg is billed like a full request | disabled unless forced |
| `unknown` | Billing behavior has not been verified | disabled |

## Test

1. Pick one provider/model pair and record the account's current usage total.
2. Send five baseline streaming requests without cancellation. Record input
   tokens, output tokens, duration, and billed amount.
3. Send five streaming requests with the same prompt, then cancel each stream
   after the first content chunk is received.
4. Wait until the provider's usage dashboard or invoice export has caught up.
5. Compare cancelled-request billing to the baseline:
   - No material billable usage: `full_refund`.
   - Lower usage than baseline, but non-zero: `partial_refund`.
   - Similar usage to baseline: `no_refund`.
   - Dashboard/API cannot prove the result: `unknown`.
6. Save the evidence: date, provider, model, account tier, request IDs if
   available, baseline cost, cancelled cost, and notes.

## Config evidence

Only write a non-`unknown` value after the evidence exists:

```toml
[hedge.providers.example]
billing_behavior = "partial_refund"
verified_date = "2026-06-02"
evidence = "internal usage export: request ids req_1..req_10"
```

If the provider changes billing terms, reset the value to `unknown` and rerun
the test.

## Audit requirements

Every future hedged logical request must record both legs under the same
logical request id:

```json
{
  "event": "hedge_leg_finished",
  "request_id": "req_logical",
  "hedge_group_id": "hedge_req_logical",
  "leg": "secondary",
  "provider": "openrouter",
  "model": "anthropic/claude-sonnet-4-6",
  "winner": false,
  "cancel_requested": true,
  "billing_behavior": "partial_refund",
  "billed_input_tokens": 1234,
  "billed_output_tokens": 12,
  "cost_usd": 0.00042
}
```

The losing leg is never hidden. Spend records the provider's actual billed cost
when known; request-latency metrics mark only the winning response as the client
visible result.
