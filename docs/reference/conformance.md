# Agent Conformance

Which agent clients grob is *tested* to carry faithfully, on which routes, and
against which failure modes. This page is the published half of a gate that runs
on every release; the executable half is
[`tests/integration/conformance_test.rs`](../../tests/integration/conformance_test.rs).

## Why this exists

The expensive failure of an LLM gateway is not the `500`. It is the **`200` that
lies**: a valid status, a well-formed stream, plausible text, and a turn whose
*meaning* was quietly destroyed on the way through. Tool arguments truncated. An
image degraded to the literal text `[Image]`. A `cache_control` breakpoint
dropped, silently multiplying cost. An upstream `429` flattened into an opaque
`500`, so the agent retries what it should have backed off from.

None of that is visible to a status-code assertion. All of it breaks the agent
while the gateway's dashboards stay green. grob has shipped fixes for exactly
this class ([#476] images, [#465] reasoning, [#488] tool-result images, [#489]
provider errors), and every provider protocol change can reintroduce one.

So the claim worth making is not "100+ providers". It is **N certified routes ×
M loss dimensions, with the tests public**.

## What "certified" means here

A dimension is certified on a route when a test asserts the *semantics* survived,
by inspecting the bytes that actually reached the provider and the bytes that
actually reached the client. Never merely that the request succeeded.

Each assertion is verified by mutation: the production code is deliberately
broken (image → placeholder, arguments truncated, history reversed, system
prompt emptied, `cache_control` skipped, structured error removed) and the gate
must fail. A conformance test that cannot fail certifies nothing.

## Matrix

| Loss dimension | Anthropic `/v1/messages` | OpenAI `/chat/completions` | OpenAI `/responses` (Codex) |
|---|---|---|---|
| Tool-call arguments intact (nested, unicode, quotes) | ✅ | ✅ | ✅ [*] |
| Multi-turn history order and roles | ✅ | ✅ | — |
| System prompt / instructions forwarded | ✅ | ✅ | ✅ [*] |
| Image forwarded as pixels, not `[Image]` | ✅ | ✅ | — |
| `cache_control` breakpoints (system **and** message) | ✅ | n/a¹ | n/a¹ |
| Upstream status verbatim + structured provider error | ✅ (429) | ✅ (400) | — |
| SSE event order and terminal event | — | — | ✅ [*] |
| Streamed text and tool arguments reassemble | — | — | ✅ [*] |

✅ asserted by the gate · — not yet asserted · n/a not expressible on that wire
format

¹ Neither OpenAI surface has a `cache_control` concept. A request translated
*from* those surfaces to Anthropic gets an injected breakpoint instead; see
[protocol-fidelity.md](protocol-fidelity.md).

[*] Covered by
[`responses_e2e_test.rs`](../../tests/integration/responses_e2e_test.rs), which
predates this gate and asserts the same way (captured upstream body plus
client-visible SSE).

## Reading a failure

The gate names the contract rather than the symptom. A regression reports

```text
the image bytes must reach the provider; sent: {"messages":[…,{"type":"text","text":"[Image]"}]}
```

not `expected 200, got 500`. The captured upstream body is included so the diff
is immediate.

## Running it

```bash
cargo nextest run conformance          # the gate alone
cargo nextest run                      # the gate with everything else
```

It is an ordinary test: offline, deterministic, no credentials, and part of the
default CI run. There is nothing to opt into and no separate job to forget.

## Scope and honesty

- **The matrix is deliberately sparse.** A dimension is marked ✅ only where an
  end-to-end test actually drives that pair. Where a behaviour is covered by unit
  tests but not by this gate, the cell stays `—`: the gate is about what survives
  the *whole* pipeline, and unit coverage has never been what this class of bug
  escapes through.
- **Request-direction coverage is stronger than response-direction.** Most rows
  assert what reached the provider. Response-direction fidelity is asserted on
  the Responses route (SSE order, reassembly) and by the provider-error row.
- **Gemini is not in the matrix.** Its translation is exercised by unit tests
  only.
- **`context_length_exceeded` is deliberately not the error fixture.** grob
  recognises that code and rewrites it into a richer envelope carrying a
  suggested `/compact` action. That is an intentional, separate contract; the
  gate pins the *generic* path, where grob has no special knowledge and must
  simply not lose what the provider said.
- **A `—` is not a claim of correctness, and not a claim of breakage.** It marks
  an untested pair. Publishing the matrix makes the gaps visible instead of
  implied; filling them is incremental and each new row is one more helper in the
  same test.

## Related

- [protocol-fidelity.md](protocol-fidelity.md) — what each wire format *can*
  carry, and where a loss is the provider's constraint rather than a grob bug.
- [errors.md](errors.md) — the error envelope the provider-error row pins.

[#465]: https://github.com/azerozero/grob/pull/465
[#476]: https://github.com/azerozero/grob/pull/476
[#488]: https://github.com/azerozero/grob/pull/488
[#489]: https://github.com/azerozero/grob/pull/489
