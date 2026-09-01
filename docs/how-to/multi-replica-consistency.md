# Keep Multiple Replicas Consistent

How to tell, and how to enforce, that every grob replica is serving the same
configuration and the same policy set.

## The problem

`/api/config/reload` applies to **the replica that received the request**, and to
no other. With a single daemon that is invisible and harmless. Behind a load
balancer it is a correctness bug: replica A picks up the new policy, replica B
misses the call and keeps enforcing the old one. Both answer `200`. Both report
healthy. Requests are routed to whichever pod the balancer picks, so the policy
that applies to a given request becomes a coin flip, and nothing in the response
says which one it was.

This is the "mutable-per-pod configuration" failure. It cannot be fixed by
reloading harder; it needs the configuration to have an **identity** that can be
compared across replicas.

## Revisions

Every state snapshot carries two content hashes:

| Revision | Covers | Moves when |
|---|---|---|
| `config` | the whole active configuration | routing, providers, models, budget, DLP, policies… anything changes |
| `policy` | the `[[policies]]` set alone | only the enforced policy set changes |

Both are stable: the same configuration produces the same revision in every
process and every run. They are computed over a canonical encoding with sorted
keys, so map iteration order cannot make two identical replicas disagree.

They are also **secret-free**. API keys and tokens are redacted before hashing,
which means rotating a credential does *not* move the revision. That is
deliberate: the deployed policy did not change, so its identity should not
change either.

The two are separate because they answer different questions. Changing a
provider `base_url` moves the config revision while leaving the enforced policy
identical; conflating them would make "did the policy change?" unanswerable.

## Checking consistency

Both revisions are on `/health`:

```bash
curl -s http://replica-a:13456/health | jq .revision
```

```json
{
  "config": "sha256:3f9a…",
  "policy": "sha256:c17b…"
}
```

Across a fleet, one line tells you whether a rollout has converged:

```bash
for r in replica-a replica-b replica-c; do
  echo "$r $(curl -s http://$r:13456/health | jq -r .revision.config)"
done | sort -k2 | uniq -cf1
```

More than one distinct revision means the fleet is inconsistent, and the count
tells you how far the rollout got.

## Enforcing consistency

Detection is not enough: a stale replica keeps serving while you look at the
dashboard. Pin the expected revision and a lagging replica removes *itself* from
the load balancer.

```toml
[server]
expected_config_revision = "sha256:3f9a…"
```

While the replica's active revision differs, `/ready` returns `503`:

```json
{
  "status": "not_ready",
  "reason": "config revision mismatch",
  "expected_config_revision": "sha256:3f9a…",
  "active_config_revision": "sha256:7c02…"
}
```

Any orchestrator that respects a readiness probe (Kubernetes, Nomad, a health
check on the balancer) then stops sending it traffic. The replica fails loudly
instead of quietly applying a superseded policy.

The 12-character short form works too, since that is what appears in logs:

```toml
expected_config_revision = "3f9a1c4d8e02"
```

`/ready` also reports both revisions on success, so a readiness probe doubles as
a consistency probe.

### Typical rollout

1. Compute the target revision once, from any replica already running the new
   config: `curl -s http://…/health | jq -r .revision.config`.
2. Set `expected_config_revision` in the deployed config.
3. Roll out. Replicas that have the new config pass readiness; those that do not
   are held out of service until they do.

Leaving the field **unset** disables the check. That is the right choice for a
single daemon: there is nothing to be inconsistent with, and an unset pin costs
nothing.

## Proving which policy applied

Detection and enforcement cover the live fleet. For the audit trail, every
request-scoped audit entry carries `policy_revision`, taken from the snapshot the
request was actually evaluated against — not from a fresh read, so a reload
racing the request cannot misattribute the decision.

This makes an after-the-fact question answerable. Given an audit line from a
fleet that was mid-rollout, `policy_revision` says which policy set judged that
specific request. Without it, a request judged under the old policy and one
judged under the new are indistinguishable.

## Limits

- Revisions describe **what a replica is running**, not what it *should* be
  running. The intended revision comes from your deployment; grob compares
  against it but has no opinion about where it came from.
- The check is per-replica and requires no coordination between replicas: no
  quorum, no leader, no shared store. It only turns a silent inconsistency into
  a visible, actionable one.
- `expected_config_revision` is itself excluded from the config revision.
  Otherwise stamping the config with its own expected revision would change that
  revision, and no value could ever match.

## Related

- [`docs/reference/observability.md`](../reference/observability.md) — the rest
  of the health and metrics surface.
- [ADR-0001](../decisions/0001-static-config-no-hot-reload.md) — why config is a
  snapshot swapped atomically rather than mutated in place.
