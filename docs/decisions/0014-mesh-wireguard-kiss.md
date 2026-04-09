---
status: proposed
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

# ADR-0014: Mesh Networking — WireGuard KISS, With a Second Profile for Scale

## Context and Problem Statement

Grob is positioned to run in multi-node deployments:

- **Dev / team** — 1 to 3 nodes on a laptop and a couple of cloud VMs.
- **Small prod** — 3 to 10 nodes across regions or compliance zones.
- **Larger prod / K8s** — 10 to 50 nodes on a managed cluster.
- **Defense-scale (hypothetical)** — > 50 nodes across datacenters with sovereignty constraints.

The early exploration (rescue era, `ROADMAP.md` Tier 4) proposed an ambitious stack: **Cilium + eBPF XDP + BGP announcements + ECDSA-signed discovery**. The target was ~100 ns routing decisions and full in-kernel DLP. This is impressive but carries real costs:

- Cilium requires Kubernetes. Bare-metal deployments need a different path.
- eBPF XDP requires Linux ≥ 5.10 with specific NIC drivers.
- BGP implies managing route reflectors, ASNs, and peering — operational burden disproportionate for < 50 nodes.
- Signed discovery with ECDSA re-issuance every 5 min is a crypto pipeline to maintain.

The 2026-04-08 architect brief (D-02, D-10) said: **no Cilium by default, no mandatory BGP, no eBPF XDP**. The default topology must be viable on bare-metal and K8s-vanilla with no special drivers. A second profile exists for customers who actually operate > 50 nodes, but it is optional and untouched until there is a client paying for it.

## Decision Drivers

- **KISS** — a solo operator should be able to deploy a 3-node mesh in an afternoon.
- **Secure by design** — WireGuard gives authenticated, encrypted transport out of the box; nothing else to bolt on.
- **Target bare-metal and K8s vanilla** — no assumption of Cilium, no assumption of eBPF.
- **Two explicit profiles** — don't hide the scale path. Document both so teams can plan growth.
- **TDD** — each profile has a reference test topology that CI can exercise.

## Considered Options

1. **Cilium + eBPF XDP as the default** (original rescue Tier 4). Rejected: too much operational burden for the first 10 clients.
2. **Istio / Linkerd service mesh** (sidecar model). Rejected: L7 overhead, per-pod certs, scales but complicates single-binary deployments.
3. **WireGuard full-mesh with static routes** — default. KISS, secure, portable.
4. **Two profiles**: `wg-static` as default, `bgp-managed` as opt-in for scale.

## Decision Outcome

**Chosen: option 4 — two profiles.**

### Profile 1: `wg-static` (default)

Topology:

- **Full-mesh** for ≤ 10 nodes (everyone peers with everyone).
- **Hub-spoke** for 10–50 nodes (one or two hubs, others peer only to the hub). Hub election is static in config.

Technology:

- **WireGuard** as the data plane (kernel or `wireguard-go`, both supported).
- **Static routing** distributed via the Grob config file (`[mesh.peers]` + `[mesh.routes]`). No dynamic discovery protocol. Config changes via `/api/config/reload`.
- **Sokolsky** ([ADR-0017](0017-sokolsky-log-backend.md)) handles the cross-plane audit trail, riding on top of the WireGuard transport.
- **mTLS** on top of WireGuard for node-to-node RPCs, with per-node certs.

Operational story:

```
operator drafts [mesh.peers] in grob.toml
  └─ shares config (committed to a private repo) with peers
  └─ each peer applies the same config → all tunnels come up
  └─ Sokolsky picks up the mTLS channel for audit
```

No route reflectors. No ASNs. No BGP daemon.

### Profile 2: `bgp-managed` (opt-in, > 50 nodes)

Topology:

- **K8s**: Cilium cluster mesh with BGP control plane.
- **Bare-metal**: BIRD or FRR running BGP, WireGuard as the data plane underneath.

When to switch:

- Node count crosses ~50.
- Multi-region with dynamic failover requirements.
- Customer explicitly needs eBPF XDP path for throughput.

This profile is **not gated** — any customer can enable it — but it is **not supported out of the box** without a conversation about operational burden. The Grob binary provides config schema and probes; the BGP infrastructure is the customer's responsibility.

## Consequences

### Positive

- Default deployment is accessible. An afternoon to get a 3-node dev cluster up.
- Security by default: WireGuard authenticates every peer cryptographically, no plaintext links.
- Two documented profiles remove the "what about scale?" objection without dragging scale complexity into the default path.
- Sokolsky layering is cleaner: one transport (WireGuard), one audit channel (mTLS), one witness model (N-of-N).
- Cuts the Tier 4 roadmap's critical path dramatically. C-1 prototype becomes a weekend.

### Negative

- Static routing means config drift must be actively managed. No automatic convergence.
- Hub-spoke at 10-50 nodes is a compromise: the hub is a single point of failure. Mitigation: dual-hub. Documented as an operational concern.
- The `bgp-managed` profile is documented but not actively tested in CI until a client funds it. Expected risk: the profile stays theoretical.

### Neutral / to watch

- If eBPF XDP becomes a client requirement, this ADR is revisited.
- WireGuard kernel module availability on hardened OS images (some enterprise Linux distros) must be verified per target.
- The future `mesh.routes` config schema should be forward-compatible with both profiles.

## Follow-ups and related ADRs

- Implementation chantiers (Phase C, deferrable):
  - **C-1** — WireGuard full-mesh prototype (3 nodes), profile `wg-static`.
  - **C-2** — Compliance routing with static `[mesh.routes]`.
  - **C-3** — Sokolsky cross-plane production wiring.
  - **C-4** (optional) — profile `bgp-managed`, gated on > 10 nodes demand.
- [ADR-0017](0017-sokolsky-log-backend.md) — the audit transport that sits on top of this mesh.
- [ADR-0012](0012-no-unikernel.md) — same KISS philosophy.
- Architect decisions: D-02, D-10.
- Obsidian concept: `50 - Concepts/Decision Tokens et Sokolsky.md` (Sokolsky context).
