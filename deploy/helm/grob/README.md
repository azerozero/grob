# grob Helm chart

Deploys [grob](https://github.com/azerozero/grob), the multi-provider LLM
routing proxy, on Kubernetes.

## Install

```bash
# From a checkout of the repo:
helm install grob deploy/helm/grob \
  --namespace grob --create-namespace \
  -f my-values.yaml
```

Render/validate without installing:

```bash
helm lint deploy/helm/grob
helm template grob deploy/helm/grob -f my-values.yaml
```

## What it creates

| Resource | Purpose |
|----------|---------|
| Deployment | grob server (uid 65534, read-only rootfs, no caps, seccomp RuntimeDefault) |
| ConfigMap | renders `config.toml` from `.Values.config`, mounted read-only at `/etc/grob` (`GROB_CONFIG`) |
| Secret | provider API keys / tokens injected via `envFrom` (empty by default; `existingSecret` to reuse one) |
| PVC | persistent `GROB_HOME` at `/var/lib/grob` (tokens + spend journals) |
| Service | ClusterIP on `:8080` — **not** exposed externally |
| Probes | startup `/health`, liveness `/live`, readiness `/ready` |
| ServiceMonitor (opt) | Prometheus Operator scrape of `/metrics` |
| HPA (opt) | scales on the `grob_active_requests` gauge |
| Ingress (opt) | public LLM paths only (`/v1`, `/health`) |
| NetworkPolicy (opt) | restricts who can reach the shared port |

## Key values

| Value | Default | Notes |
|-------|---------|-------|
| `replicaCount` | `1` | see **Budget & replicas** |
| `budget.acknowledgeMultiReplicaRisk` | `false` | required to render >1 replica |
| `image.repository` / `image.tag` | `ghcr.io/azerozero/grob` / chart `appVersion` | |
| `config` | minimal TOML | full `grob.toml`, rendered verbatim into the ConfigMap |
| `secret.create` / `secret.existingSecret` | `true` / `""` | provider keys as env (`env:NAME` in config); empty Secret by default |
| `persistence.enabled` / `.size` / `.accessModes` | `true` / `1Gi` / `[ReadWriteOnce]` | `GROB_HOME` PVC |
| `service.type` / `service.port` | `ClusterIP` / `8080` | |
| `metrics.bearerTokenSecret` | `{}` | `{name,key}` of a Secret mounted at `/etc/grob/metrics/<key>` for `[metrics] bearer_token_file` |
| `serviceMonitor.enabled` | `false` | Prometheus Operator |
| `serviceMonitor.bearerTokenSecret` | `{}` | `{name,key}` of a Secret to present when scraping a gated `/metrics` |
| `autoscaling.enabled` / `.maxReplicas` | `false` / `1` | HPA on `grob_active_requests` |
| `ingress.enabled` / `networkPolicy.enabled` | `false` / `false` | exposure controls |

## Budget & replicas (read this)

grob enforces spend budgets from **per-pod, append-only spend journals** under
`GROB_HOME`. With the default `ReadWriteOnce` PVC each pod owns its journal, so:

- **1 replica (default):** a single authoritative running total — budgets hold.
- **N replicas:** each pod tracks spend independently → the effective cap is
  roughly **N× the configured budget**, and totals diverge between pods.

The chart therefore **refuses to render** more than one replica
(`replicaCount > 1` or `autoscaling.maxReplicas > 1`) unless you set
`budget.acknowledgeMultiReplicaRisk: true`. For a *single* shared budget across
replicas you need a `ReadWriteMany` volume shared by all pods (set
`persistence.accessModes: [ReadWriteMany]` and a suitable `storageClass`) — and
even then concurrent appends are not strongly serialized, so treat the cap as
best-effort.

## Persistence

`persistence.enabled: true` is the safe default. The PVC at `GROB_HOME` holds the
OAuth token store (refreshed/rewritten at runtime) and the month-to-date spend
journals. **Disabling it loses both on every restart** (forced re-auth + budget
reset). The Deployment uses the `Recreate` strategy so a `ReadWriteOnce` volume
is never mounted by two pods at once.

## Control plane is on the same port

`/api/config/reload`, `/rpc`, `/api/oauth/*` and `/api/config` are served on the
**same HTTP port** as the LLM API. Keep them cluster-internal:

- The `Service` is `ClusterIP` (no external exposure) by default.
- The optional `Ingress` routes **only** `/v1` and `/health` — never control paths.
- Enable `networkPolicy` to allow only approved clients to reach the port.
- For admin actions, reach the control plane via `kubectl port-forward`.

## Config reloads

The pod template carries a `checksum/config` (and `checksum/secret`) annotation,
so `helm upgrade` after editing `config`/`secret` triggers a rolling restart that
picks up the new config. Alternatively, grob exposes `POST /api/config/reload`
to hot-swap reloadable state without a restart (reach it internally, per above).

## Metrics & autoscaling

`serviceMonitor.enabled: true` registers a Prometheus Operator scrape of
`/metrics`. The HPA targets the `grob_active_requests` gauge and needs a custom
metrics adapter (e.g. `prometheus-adapter`) publishing it as a Pods metric.
Remember the budget caveat above before enabling autoscaling.

### Authenticating `/metrics`

`/metrics` is **public by default** (it carries spend, budget, and tenant
labels — keep it internal). To require a bearer token, keep the token in a
**Secret mounted as a file** and point grob's `bearer_token_file` at it. **Never**
put the token inline in `config` — that value is rendered into the ConfigMap and
the Helm release history in clear text.

```bash
# 1. Create the Secret holding the token (out of band, or via secret.data):
kubectl create secret generic grob-metrics-token --from-literal=token=<TOKEN>
```

```yaml
# 2. Mount it into the grob pod and reference it in config (a PATH, not the token):
metrics:
  bearerTokenSecret:
    name: grob-metrics-token
    key: token                       # mounted at /etc/grob/metrics/token
config: |
  # ...your config...
  [metrics]
  bearer_token_file = "/etc/grob/metrics/token"

# 3. Make Prometheus present the SAME token when scraping:
serviceMonitor:
  enabled: true
  bearerTokenSecret:
    name: grob-metrics-token
    key: token
```

Unauthorized scrapes then get `401`. `/health`, `/live`, and `/ready` stay
public. TLS is handled by your ingress / the chart's TLS settings, not here.

> Changing the token requires a pod restart — grob resolves it once at startup,
> so `POST /api/config/reload` deliberately rejects `[metrics]` token changes.
> The config/secret checksums annotated on the Deployment already roll the pod
> on `helm upgrade` when the mounted Secret changes.
