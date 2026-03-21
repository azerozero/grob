# Grob Roadmap — Priorités par impact business

**Dernière MAJ** : 2026-03-21

---

## Tier 1 — Vendre (semaines 1-2) ✅

| # | Feature | Status |
|---|---------|--------|
| 1 | Benchmark publié (overhead, RPS, escalation, payload sizes) | ✅ |
| 2 | README "Obviously Awesome" | ✅ |

## Tier 2 — Différenciation visible (semaines 3-6) ✅

| # | Feature | Status |
|---|---------|--------|
| 3 | `grob watch` (TUI dashboard live) | ✅ |
| 4 | OpenTelemetry (OTLP export) | ✅ |

## Tier 3 — Scale & monétisation (mois 2-4) ✅

| # | Feature | Status |
|---|---------|--------|
| 5 | Virtual keys multi-tenant (budget, rate limit, model allowlist) | ✅ |
| 6 | Log export (stdout, file, HTTP) | ✅ |
| 7 | Multi-account key pool (sequential, round_robin, fallback) | ✅ |
| 8 | Config promotion pipeline (push, pull, rollback) | ✅ |
| 9 | `grob bench` CLI (escalation, concurrency, 5 payload sizes) | ✅ |

---

## Tier 4 — Proxy Mesh Souverain (M6-M12)

Architecture multi-node avec routage par conformité, eBPF XDP, et annonces signées.

### Pricing cible

| Tier | Prix | Inclut |
|------|------|--------|
| **Community** | Gratuit (AGPL) | Single node, toutes les features actuelles |
| **Pro** | 500-800€/mois | Virtual keys, log export, support 48h SLA |
| **Enterprise** | 2 000-5 000€/mois | Mesh multi-node, annonces signées, audit cross-node |
| **Sovereign** | 20-50k€/an + consulting | Air-gapped, eBPF XDP, LoRA adapters, PKI custom |

### Phase 4.1 — Mode passthrough (2-3j)

Byte-level proxy sans JSON parsing quand aucune feature L7 n'est activée.

| Métrique | Actuel (L7) | Passthrough | Bifrost |
|----------|:---:|:---:|:---:|
| Overhead | ~100µs | **~5µs** | 11µs |
| Technique | hyper zero-copy, pas de serde | io::copy blob | Go net/http |

### Phase 4.2 — Mesh discovery + annonces signées (5-7j)

Chaque node broadcast ses capacités de conformité, signées cryptographiquement.

| Feature | Description |
|---------|-------------|
| **Annonces signées** | JSON signé ECDSA P-256 : `node_id`, `capabilities` (RGPD, PCI, HIPAA, air-gap), `region`, `load`, `timestamp` |
| **Signataire** | Humain (RSSI certifie la conformité PCI), HSM (rotation auto), ou pipeline CI (post-audit) |
| **Vérification** | Les nodes vérifient la signature avant d'accepter le routage |
| **Lifecycle** | Re-annonce toutes les 5 min, expiration après 15 min sans refresh |
| **Anti-tampering** | Node retiré du mesh si signature invalide ou expirée |

```toml
[mesh.announce]
signing_key = "/etc/grob/mesh-signing.key"  # ECDSA P-256
interval = "5m"
expires_after = "15m"
# Qui signe : "human" | "hsm" | "ci-pipeline"
signer_type = "human"
```

```json
{
  "node_id": "eu-paris-01",
  "capabilities": ["gdpr", "pci-dss", "eu-ai-act"],
  "region": "eu-west-3",
  "providers": ["mistral", "ovh-ai"],
  "load": 0.3,
  "timestamp": "2026-03-21T10:00:00Z",
  "signer": "rssi@company.com",
  "signature": "MEUCIQD..."
}
```

### Phase 4.3 — Mesh controller + routage conformité (5-7j)

| Feature | Description |
|---------|-------------|
| **Controller** | Reçoit les annonces, maintient la table de routage par conformité |
| **Routage par contrainte** | Client demande "RGPD + PCI" → route vers Node EU Paris |
| **Geo-routing** | Latence-aware + data residency (région tag) |
| **Failover mesh** | Si Node EU-1 down → circuit breaker → failover vers Node EU-2 |
| **mTLS inter-node** | Tous les hops chiffrés avec certificats clients mutuels |
| **Load balancing** | Pondéré par `load` dans les annonces (least-loaded first) |

```
Client → Grob Local (Bearer grob_xxx)
  → lit .grob.toml → compliance = ["pci-dss", "air-gap"]
  → DLP scan local (AVANT de quitter la machine)
  → Mesh Controller (mTLS) → "route pci-dss + air-gap"
  → Controller → Node Air-Gap Brest (mTLS)
  → Ollama/vLLM local → réponse
  → Audit signé à chaque hop
```

### Phase 4.4 — eBPF XDP + Hyperscan DLP (5-10j)

Architecture hybride kernel/userspace avec **DLP complet en kernel** via Hyperscan.

**Référence** : [Gcore](https://gcore.com/blog/how-we-use-regular-expressions-in-xdp-for-packet-filtering) fait du regex dans XDP en production à 200M pps en compilant Hyperscan comme kernel module. Linux 6.x+ supporte `bpf_loop` (8M iterations) et les open-coded iterators (v6.4+).

#### DLP en kernel — ce qui est maintenant possible

| Validation DLP | XDP+Hyperscan | Comment | Latence |
|----------------|:---:|---------|:---:|
| Secret scan (25 patterns) | ✅ | Hyperscan kernel module (Aho-Corasick) | ~100 ns |
| PII credit card (Luhn) | ✅ | `bpf_loop` arithmétique | ~50 ns |
| PII IBAN (mod97) | ✅ | `bpf_loop` arithmétique | ~50 ns |
| Prompt injection (28 langues) | ✅ | Hyperscan kernel module | ~100 ns |
| URL exfiltration (prefix) | ✅ | Prefix match dans XDP | ~50 ns |
| Name pseudonymization | ❌ | HMAC + state → userspace | ~1µs |
| JSON parsing | ❌ | Pas de parser JSON en kernel | — |
| Routing inter-node | ✅ | L3/L4 packet forwarding | ~200 ns |
| mTLS termination | ❌ | Userspace (kTLS pour data path) | ~50µs |

#### Architecture

```
Packet arrive
     │
     ▼
┌──────────────────────────────┐
│  XDP + Hyperscan module      │  ~100-200 ns
│                               │
│  1. Hyperscan: 25 patterns   │  ← DLP secrets complet en kernel
│  2. Luhn checksum (bpf_loop) │  ← Credit card en kernel
│  3. Injection regex          │  ← 28 langues en kernel
│  4. URL prefix scan          │  ← Exfiltration en kernel
│                               │
│  ├─ Clean → XDP_REDIRECT     │──→ Forward direct (~200 ns)
│  ├─ Secret → XDP_PASS        │──→ Userspace (redaction ~100µs)
│  └─ Injection → XDP_DROP     │──→ Block instantané (~200 ns)
└──────────────────────────────┘
```

#### Performance

| Scénario | Sans XDP | Avec XDP+Hyperscan | Gain |
|----------|:---:|:---:|:---:|
| Clean traffic (99%) | ~170µs | **~100-200 ns** | **1000x** |
| Secret détecté (block) | ~400µs | **~200 ns** (XDP_DROP) | **2000x** |
| Secret détecté (redaction) | ~400µs | ~400µs (userspace) | 0 |
| Injection (block) | ~400µs | **~200 ns** (XDP_DROP) | **2000x** |
| Inter-node forward | ~50µs | **~200 ns** | **250x** |

#### Sous-phases

| # | Composant | Effort |
|---|-----------|--------|
| 4.4a | Hyperscan kernel module + eBPF helpers | 5-7j |
| 4.4b | Programme XDP DLP (`aya-rs`) | 3-5j |
| 4.4c | Luhn/mod97 en `bpf_loop` | 1-2j |
| 4.4d | Intégration grob (XDP_PASS → userspace) | 2-3j |

**Crates** : `aya` (Rust eBPF), Hyperscan (Intel, kernel module).

#### Limites physiques

| Technique | Floor | Usage |
|-----------|:---:|---|
| HTTP TCP | ~3-5 µs | Standard actuel |
| eBPF XDP | ~100 ns | Kernel forwarding + DLP |
| DPDK | ~50 ns | Kernel bypass complet (CPU dédié) |
| Shared memory | ~10 ns | Intra-machine |
| L1 cache | ~1 ns | Intra-process |
| Sub-ns | Impossible | Limite physique (lumière = 30cm/ns) |

### Phase 4.5 — Cross-node audit (3-5j)

| Feature | Description |
|---------|-------------|
| **Merkle chain partagé** | Chaque hop ajoute une entrée signée à la chaîne d'audit |
| **Traçabilité cross-node** | Audit trail complet : client → local → mesh → node → provider |
| **Vérification end-to-end** | Un auditeur peut vérifier la chaîne complète avec les clés publiques de chaque node |
| **Non-répudiation** | Chaque node signe son entrée — impossible de nier le traitement |

### Effort total Tier 4

| Phase | Composant | Effort |
|-------|-----------|--------|
| 4.1 | Mode passthrough | 2-3j |
| 4.2 | Mesh discovery + annonces signées | 5-7j |
| 4.3 | Mesh controller + routage conformité | 5-7j |
| 4.4 | eBPF XDP | 3-5j |
| 4.5 | Cross-node audit | 3-5j |
| **Total** | | **~3-4 semaines** |

---

## Zero Trust — Sécurité inter-composants

### Niveau 1 — Implémenté ✅

| Feature | Status |
|---------|--------|
| JWT auth sur requêtes entrantes | ✅ RS256/HS256, JWKS refresh |
| Virtual keys auth | ✅ SHA-256 hash, per-key budget/rate-limit |
| Rate limiting par token | ✅ Per-tenant token bucket |
| Constant-time auth | ✅ `subtle` crate |
| mTLS client cert upstream | ✅ `tls_cert`/`tls_key`/`tls_ca` par provider |
| Rotation clé DLP | ✅ Auto toutes les 24h (configurable) |

### Niveau 2 — Feature requests (backlog)

| Feature | Description | Priorité |
|---------|-------------|----------|
| **LoRA adapter registry** | Distribution sécurisée de LoRA via OCI registry avec signature ECDSA + manifest SHA-256 + licence token JWT | M6+ |
| **LoRA chargement dynamique** | Header `X-Dunst-Adapter` + vérification JWT → charge l'adapter si en cache, pull si absent | M6+ |
| **LoRA fichier local (air-gap)** | `.gguf` + `.gguf.sig` + `manifest.toml` avec SHA-256 + signature ECDSA. Refus de démarrer si sig invalide. | M6+ |
| **HSM pour clés de session** | PKI complète avec HSM pour les clés de session DLP. Overkill sauf contrat OTAN. | Sur demande client |
| **Re-auth par requête LLM** | Vérifier l'identité à chaque token généré. Overkill pour 99% des cas. | Sur demande client |
| **Intégrité SSE stream** | Signature de chaque chunk SSE. Overkill. | Sur demande client |

---

## Cleancode — Dette technique ✅

**Score** : 7.4/10 → corrigé (handler boilerplate, scorer consolidation, router tests, crypto unwrap, error-path tests).

---

## Documentation ✅

**DCI Score** : 9.5/10. 16 docs de référence, AGENTS.md, llms.txt, feature matrix avec vérification compliance.

---

## Benchmarks — Chiffres publiés ✅

### Overhead par feature (80KB payload, macOS 16 cores)

| Scénario | P50 | Overhead pur |
|----------|:---:|:---:|
| TCP baseline (direct) | 123µs | — |
| Proxy pur | 290µs | +167µs |
| + DLP (clean text) | 556µs | +433µs |
| + DLP (trigger) | 533µs | +410µs |
| + All features | 537µs | +414µs |

### Throughput concurrent (c=16)

| Scénario | RPS |
|----------|:---:|
| Direct baseline | 82,500 |
| Proxy + all features | 40,100 |

### Signing cost

| Algorithme | Latence |
|-----------|:---:|
| HMAC-SHA256 | 1.2µs |
| Ed25519 | 19µs |
| ECDSA P-256 | 152µs |

### Comparaison concurrence

| Proxy | Overhead | RPS | Features actives |
|-------|:---:|:---:|---|
| **Grob** | **~100µs** | **40K** | DLP + routing + cache + rate limit |
| Bifrost | 11µs | 5K | Proxy pur (byte-copy) |
| TensorZero | 370µs | 10K | Proxy pur |
| LiteLLM | ~5000µs | 200 | Proxy pur |

---

## Pas prioritaire (backlog)

| Feature | Pourquoi pas maintenant |
|---------|------------------------|
| SSO/OIDC | Premiers clients en air-gapped — pas d'Okta |
| RBAC | Besoin de virtual keys d'abord |
| Embeddings/images/audio | Marché = coding assistants, pas DALL-E |
| A2A protocol | Trop early, adoption quasi nulle |
| SOC2/ISO | 0 client payant, $30-100k de certification = overkill |
| LoRA-as-a-Service | Phase 3 (M6+). D'abord valider la traction proxy |
