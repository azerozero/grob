# Design Doc: DLP images/vidéos, provenance (watermark + C2PA), et control plane d'agents

**Author**: ludwig
**Status**: Draft
**Date**: 2026-08-04
**Reviewers**: TBD

## Context

Le DLP de Grob (`src/features/dlp/`) est 100 % texte : Aho-Corasick + DFA sur les chunks SSE,
scan des URLs et images Markdown (`url_exfil.rs`), canaries (`canary.rs`).
Or le pipeline transporte déjà des images : `KnownContentBlock::Image { source: ImageSource }`
(base64 ou URL) côté requête, et `KnownToolResultBlock::Image` côté résultats d'outils
(screenshots d'agents navigateur, captures de terminal, PDF rendus).

Deux angles morts :

1. **Exfiltration par pixel.** Un screenshot d'IDE contient des clés API, un `.env`, du code
   client, des visages, un écran de prod. Aujourd'hui il traverse Grob sans être regardé.
   Symétriquement, une image *entrante* peut porter une prompt injection écrite en texte
   dans l'image, invisible pour le scanner texte mais lue par le modèle vision.
2. **Provenance.** Quand une image sort d'un agent (générée, ou capturée puis rediffusée),
   rien ne dit d'où elle vient : quel tenant, quelle session, quel modèle, quelle policy.
   Impossible de tracer une fuite a posteriori.

Question posée : « une lib JS qui lit une sorte de QR code dans l'image/vidéo pour retrouver
les infos stockées dedans, c'est une bonne idée ? »

## Goals

- Scanner le contenu image (in et out) avec la même sémantique que le DLP texte :
  `Allow | Redact | Warn | Block`, mêmes rapports, mêmes events tap/watch.
- Marquer toute image/vidéo qui transite par Grob avec une provenance vérifiable,
  et pouvoir la relire côté client (lib JS) comme côté serveur (RPC).
- Ne pas casser le budget latence du chemin chaud : le scan image doit être hors du
  chemin bloquant par défaut (opt-in synchrone).
- Rester dans les invariants Grob : feature flag, trait-driven, config TOML, zéro I/O
  supplémentaire obligatoire.

## Non-Goals

- Faire de la reconnaissance de visages/objets généraliste. Hors périmètre : c'est un
  produit de vision, pas un proxy.
- Transcoder/ré-encoder de la vidéo dans le proxy. Grob n'est pas un pipeline média.
- Prétendre à un DRM inviolable. Un watermark robuste est **dissuasif et traçant**,
  pas cryptographiquement inarrachable.
- Embarquer un moteur OCR lourd (Tesseract, ONNX) dans le binaire 6 MB par défaut.

## Réponse directe : le QR code dans l'image, bonne idée ?

**Comme brique unique : non. Comme couche visible optionnelle : oui.**

Ce qui cloche avec « je colle un QR dans le coin » :

- **Visible** → on le recadre en deux secondes, le premier crop tue la traçabilité.
- **Fragile** → recompression JPEG agressive, resize, screenshot d'écran, capture de
  capture : le QR se dégrade vite hors de ses tolérances.
- **Coût pixel** → il mange de la surface utile, inacceptable sur un screenshot d'UI.
- **Capacité mal placée** → un QR stocke des octets ; on veut un *identifiant opaque*
  qui pointe vers un registre, pas la donnée elle-même (mettre le tenant en clair dans
  l'image, c'est créer une nouvelle fuite).

Le bon découpage est en trois couches indépendantes qui dégradent gracieusement :

| Couche | Support | Survit à | Casse sur | Rôle |
|---|---|---|---|---|
| **L1 — Métadonnées signées** (C2PA / manifeste dans XMP/EXIF) | conteneur du fichier | copie, transfert, upload | screenshot, strip metadata, ré-encodage | provenance riche et vérifiable, cas nominal |
| **L2 — Watermark invisible robuste** (spectre étalé / DCT-DWT, style Trustmark/SynthID) | pixels | recompression, resize, crop partiel, screenshot | crop massif, régénération, forte dégradation | identifiant opaque 64–128 bits, cas hostile |
| **L3 — Empreinte perceptuelle** (pHash / dHash indexé côté serveur) | aucune modif de l'image | tout, y compris strip complet | transformation sémantique lourde | rattrapage « d'où vient cette image ? » sans rien avoir écrit dedans |

Le QR devient une variante *L2-visible* : utile seulement quand on **veut** que ce soit
visible (asset publié, marquage légal, démo), jamais comme mécanisme principal.

Ce qui est écrit dans L1/L2 : **jamais** de données métier. Uniquement
`trace_id` (128 bits aléatoires) + version de schéma. Le mapping
`trace_id → {tenant, session, model, policy, timestamp}` vit dans le `GrobStore`
(journal JSONL append-only, comme le spend). Cohérent avec le modèle de données existant
et ça évite de transformer le watermark en canal d'exfiltration.

Une lib JS de lecture reste souhaitable : elle lit L1 (parse C2PA/XMP, pur JS), calcule L3
(pHash en WASM ou Canvas) et appelle Grob pour résoudre le `trace_id`. La détection L2
robuste est du traitement du signal → WASM, ou déportée sur l'endpoint serveur.

## Proposed Design

### A. `src/features/media/` (feature flag `media`, off par défaut)

Nouveau module frère de `dlp/`, avec le même style trait-driven :

```rust
pub trait MediaScanner {                       // → src/traits.rs
    fn scan(&self, m: &MediaRef) -> MediaVerdict;
}
pub trait MediaMarker {
    fn embed(&self, m: &mut MediaBuf, trace: TraceId) -> Result<(), MediaError>;
    fn extract(&self, m: &MediaRef) -> Option<TraceId>;
}
```

`MediaRef` s'obtient depuis `ImageSource` sans copie quand c'est du base64 inline ;
les images par URL ne sont **pas** téléchargées par défaut (`fetch_remote = false`,
sinon on offre un SSRF au client).

Sous-modules :

- `decode.rs` — sniff du format (magic bytes), bornes dures (`max_bytes`, `max_pixels`)
  contre les décompression bombs, refus par défaut de tout format non listé.
- `scan/` — les détecteurs, du moins cher au plus cher :
  - `heuristics.rs` — taille, ratio, format, entropie, présence de métadonnées EXIF/GPS
    (une image avec GPS qui part chez un provider, c'est déjà un signal).
  - `stego.rs` — détection de payload caché grossier (LSB, tail-append après le marqueur
    de fin), pas cher et directement anti-exfiltration.
  - `text.rs` — OCR **optionnel**, derrière la feature `media-ocr`, qui réinjecte le texte
    extrait dans le `DlpEngine` existant. C'est le point clé : zéro duplication de règles,
    l'image devient juste une nouvelle source de texte pour le DFA déjà là. Sur macOS on
    peut brancher Vision ; sinon sidecar HTTP, jamais linké en dur dans le binaire scratch.
  - `phash.rs` — empreinte perceptuelle (L3), et matching contre une deny-list
    d'images connues (documents internes, slides confidentielles).
- `mark/` — `c2pa.rs` (L1), `invisible.rs` (L2, DWT-DCT), `qr.rs` (L3-visible, opt-in).
- `registry.rs` — journal `~/.grob/media/YYYY-MM.jsonl` : `trace_id`, phash, verdict,
  tenant, model, ts. Même pattern que `spend/`.

### B. Point d'insertion dans le pipeline

Dans `src/server/dispatch/mod.rs`, à côté des appels DLP existants
(`sanitize_request_reported` / `sanitize_provider_response_reported`) :

```
request  → [DLP texte] → [Media scan in]  → tool_layer → cache → provider
response → [DLP texte] → [Media scan out] → [Media mark] → client
```

Trois modes de scan, configurables :

- `off` (défaut),
- `async` — l'image part, le scan tourne en tâche détachée, alimente registry + tap/watch.
  Coût zéro sur la latence, détection post-hoc. C'est le défaut recommandé.
- `blocking` — verdict avant émission, avec `timeout_ms` et fail-open/fail-closed explicite.

Le marquage sortant est lui toujours synchrone mais bon marché : L1 est une écriture de
métadonnées ; L2 n'est appliqué que si `watermark = true` et que le média est décodable.

### C. Surfaces d'exposition

- **RPC** — nouveau namespace `media` dans `src/control/engine.rs` +
  `src/server/rpc/media_ns.rs` : `media/verify` (image → trace_id + provenance),
  `media/trace` (trace_id → contexte), `media/policy`. RBAC : `verify` = Observer,
  `trace` = Operator (il révèle tenant/session).
- **MCP** — bridge automatique via `control_bridge.rs`, un agent peut demander
  « d'où vient cette image ? ».
- **HTTP** — `POST /v1/media/verify` (multipart), le seul endpoint dont la lib JS a besoin.
- **CLI** — `grob media verify <file>`, `grob media trace <id>`.
- **Tap/watch** — nouveaux events `media.scanned`, `media.blocked`, `media.marked`.

### D. La lib JS (`grob-media-verify`, package séparé)

```js
const r = await grobMedia.verify(fileOrBlob, { endpoint: "https://grob/v1/media/verify" });
// { level: "c2pa" | "watermark" | "phash" | "none",
//   traceId, verified: bool, provenance?: {...} }
```

Fait en local ce qui est local (parse C2PA, pHash), délègue le reste. Pas de secret
côté client. Le résultat inclut *quelle couche* a répondu, ce qui rend la confiance
lisible plutôt que binaire.

### E. Vidéo

Même architecture, mais on ne décode pas de vidéo dans le proxy. Découpage :
L1 sur le conteneur (MP4 `uuid` box / Matroska tags), L3 sur des keyframes échantillonnées
via un sidecar ffmpeg optionnel, L2 hors périmètre v1. Le tag doit être **par segment**,
pas par fichier, sinon un simple découpage efface la provenance.

## Alternatives Considered

- **QR visible seul.** Simple, lisible partout, zéro dépendance signal. Rejeté comme
  mécanisme principal : un crop suffit à l'annuler, et il pollue l'image. Conservé en L3-visible.
- **EXIF/XMP seuls (sans C2PA).** Trivial à écrire. Rejeté : strip par n'importe quel
  upload, non signé donc falsifiable. C2PA coûte plus cher mais apporte la signature.
- **Watermark cryptographique fort / vrai DRM.** Chiffrement + client de confiance.
  Rejeté : suppose de contrôler le lecteur, ce que Grob ne fait pas. On vise la traçabilité,
  pas le contrôle d'usage.
- **Déléguer tout le scan image à un service tiers.** Rejeté par défaut : envoyer les
  screenshots à scanner à un tiers, c'est exactement la fuite qu'on veut empêcher.
  Le sidecar reste local et optionnel.
- **Tout mettre dans le DLP existant.** Rejeté : le DLP est un chemin chaud streaming,
  strictement CPU-texte. Y greffer du décodage image dégraderait le p99 pour tout le monde.

## Risks and Mitigations

| Risque | Mitigation |
|---|---|
| Décompression bomb / DoS via image | bornes dures pré-décodage, timeout, mode `async` par défaut |
| SSRF via `ImageSource::Url` | pas de fetch distant par défaut, allow-list si activé |
| Faux positifs OCR→DLP bloquants | mode `async` par défaut, `blocking` explicite et opt-in |
| Le watermark devient un canal d'exfil | seul un `trace_id` opaque est embarqué, jamais de donnée métier |
| Poids binaire (6 MB, `FROM scratch`) | feature `media` off par défaut, OCR en sidecar, jamais linké |
| Fausse confiance en la provenance | la réponse dit toujours *quelle couche* a matché et si elle est signée |

## Plan de livraison

1. **Slice 1 — squelette.** `src/features/media/`, feature flag, `MediaRef` depuis
   `ImageSource`, decode + bornes, `phash.rs`, registry JSONL, events tap. Aucun blocage,
   observation seule.
2. **Slice 2 — verdicts.** heuristics + stego, wiring dispatch en mode `async`,
   politique par policy (`src/features/policies/`), mode `blocking`.
3. **Slice 3 — provenance.** C2PA (L1) + registry `trace_id`, RPC `media/*`,
   endpoint HTTP, CLI.
4. **Slice 4 — watermark.** L2 invisible + QR opt-in, lib JS, tests de robustesse
   (recompression/resize/crop/screenshot) en harness.
5. **Slice 5 — vidéo.** L1 conteneur + keyframes L3 via sidecar.

Chaque slice = une ADR courte + un `README.md` de module, conforme au flow du repo.

---

# Partie 2 — Control plane d'agents

## État actuel

Grob a déjà l'ossature d'un control plane, mais **orienté proxy**, pas **orienté agent** :

- `src/control/engine.rs` — catalogue d'actions `(role, action)` + RBAC 4 niveaux,
  partagé CLI/RPC/MCP. Bonne fondation, stateless.
- `src/server/rpc/` — 9 namespaces (`server`, `model`, `provider`, `budget`, `keys`,
  `config`, `tools`, `hit`, `pledge`).
- `src/features/pledge/` — retrait structurel d'outils avant dispatch. C'est déjà du
  contrôle d'agent : la capacité n'existe pas, donc l'agent ne peut pas la tenter.
- `src/features/policies/` — decision tokens, multisig, quorum, HIT (human-in-the-loop).
- `src/features/tool_layer/` — aliasing, capability gating, injection d'outils.
- `src/features/tap`, `watch` — événementiel et TUI temps réel.
- `orca.yaml` — sandbox podman par workspace, egress limité à grob + GitHub.

Autrement dit : les *primitives* (identité, capacités, budget, audit, HIT, isolation
réseau) existent déjà. Ce qui manque est la **notion d'agent comme entité de première classe**.

## Le gap

Aujourd'hui une requête a un tenant, une policy, un budget. Elle n'a pas d'**agent
identifié et durable**. Conséquences :

- Pas de budget par agent, seulement global/provider/model.
- Pas d'arbre de filiation : un subagent (`GROB-SUBAGENT-MODEL`) n'est pas rattaché à son
  parent, donc pas de budget hérité ni de kill récursif.
- Pas de cycle de vie : impossible de suspendre, reprendre, tuer un agent en cours.
- L'audit est par requête, pas par trajectoire d'agent.
- Aucune boucle de rappel : rien ne relie « cette image a fuité » à « quel agent l'a produite ».
  C'est précisément le `trace_id` de la partie 1 qui referme cette boucle.

## Direction proposée

**Un namespace `agent` + une identité qui traverse tout le pipeline.**

```rust
pub struct AgentId(Ulid);
pub struct AgentContext {
    id: AgentId,
    parent: Option<AgentId>,   // filiation subagent
    tenant: TenantId,
    pledge_profile: String,    // capacités, réutilise l'existant
    budget: BudgetScope,       // hérité du parent, borné
    lease: Lease,              // TTL + renouvellement, mort par défaut
}
```

Points de conception qui comptent :

- **L'identité est portée, pas devinée.** En-tête `x-grob-agent-id` (ou tag système,
  comme `GROB-SUBAGENT-MODEL` aujourd'hui), propagée aux subagents. Sinon on retombe
  sur de l'heuristique fragile.
- **Le lease plutôt que le kill.** Un agent qui ne renouvelle pas son bail s'éteint tout
  seul. Un agent orphelin ne peut pas brûler du budget indéfiniment. C'est le seul modèle
  qui survit à un crash du superviseur.
- **Budget hiérarchique.** Le budget d'un enfant est prélevé sur celui du parent. Un
  subagent ne peut jamais dépasser son parent. Réutilise le journal spend, en ajoutant
  la dimension `agent_id`.
- **Capacités par filiation.** Un enfant hérite du profil pledge du parent et ne peut
  que le restreindre, jamais l'élargir. Monotone, comme `Role::has_at_least`.
- **Actions de contrôle** : `agent/spawn`, `agent/list`, `agent/inspect`, `agent/pause`,
  `agent/resume`, `agent/kill` (récursif sur les descendants), `agent/budget`,
  `agent/trace`. Exposées d'un coup en CLI + RPC + MCP via `ControlEngine`.
- **Trajectoire auditée.** Un agent produit une trace ordonnée d'événements
  (requêtes, outils, verdicts DLP, médias marqués). Journal JSONL, même pattern que le reste.
- **HIT branché sur l'agent.** `policies/hit` existe déjà ; le point d'attache naturel
  est l'agent, pas la requête isolée.

## Ce que ça débloque

- Kill switch réel : un agent qui déraille est coupé, descendance comprise.
- Attribution du coût par agent, pas par clé API.
- Post-mortem : d'une image marquée → `trace_id` → agent → trajectoire complète.
- Sandbox alignée : `orca.yaml` isole déjà au niveau réseau ; `AgentId` donne le pendant
  logique côté proxy.

## Risques

- **Scope creep vers l'orchestrateur.** Grob doit rester un *control plane*, pas un
  runtime d'agents. Il n'exécute pas, il autorise, borne, observe et coupe.
  Frontière à écrire noir sur blanc dans l'ADR.
- **Identité usurpable.** `x-grob-agent-id` en clair est déclaratif. Il faut le lier à
  la clé API / decision token (`policies/decision_token` existe déjà).
- **État persistant.** Le control plane actuel est stateless ; les agents introduisent
  du cycle de vie. À contenir dans `GrobStore`, sans base de données.

## Open Questions

- L'OCR : sidecar local, ou API vision du provider déjà configuré (attention, on
  enverrait alors l'image suspecte au provider, ce qui contredit l'objectif) ?
- C2PA en Rust : implémentation externe acceptable au regard du budget binaire et de
  `cargo-deny` ?
- Le watermark L2 : implémentation maison (DWT-DCT ~300 lignes, contrôlée mais à valider
  empiriquement) ou dépendance ?
- Les agents deviennent-ils un produit Admin/Enterprise (cf. ADR-0028 open-core boundary)
  ou restent-ils dans le cœur Apache ?
- Faut-il un `agent_id` obligatoire à terme, avec un agent implicite par défaut ?
