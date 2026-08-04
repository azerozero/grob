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

Bonne nouvelle : ce découpage à couches est exactement ce que l'industrie a standardisé
sous le nom **Durable Content Credentials** (Adobe / CAI). La spec C2PA 2.1 appelle
watermark et fingerprint des **soft bindings**, et impose qu'ils soient produits par un
algorithme de la [C2PA Soft Binding Algorithm List](https://github.com/c2pa-org/softbinding-algorithm-list).
Le principe officiel est littéralement le nôtre : si une plateforme strippe le manifeste
C2PA, on retrouve la provenance dans une base en ligne via le watermark ou l'empreinte.
Donc on n'invente rien, on implémente un standard, ce qui règle aussi l'interop.

Le bon découpage est en trois couches indépendantes qui dégradent gracieusement :

| Couche | Support | Survit à | Casse sur | Rôle |
|---|---|---|---|---|
| **L1 — Métadonnées signées** (C2PA / manifeste dans XMP/EXIF) | conteneur du fichier | copie, transfert, upload | screenshot, strip metadata, ré-encodage | provenance riche et vérifiable, cas nominal |
| **L2 — Watermark invisible robuste** (spectre étalé / DCT-DWT, style Trustmark/SynthID) | pixels | recompression, resize, crop partiel, screenshot | crop massif, régénération, forte dégradation | identifiant opaque 64–128 bits, cas hostile |
| **L3 — Empreinte perceptuelle** (pHash / dHash indexé côté serveur) | aucune modif de l'image | recompression, resize, crop ≤ 25 %, screenshot, niveaux de gris, et leur cumul (mesuré) | **miroir, rotation**, transformation sémantique lourde | rattrapage « d'où vient cette image ? » sans rien avoir écrit dedans |

> Les colonnes de L3 sont **mesurées**, pas estimées (voir « Robustesse de L3 mesurée »
> plus bas). Celles de L1 et L2 restent des attentes issues de la littérature : L1 est
> évidente (métadonnées présentes ou absentes), L2 devra être mesurée de la même façon
> avant d'être promise à quiconque.

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

## État de l'art (recherche, 2026-08)

### Ce qui existe déjà en Rust, vérifié sur crates.io

| Besoin | Crate | Verdict |
|---|---|---|
| L1 C2PA | `c2pa` 0.90.4, MIT/Apache-2.0 | **Mesuré, et c'est un problème** : voir ci-dessous. `--no-default-features --features rust_native_crypto,file_io` élimine bien OpenSSL et les 4 clients HTTP, mais **coûte +7,0 MB** de binaire strippé+LTO. |
| L2 watermark | `trustmark` 0.2.2 (Adobe, MIT) | **Sidecar.** Tire `ort` (ONNX Runtime) + `ndarray` + `image` + des modèles ONNX téléchargés séparément. Incompatible avec `FROM scratch`. |
| L3 fingerprint | `img_hash` 3.2.0 (pHash/dHash) | **À utiliser**, 51 deps transitives, pur Rust. |

### Mesures réelles (pas des estimations)

Crate jetable, profil release identique à celui de Grob (`lto = true`,
`codegen-units = 1`, `strip = true`, `opt-level = 3`), macOS aarch64 :

| Binaire | Taille | Delta |
|---|---|---|
| hello world | 296 KB | référence |
| + `c2pa` (no-default-features, `rust_native_crypto`, `file_io`) | **7,33 MB** | +7,0 MB |
| + `trustmark` 0.2.2 | **12,24 MB** | **+11,9 MB** |

Soit +7,0 MB pour C2PA et +11,9 MB pour TrustMark, sur une image de conteneur Grob qui
pèse ~6 MB aujourd'hui. **TrustMark seul multiplie la taille par plus de trois**, et
l'arbre (162 crates) contient `ort`/`ort-sys` (ONNX Runtime), `ndarray`, `image` et
`fast_image_resize`, sans compter les modèles ONNX qui se téléchargent séparément.

Côté C2PA, `cargo tree` ne contient **aucun** `reqwest`, `openssl`, `ureq`, `wasi` ni
`wstd` avec ces features, mais l'arbre monte quand même à **240 crates uniques**
(CBOR, COSE, X.509, `rasn-cms`, `iref`…).

**Conclusion qui change le plan** : ni C2PA ni TrustMark ne peuvent être des features
qu'on active tranquillement. Les activer toutes les deux ferait passer le binaire de
6 MB à ~25 MB. Deux options, à trancher dans l'ADR :

1. **Feature opt-in assumée** (`media-c2pa`), en documentant noir sur blanc le coût, avec
   une image de conteneur séparée `grob:media`. Le binaire par défaut reste à 6 MB.
2. **Sidecar**, pour C2PA comme pour TrustMark, qui signent et vérifient hors du
   processus. Le cœur ne connaît que `trace_id` et pHash, tous deux légers.

L'option 2 est la seule tenable pour TrustMark, et cohérente pour C2PA : elle rend le
noyau indifférent au format de provenance et mutualise le protocole sidecar avec l'OCR.
L'option 1 reste utile pour C2PA seul, si quelqu'un veut un binaire unique sans
orchestration.

Détail d'API relevé en testant : `c2pa::Reader::from_file` exige la feature `file_io`,
absente des defaults. À savoir avant de perdre du temps dessus.

### Robustesse de L3 mesurée (le contrat, pas une promesse)

`img_hash` 3.2.0, `HashAlg::Gradient`, hash 64 bits, image synthétique 800×600 de type
capture d'écran. Distance de Hamming entre l'original et sa version transformée :

| Transformation | Distance /64 |
|---|---|
| JPEG q=90 / 70 / 50 | 1 / 1 / 1 |
| JPEG q=30 | 3 |
| Resize 75 % / 50 % / 25 % | 1 / 1 / 1 |
| Crop 5 % / 10 % / 25 % | 1 / 3 / 5 |
| « Screenshot » (resize + luminosité + JPEG 80) | 1 |
| Niveaux de gris | 0 |
| Resize 50 % + luminosité + JPEG 60 (cumulé) | 0 |
| Crop 20 % + JPEG 60 (cumulé) | 3 |
| **Miroir horizontal** | **21** |
| **Rotation 90°** | **52** |

- Pire cas sur les transformations supportées : **5**.
- Image la plus proche parmi 10 images réellement différentes : **18**.
- **Marge de séparation : 13.** Un seuil à 10 sépare proprement, avec de la marge des
  deux côtés. C'est ce seuil qui doit être codé en dur et testé, pas deviné.

Deux enseignements qui vont dans le README du module :

1. L3 est **remarquablement robuste** au cas nominal, y compris aux transformations
   cumulées, qui sont le cas réel. C'est la couche la moins chère et elle porte
   beaucoup plus que je ne le supposais.
2. L3 **ne résiste ni au miroir ni à la rotation** (21 et 52, au-delà du seuil). C'est
   une limite structurelle du hash par gradient, pas un réglage. Si quelqu'un retourne
   l'image, seuls L1 et L2 répondent. À écrire dans la doc, sinon on promet une
   traçabilité qu'on n'a pas.

Méthode : le premier corpus de test que j'avais écrit donnait une séparation nulle, non
pas à cause de pHash mais parce que mes images « différentes » se ressemblaient toutes
(distance 1). Un corpus non discriminant produit une conclusion fausse. Le test définitif
vérifie donc explicitement la séparation avant de conclure quoi que ce soit sur la
robustesse.

TrustMark (Adobe/Univ. Surrey, ICCV 2025, `arXiv:2311.18297`) est l'état de l'art ouvert :
résolution arbitraire, qualité > 43 dB, implémentations Python/Rust/JS via ONNX.
SynthID-Image (DeepMind, `arXiv:2510.09263`) est le pendant fermé, déployé à l'échelle
d'internet, non utilisable ici.

**Conséquence sur le design** : écrire notre propre DWT-DCT était une mauvaise idée.
On garde une implémentation triviale en fallback pur-Rust si vraiment nécessaire, mais
le chemin principal est TrustMark en sidecar via l'ABI `MediaMarker`. Le trait était donc
la bonne abstraction : il absorbe le changement sans toucher au pipeline.

À noter aussi `invisimark` (DWT-DCT-SIFT, QR invisible, testé survivant aux pipelines
Instagram/Facebook) : c'est exactement la variante « QR mais invisible », qui confirme
que le QR a du sens **encodé dans le domaine fréquentiel**, pas peint dans le coin.

### Sur la prompt injection multimodale

OWASP LLM01:2025 la liste explicitement (« Scenario #7: Multimodal Injection ») et écrit
noir sur blanc que *les injections n'ont pas besoin d'être lisibles par un humain, du
moment que le modèle les parse*. Le document conclut que les défenses multimodales
spécifiques sont un domaine de recherche ouvert. Deux mitigations OWASP s'appliquent
directement à notre design et sont déjà des primitives Grob :

- « Segregate and identify external content » → marquer les images entrantes comme non
  fiables, ce que `tool_layer` peut faire.
- « Require human approval for high-risk actions » → `policies/hit` existe déjà.

Autrement dit : on ne prétend pas détecter toutes les injections image. On fait de
l'OCR→DLP (bon marché, attrape le cas naïf), on **marque la provenance** et on branche
le HIT. C'est la posture honnête.

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
- `mark/` — `c2pa.rs` (L1, client sidecar de provenance par défaut, crate `c2pa` en
  option `media-c2pa` à +7 MB), `soft_binding.rs` (L2, sidecar TrustMark conforme à la
  C2PA Soft Binding Algorithm List), `qr.rs` (L3-visible, opt-in).
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

Le découpage détaillé en PRs vit dans [`002-media-agents-delivery-plan.md`](002-media-agents-delivery-plan.md).
En résumé :

1. **Squelette.** `src/features/media/`, feature flag, `MediaRef` depuis `ImageSource`,
   decode + bornes, `phash.rs`, registry JSONL, events tap. Observation seule.
2. **Sidecar.** Protocole unique et versionné, partagé par OCR, C2PA et TrustMark.
   Remonté tôt car la mesure de taille de binaire rend le hors-processus obligatoire.
3. **Verdicts.** heuristics + stego + OCR→DLP en mode `async`, puis `blocking` et
   politique par policy (`src/features/policies/`).
4. **Provenance.** L1 + registry `trace_id`, RPC `media/*`, endpoint HTTP, CLI.
5. **Watermark.** L2 + QR opt-in, lib JS, tests de robustesse
   (recompression/resize/crop/screenshot) en harness.
6. **Vidéo.** L1 conteneur + keyframes L3 via sidecar.

Chaque slice = une ADR courte + un `README.md` de module, conforme au flow du repo.

---

## Partie 2 — Control plane d'agents

### État actuel

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

### Le gap

Aujourd'hui une requête a un tenant, une policy, un budget. Elle n'a pas d'**agent
identifié et durable**. Conséquences :

- Pas de budget par agent, seulement global/provider/model.
- Pas d'arbre de filiation : un subagent (`GROB-SUBAGENT-MODEL`) n'est pas rattaché à son
  parent, donc pas de budget hérité ni de kill récursif.
- Pas de cycle de vie : impossible de suspendre, reprendre, tuer un agent en cours.
- L'audit est par requête, pas par trajectoire d'agent.
- Aucune boucle de rappel : rien ne relie « cette image a fuité » à « quel agent l'a produite ».
  C'est précisément le `trace_id` de la partie 1 qui referme cette boucle.

### Ce que dit le marché (recherche, 2026-08)

Le terme « agent control plane » s'est stabilisé en 2025-2026 et converge, chez tous les
acteurs (Microsoft Agent 365 / Entra Agent ID, Okta, Guild, Nagarro, Lyzr), sur la même
thèse : **la gouvernance d'agents est un problème de plan d'identité, pas d'admin d'accès.**
Les briques citées systématiquement :

1. **Une identité dédiée par agent**, pas une clé API partagée ni l'identité de l'humain.
2. **Credentials scopés** et éphémères.
3. **Registre** d'agents, avec propriétaire et cycle de vie déclaré.
4. **Piste d'audit attribuable** par action.
5. **Révocation / décommissionnement** automatique quand l'agent échoue son évaluation.
6. Alignement NIST AI RMF / EU AI Act.

Deux points intéressants pour Grob :

- Le problème n°1 identifié est l'**agent sprawl** : personne ne sait combien d'agents
  tournent ni ce qu'ils touchent. Grob voit déjà *tout le trafic modèle*. Il est
  structurellement le mieux placé pour tenir le registre, sans instrumenter les agents.
- Les offres du marché sont des plans de contrôle *SaaS d'entreprise* (Entra, Okta).
  Grob occupe un créneau différent : un plan de contrôle **local, self-hosted, 6 MB**,
  qui donne 80 % du résultat sans annuaire d'entreprise. C'est un vrai différenciateur.

Côté standard, MCP 2025-06-18 (`basic/authorization`) donne des fondations réutilisables
telles quelles, et évite d'inventer un schéma maison :

- OAuth 2.1 + PKCE obligatoire, Dynamic Client Registration (RFC 7591).
- **Resource Indicators (RFC 8707)** : le token est lié à sa ressource cible.
- **Protected Resource Metadata (RFC 9728)** + `WWW-Authenticate` sur 401.
- **Interdiction du token passthrough**, explicitement pour éviter le *confused deputy*.

Ce dernier point est directement une règle de conception pour Grob : un agent enfant ne
doit **jamais** recevoir le token de son parent. Il reçoit un token dérivé, d'audience
restreinte. Ça rejoint exactement la contrainte « les capacités décroissent
monotonement » déjà posée, mais avec un mécanisme normé pour l'appliquer.

### Direction proposée

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

### Ce que ça débloque

- Kill switch réel : un agent qui déraille est coupé, descendance comprise.
- Attribution du coût par agent, pas par clé API.
- Post-mortem : d'une image marquée → `trace_id` → agent → trajectoire complète.
- Sandbox alignée : `orca.yaml` isole déjà au niveau réseau ; `AgentId` donne le pendant
  logique côté proxy.

### Risques

- **Scope creep vers l'orchestrateur.** Grob doit rester un *control plane*, pas un
  runtime d'agents. Il n'exécute pas, il autorise, borne, observe et coupe.
  Frontière à écrire noir sur blanc dans l'ADR.
- **Identité usurpable.** `x-grob-agent-id` en clair est déclaratif. Il faut le lier à
  la clé API / decision token (`policies/decision_token` existe déjà).
- **État persistant.** Le control plane actuel est stateless ; les agents introduisent
  du cycle de vie. À contenir dans `GrobStore`, sans base de données.

### Open Questions

**Tranchées par la recherche et la mesure :**

- ~~C2PA en Rust, acceptable ?~~ Le crate existe et compile sans OpenSSL, mais il coûte
  **+7,0 MB mesurés** (binaire 296 KB → 7,33 MB, profil release de Grob). Donc : sidecar
  par défaut, feature in-process `media-c2pa` en option documentée.
- ~~Watermark maison ou dépendance ?~~ Ni l'un ni l'autre en direct : TrustMark en
  **sidecar** (ONNX incompatible avec `FROM scratch`), derrière le trait `MediaMarker`.
- ~~Le sidecar : un protocole ou trois intégrations ?~~ **Un seul**, versionné, posé en
  PR 2. La mesure C2PA a tranché la question : trois couches sur quatre sont hors
  processus, donc c'est une fondation, pas un détail.
- ~~Faut-il inventer un schéma d'identité d'agent ?~~ Non : OAuth 2.1 + RFC 8707
  (resource indicators) + RFC 9728, comme MCP 2025-06-18. Et interdiction stricte du
  token passthrough parent → enfant.

**Encore ouvertes :**

- L'OCR : moteur du sidecar (Vision sur macOS, autre chose ailleurs) ? Le protocole rend
  la question locale, mais il faut un défaut recommandé. Ne **pas** utiliser l'API vision
  du provider : envoyer l'image suspecte au provider contredit l'objectif.
- Les agents : produit Admin/Enterprise (cf. ADR-0028 open-core boundary) ou cœur Apache ?
  Le marché monétise exactement cette couche, donc la question est commerciale.
- `agent_id` obligatoire à terme, avec un agent implicite par défaut ?
- Faut-il viser une conformité déclarée NIST AI RMF / EU AI Act, ou juste fournir les
  primitives et laisser l'utilisateur mapper ?
- Distribue-t-on des sidecars officiels (images conteneur), ou seulement un protocole
  et une implémentation de référence ?
