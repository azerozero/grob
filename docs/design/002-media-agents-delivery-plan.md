# Plan d'exécution : media DLP/provenance + control plane d'agents

> Compagnon opérationnel de [`001-image-dlp-provenance.md`](001-image-dlp-provenance.md).
> Ce document ne rejustifie rien : il découpe le travail en PRs livrables, chacune
> mergeable seule, avec fichiers, tests et critères d'acceptation.

## Principes de découpage

- **Une PR = une valeur observable.** Pas de PR « infrastructure seule » qui n'apporte
  rien de vérifiable.
- **Off par défaut jusqu'au bout.** `media` et `agents` restent hors du `default` de
  `Cargo.toml` tant que la surface n'est pas stabilisée. Zéro impact sur le binaire
  existant, zéro régression possible sur le chemin chaud.
- **Observer avant de bloquer.** Toute capacité arrive d'abord en mode lecture seule
  (journal + events), puis en mode verdict. On ne coupe jamais du trafic sur du code
  qui n'a pas d'abord tourné à vide en production.
- **Charte de slice à chaque nouveau module** (`README.md` + entrée dans
  `docs/slices/MANIFEST.md`), conformément à la convention du repo.
- Conventional commits, branche `feat/*`, auto-merge activé, une ADR quand une décision
  est structurante.

## Vue d'ensemble

| # | PR | Feature flag | Bloque le trafic ? | État |
|---|---|---|---|---|
| 1 | Squelette `media` : décodage borné + pHash + journal | `media` | non | ✅ **livré** (#501) |
| 2 | **Protocole sidecar** (fondation partagée) | `media` | non | ✅ **livré** |
| 3 | Détecteurs bon marché (heuristiques, stégano) | `media` | non | ✅ **livré** (#504, #505) |
| 3b | Point d'entrée async depuis le chemin requête | `media` | non | ✅ **livré** (#518) |
| 4 | OCR → DLP via sidecar | `media` | non | ✅ **livré** (#521) |
| 5 | Mode `blocking` + intégration policies | `media` | oui | à faire |
| 6 | Provenance L1 (C2PA) + registre `trace_id` | sidecar, ou `media-c2pa` | non | à faire |
| 7 | Surfaces : RPC `media/*`, HTTP verify, CLI | `media` | non | à faire |
| 8 | Watermark L2 via sidecar TrustMark | `media` | non | à faire |
| 9 | Lib JS `grob-media-verify` | — | non | à faire |
| 10 | Vidéo : L1 conteneur + keyframes L3 | `media` | non | à faire |
| A1 | `AgentId` + contexte propagé + attribution du spend | `agents` | non | à faire |
| A2 | Registre d'agents + leases | `agents` | oui (expiration) | à faire |
| A3 | Budget et capacités hiérarchiques | `agents` | oui | ⚠️ prérequis livré (#500) |
| A4 | Surfaces `agent/*` + trajectoire auditée | `agents` | non | à faire |
| A5 | Jonction media ↔ agent (`trace_id` → agent) | les deux | non | à faire |

> **Révision après mesure.** Le sidecar est passé de la PR 4 à la PR 2, et C2PA de la
> PR 5 à la PR 6, derrière le sidecar. Raison : `c2pa` compilé en dur coûte **+7,0 MB**
> sur un binaire qui en fait 6 (mesure dans le design doc). Trois des couches lourdes
> (OCR, C2PA, TrustMark) sont donc hors processus, ce qui fait du protocole sidecar la
> fondation et non un détail d'implémentation. Le noyau ne manipule que `trace_id` et
> pHash, tous deux légers.

Les deux pistes sont indépendantes jusqu'à A5. Elles peuvent avancer en parallèle.

---

## Piste média

### PR 1 — Squelette `media` : décoder sans se faire tuer, empreinter, journaliser

> **✅ Livré (#501).** Charte : [`src/features/media/README.md`](../../src/features/media/README.md).
> Une correction issue de l'implémentation : le hash est écrit à la main plutôt qu'importé
> d'`img_hash` (≈50 crates transitives et un `image` 0.23 épinglé pour une soixantaine de
> lignes d'arithmétique), et sa séparation mesurée est **7 / 16** au lieu des 5 / 18 de la
> sonde de référence. Le seuil de 10 tient toujours, avec moins de marge : les deux bords
> du gap sont assertés en test pour que l'érosion échoue en CI. Critères d'acceptation
> vérifiés : **zéro dépendance ajoutée** (429 crates avec ou sans la feature) et binaire
> par défaut **inchangé à 17,293 MB**.

**Pourquoi en premier** : le décodage borné est la seule partie où une erreur est fatale
(DoS). On la pose seule, on la teste à fond, et tout le reste s'appuie dessus.

**Fichiers**

```
src/features/media/mod.rs          MediaRef, MediaBuf, MediaError, MediaConfig
src/features/media/decode.rs       sniff magic bytes, bornes pré-décodage
src/features/media/phash.rs        empreinte perceptuelle (img_hash)
src/features/media/registry.rs     journal ~/.grob/media/YYYY-MM.jsonl
src/features/media/README.md       charte de slice
src/traits.rs                      + MediaScanner, MediaMarker
Cargo.toml                         feature `media` (hors default), img_hash optionnel
docs/slices/MANIFEST.md            + ligne media
docs/decisions/0030-media-pipeline.md
```

**Points de conception à ne pas rater**

- `MediaRef::from_image_source(&ImageSource)` emprunte sans copier pour le base64 inline.
  Pour `type = "url"`, retourne `MediaRef::Remote` **sans fetch** : la décision de
  télécharger n'appartient pas à cette couche.
- Les bornes (`max_bytes`, `max_pixels`, `allowed_formats`) sont vérifiées **avant**
  toute allocation de buffer de pixels. C'est tout l'intérêt : refuser un PNG de
  10 px annonçant 50 000 × 50 000 sans jamais l'ouvrir.
- Allow-list de formats, jamais de deny-list.

**Tests** — `tests/unit/media_test.rs`

- Une decompression bomb (petit fichier, dimensions énormes) est rejetée sans allocation.
- Chaque format non listé est refusé, y compris avec une extension mensongère.
- **pHash : la matrice de robustesse est déjà mesurée** (voir le design doc). Elle se
  transpose directement en test, avec les valeurs constatées comme bornes :

  | Cas | Distance mesurée | Assertion |
  |---|---|---|
  | JPEG q ≥ 30 | ≤ 3 | `dist <= 5` |
  | Resize 25–75 % | 1 | `dist <= 5` |
  | Crop ≤ 25 % | ≤ 5 | `dist <= 5` |
  | Cumul resize + luminosité + JPEG 60 | 0 | `dist <= 5` |
  | Images différentes (10 échantillons) | ≥ 18 | `dist > 10` |
  | Miroir / rotation | 21 / 52 | **non supporté**, test qui documente la limite |

  Le seuil de correspondance est **10**, choisi au milieu de la marge mesurée (5 → 18).
  Il est codé en constante nommée, pas dispersé en littéral.
- Le journal est append-only et relisible après troncature partielle (crash simulé).

**Banc d'essai** : [`assets/phash_robustness_probe.rs`](assets/phash_robustness_probe.rs) (versionné dans le repo) est le programme exact qui a produit ces
chiffres, pour qu'une mise à jour d'`img_hash` ou un changement d'algorithme se voie
immédiatement au lieu de dériver en silence.

**Acceptation** : sans `--features media`, `cargo tree` ne contient aucune des nouvelles
dépendances et la taille du binaire release ne bouge pas de plus de 1 % par rapport à
`main` (référence mesurée aujourd'hui : **17,3 MB** en release macOS aarch64 ; l'image
conteneur musl `FROM scratch` reste sur sa propre référence de ~6 MB). Un critère
« binaire identique à l'octet près » serait ininspectable en pratique, à cause des
identifiants de build et des chemins ; la garde utile est l'absence de dépendance et la
stabilité de la taille. Avec la feature, on peut empreinter une image et la retrouver
dans le journal.

---

### PR 2 — Protocole sidecar (la fondation)

> **Livré.** Deux questions de l'utilisateur ont tranché la conception :
> *stateless ou pas ?* et *il faut fonctionner hors macOS*.
>
> **Stateless, et garanti par le type** : `SidecarRequest` ne porte ni tenant,
> ni session, ni policy, ni trace_id, et un test verifie que la serialisation
> n'expose aucun champ de ce genre. Un sidecar ne peut donc pas correler les
> appels meme s'il le voulait.
>
> **Hors macOS, mesure** : `ocrs` (Rust pur, ~12 MB de modeles, CPU, zero
> dependance systeme) donne le meme score DLP que Vision, 3 secrets sur 4, avec
> des modes d'echec differents. Vision perd un caractere dans le litteral
> Stripe, `ocrs` perd les underscores.
>
> `deepseek-ocr.rs` (Apache-2.0, serveur compatible OpenAI) a ete evalue :
> excellent en haute fidelite, mais 4,7 a 9 GB de poids et 9 a 50 GB de RAM,
> donc troisieme niveau optionnel et non defaut. Son serveur OpenAI se branche
> derriere ce protocole via un adaptateur HTTP mince, ce qui valide au passage
> le choix d'avoir pose un protocole plutot que trois integrations.
>
> Interop Rust vers Python verifiee contre une implementation de reference de
> ~120 lignes : un protocole n'existe qu'une fois qu'une seconde implementation
> independante le parle. Mutation testing : 0 survivant du premier coup.

**Pourquoi si tôt** : la mesure de taille de binaire (+7 MB pour C2PA seul) rend le
hors-processus obligatoire pour trois couches sur quatre. Ce n'est donc plus un détail
d'intégration mais l'ossature de toute la piste média. Le poser une fois, proprement,
évite trois intégrations divergentes.

**Fichiers**

```
src/features/media/sidecar/mod.rs      trait MediaSidecar, découverte, santé
src/features/media/sidecar/proto.rs    contrat requête/réponse versionné
src/features/media/sidecar/client.rs   HTTP sur unix socket, timeouts, circuit breaker
docs/decisions/0031-media-sidecar.md
```

**Points de conception**

- **Un seul protocole** pour OCR, C2PA et TrustMark. C'était une question ouverte du
  design doc ; elle est tranchée ici.
- Unix socket par défaut, jamais de port TCP exposé : le sidecar reçoit des images
  potentiellement sensibles, il ne doit pas être joignable depuis le réseau.
- **Absence de sidecar = capacité désactivée proprement**, jamais une erreur de
  démarrage. Grob doit démarrer et servir même si tout l'appareillage média est absent.
- Réutiliser le circuit breaker existant (`src/routing/`) plutôt que d'en écrire un
  deuxième : un sidecar en vrac se comporte exactement comme un provider en vrac.
- Le protocole est versionné dès le premier jour, sinon on ne pourra jamais le faire
  évoluer sans casser les déploiements.

**Tests** : sidecar absent → dégradation silencieuse et démarrage normal ; sidecar lent
→ timeout respecté ; sidecar qui plante en boucle → circuit ouvert, plus d'appels ;
version de protocole incompatible → refus explicite et lisible.

**Acceptation** : un sidecar factice qui renvoie une réponse fixe est appelé par Grob,
et son absence ne change rien au comportement du proxy.

---

### PR 3 — Détecteurs bon marché + branchement asynchrone

> **✅ Détecteurs livrés (#504), durcis (#505).** Le wiring dispatch/watch est sorti de
> cette PR (devenu 3b) : il dépend d'un plumbing de config qui n'existe pas encore, et
> le mélanger à la couche de détection aurait fait une PR non testable isolément.
>
> Leçon de #505, qui vaut au-delà de ce slice : le job de mutation testing de la CI est
> passé au vert sur #504, mais un `cargo-mutants` local sur `scan/` a trouvé **20 mutants
> survivants**. Les tests vérifiaient que les findings se déclenchaient, jamais que
> l'arithmétique d'offsets qui les produit était juste. Corrigé à **0 survivant**. À
> retenir pour les PRs suivantes : sur du parsing d'offsets, tester le résultat ne teste
> rien ; il faut épingler l'arithmétique.

**Fichiers**

```
src/features/media/scan/mod.rs          MediaVerdict, orchestration
src/features/media/scan/heuristics.rs   taille, ratio, entropie, EXIF/GPS
src/features/media/scan/stego.rs        LSB, données après marqueur de fin
src/server/dispatch/mod.rs              hook async, aucun await bloquant
src/features/watch/events.rs            media.scanned
src/features/tap/mod.rs                 idem
```

**Points de conception**

- Le hook `async` détache une tâche et **ne renvoie rien au pipeline**. Aucun `.await`
  ajouté sur le chemin de la requête. C'est vérifiable au type : la fonction retourne `()`.
- Une image porteuse de GPS qui part vers un provider est un signal en soi, même sans
  secret détecté. C'est le détecteur le moins cher et l'un des plus parlants.
- La détection de stégano vise le cas grossier (LSB uniforme, appended payload). On ne
  prétend pas battre un stéganographe motivé, et le README doit le dire.

**Tests** — corpus d'images fixtures : propre, LSB modifié, payload appendu, EXIF GPS.
Test de non-régression latence : p99 inchangé avec `mode = "async"` sur 1000 requêtes
portant une image.

**Acceptation** : `grob watch` montre les events `media.scanned` en direct pendant qu'un
agent envoie des screenshots, sans une milliseconde de latence ajoutée.

---

### PR 4 — OCR → DLP (via le sidecar de la PR 2)

> **Livré (#521), et le resultat depasse la mesure initiale.** La normalisation
> anti-confusion fait passer les DEUX moteurs de 3 secrets sur 4 a **4 sur 4**.
> Le choix du moteur reste donc une preference de deploiement au lieu de fuir
> dans les proprietes de securite, ce que le protocole sidecar promettait.
>
> Un piege trouve a l'implementation : les reparations doivent **composer**, pas
> seulement coexister. `ocrs` rend `sk_live_` en `sk Live_`, soit un underscore
> perdu ET une erreur de casse dans le meme litteral ; reparer l'un sans l'autre
> laisse la regle muette. Il a fallu un second essai, desormais epingle par un
> test.

**Pourquoi c'est la PR la plus rentable, et c'est maintenant mesuré** : elle transforme
l'image en texte et rend *toutes* les règles DLP existantes applicables. Zéro duplication
de règles. Test bout en bout déjà fait (screenshot → OCR Vision → vrai `DlpEngine`) :
**3 secrets sur 4 détectés sur de la sortie OCR brute, sans une seule règle nouvelle.**
Détail et sondes dans le design doc.

**Fichiers**

```
src/features/media/scan/text.rs      appel sidecar OCR + réinjection DlpEngine
src/features/media/scan/normalize.rs normalisation anti-confusion OCR (voir ci-dessous)
```

**Points de conception**

- Le texte OCR passe par le `DlpEngine` **existant**, sans nouvelle règle. Si le DLP
  détecte une clé AWS dans un screenshot, c'est le même code que pour le texte.
- **Normalisation avant scan, et seulement sur le chemin image.** La mesure montre qu'une
  unique erreur de caractère fait échouer une règle, et que les motifs à long préfixe
  littéral (`sk_live_`, `ghp_`) sont les plus fragiles alors que les classes de
  caractères larges (`AKIA[0-9A-Z]{16}`) encaissent. D'où : préfixes insensibles à la
  casse, et repli des confusions visuelles (`×`→`x`, `0`/`O`, `1`/`l`/`I`, `,`/`.`).
  Bon marché, et ciblé sur le mode d'échec réellement observé.
- Cette tolérance ne doit **jamais** s'appliquer au chemin texte : elle y créerait des
  faux positifs pour tout le monde. C'est une propriété du scan d'image, pas du moteur.
- Le résultat OCR n'est **jamais** journalisé en clair : seuls les identifiants de règles
  déclenchées le sont. La sortie OCR contient les secrets, c'est tout l'intérêt.
- Sur macOS, un sidecar s'appuyant sur Vision est trivial à écrire (voir
  [`assets/ocr_probe.swift`](assets/ocr_probe.swift), une trentaine de lignes) ; ailleurs,
  n'importe quel moteur respectant le protocole convient.

**Tests** : le corpus de la mesure devient un test de non-régression, avec le taux de
détection comme assertion (≥ 3/4 sur la sortie OCR de référence, 4/4 après
normalisation). Vérifier aussi que le texte OCR n'apparaît nulle part dans le journal.

---

### PR 5 — Mode bloquant + policies

**Fichiers**

```
src/features/media/config.rs        mode = off|async|blocking, timeout_ms, on_timeout
src/features/policies/resolved.rs   + override media par policy
src/server/dispatch/mod.rs          chemin bloquant
```

**Points de conception**

- `on_timeout = "allow" | "deny"` doit être **explicite dans la config**, sans défaut
  implicite. C'est le genre de choix qu'on ne devine pas à la place de l'opérateur.
- Le verdict réutilise la sémantique DLP (`Allow | Redact | Warn | Block`) pour que les
  opérateurs n'aient pas deux modèles mentaux.
- `Redact` sur une image signifie la remplacer par un placeholder, pas la flouter.
  Le proxy n'édite pas de pixels.

**Tests** : une image piégée est bloquée en `blocking`, passe en `async`, et le timeout
respecte `on_timeout` dans les deux sens.

---

### PR 6 — Provenance L1 (C2PA) + registre

**Fichiers**

```
src/features/media/mark/mod.rs       MediaMarker
src/features/media/mark/c2pa.rs      client sidecar de provenance (défaut)
src/features/media/trace.rs          TraceId (61 bits CSPRNG, capacité TrustMark Bch5)
src/features/media/registry.rs       trace_id → contexte
Cargo.toml                           feature media-c2pa (in-process, opt-in, +7 MB)
docs/decisions/0032-content-provenance.md
```

**Points de conception**

- **Chemin par défaut : sidecar.** Mesure faite : `c2pa` compilé en dur ajoute
  **+7,0 MB** à un binaire qui en fait 6, même en `--no-default-features` avec
  `rust_native_crypto` (240 crates transitives : CBOR, COSE, X.509). Doubler la taille
  de l'image pour signer des métadonnées n'est pas un arbitrage défendable par défaut.
- La feature `media-c2pa` reste disponible pour un binaire unique sans orchestration,
  avec le coût **écrit dans la doc**, pas découvert par l'utilisateur.
- À savoir avant de commencer : `c2pa::Reader::from_file` exige la feature `file_io`,
  absente des defaults. Les features utiles vérifiées sont
  `--no-default-features --features rust_native_crypto,file_io` : cet ensemble élimine
  bien `reqwest`, `openssl`, `ureq`, `wasi` et `wstd` de l'arbre (vérifié à `cargo tree`).
- Le manifeste contient `trace_id` et **rien d'autre** d'identifiant. Pas de tenant, pas
  de nom de modèle, pas de session. La tentation sera forte, il faut la refuser : tout ce
  qu'on écrit dans l'image devient public.

**Tests** : round-trip signer → lire ; manifeste strippé → `trace_id` toujours résolvable
via pHash ; aucune donnée métier dans le fichier de sortie (test explicite qui cherche le
nom du tenant dans les octets bruts) ; et un test de garde qui échoue si la taille du
binaire par défaut dépasse un seuil.

---

### PR 7 — Surfaces d'exposition

**Fichiers**

```
src/control/engine.rs               + Action::Media, MediaAction
src/server/rpc/media_ns.rs          media/verify, media/trace, media/policy
src/server/endpoints.rs             POST /v1/media/verify
src/commands/media.rs               grob media verify|trace
```

**Points de conception**

- RBAC : `verify` en Observer (répond « cette image vient de chez vous »), `trace` en
  Operator (révèle tenant et session). La distinction est le cœur du modèle de fuite.
- Le bridge MCP est automatique via `control_bridge.rs`, donc un agent peut demander
  « d'où vient cette image ? » sans code supplémentaire. C'est le bénéfice du
  `ControlEngine` existant.
- La réponse expose **quelle couche** a matché (`c2pa` signé, `watermark`, `phash`,
  `none`) et non un booléen. La confiance doit être lisible.

---

### PR 8 — Watermark L2 (sidecar TrustMark)

**Fichiers** : `src/features/media/mark/soft_binding.rs`, plus le sidecar de la PR 2.

**Le sidecar n'est pas discutable ici** : mesuré, `trustmark` 0.2.2 ajoute **+11,9 MB**
au binaire (296 KB → 12,24 MB), soit plus de trois fois la taille de l'image Grob
actuelle, sans compter les modèles ONNX téléchargés séparément. `ort`/`ort-sys`,
`ndarray` et `fast_image_resize` n'ont rien à faire dans un binaire `FROM scratch`.

**Tests de robustesse** : **déjà mesurés**, contrairement à ce que ce plan disait
initialement. Les modèles ONNX sont publics et la matrice complète est dans le design
doc, avec la sonde reproductible
[`assets/l2_watermark_robustness_probe.rs`](assets/l2_watermark_robustness_probe.rs).
Cette PR se contente donc de **transposer la matrice en tests** et de vérifier qu'elle
ne régresse pas avec la version des modèles.

Ce que la mesure impose au code de cette PR :

- **Vérifier l'extraction juste après l'écriture.** Le marquage n'est pas garanti sur
  toute porteuse : une image synthétique 512×512 échoue au round-trip propre là où la
  même en 256×256 réussit. Écrire sans relire, c'est promettre une traçabilité absente.
- **Journaliser l'échec de marquage** comme un événement de premier ordre, pas comme une
  erreur silencieuse.
- **Ne pas promettre L2 sur les captures d'écran retouchées** : un décalage de luminosité
  de +2/255, invisible, suffit à détruire le watermark. La doc utilisateur doit le dire.
- Budget mesuré : ~50 ms d'encodage, ~30 ms de décodage par image. Confirme le sidecar et
  exclut le chemin bloquant.

**Ce que L2 apporte réellement par rapport à L3**, mesuré : le miroir horizontal, et
rien d'autre dans la matrice testée. En sens inverse L3 couvre la luminosité et le crop
25 % où L2 échoue. Les deux couches sont donc complémentaires mais **L2 est le moins
rentable des deux** rapporté à son coût (+11,9 MB, sidecar, modèles de 65 MB). Cette PR
est légitimement la dernière de la piste média.

---

### PR 9 — Lib JS `grob-media-verify`

Package séparé. Fait localement ce qui est local (parse C2PA, pHash en WASM), délègue L2
au serveur. Aucun secret côté client. Retourne toujours la couche qui a répondu.

---

### PR 10 — Vidéo

L1 sur le conteneur (boîte `uuid` MP4, tags Matroska), L3 sur keyframes échantillonnées
via sidecar ffmpeg. **Marquage par segment**, jamais par fichier : un simple découpage
ne doit pas effacer la provenance. L2 vidéo hors périmètre.

---

## Piste agents

### PR A1 — `AgentId` et propagation

**Fichiers**

```
src/features/agents/mod.rs        AgentId (ULID), AgentContext
src/features/agents/extract.rs    en-tête x-grob-agent-id + tag système
src/features/agents/README.md
src/features/token_pricing/       + dimension agent_id dans le journal spend
docs/decisions/0033-agent-identity.md
```

**Points de conception**

- L'identité est **portée, jamais devinée**. En-tête `x-grob-agent-id`, ou tag système
  sur le modèle de `GROB-SUBAGENT-MODEL` qui existe déjà. Toute heuristique
  d'auto-détection serait fragile et créerait de fausses attributions.
- La filiation est déclarée par l'appelant (`x-grob-parent-agent-id`), et **vérifiée**
  contre le registre en A2.
- Le spend gagne une dimension `agent_id`. Le format du journal doit rester
  rétrocompatible en lecture (champ optionnel), sinon on casse les journaux existants.

**Acceptation** : `grob status` sait dire combien coûte chaque agent. C'est immédiatement
utile, avant même toute notion de contrôle.

---

### PR A2 — Registre et leases

**Fichiers** : `src/features/agents/registry.rs`, `lease.rs`, journal
`~/.grob/agents/*.jsonl`.

**Points de conception**

- **Réutiliser `expires_at` des decision tokens**, qui existe déjà et est désormais
  réellement vérifié (voir A3). Un second système de TTL parallèle serait une divergence
  garantie.
- **Le lease, pas le kill.** Un agent tient un bail à TTL qu'il renouvelle. S'il ne
  renouvelle pas, il expire. C'est le seul modèle qui survit au crash du superviseur :
  un agent orphelin ne peut pas brûler du budget indéfiniment parce que personne n'est
  là pour le tuer.
- Le TTL par défaut doit être court (quelques minutes) avec renouvellement transparent.
  Un défaut long annule le bénéfice.
- L'expiration se manifeste en HTTP 403 avec un message explicite, pas un échec obscur.

**Tests** : un agent dont le bail expire est refusé ; le renouvellement le maintient ;
un parent qui expire fait expirer sa descendance.

---

### PR A3 — Budget et capacités hiérarchiques

**Ce qui existe déjà, vérifié dans le code** : `policies/decision_token` implémente
littéralement un modèle boss/worker avec `issuer`, `audience` (glob), `expires_at`,
HMAC-SHA256 sur les claims, et une séparation `DecisionToken` / `AgentVisibleToken` qui
est exactement l'anti-passthrough recherché. Le socle est donc plus avancé que ce plan
ne le supposait : A3 branche l'existant au lieu de l'inventer.

**Deux failles trouvées et corrigées en amont de cette PR** (elles auraient rendu le
modèle de sécurité décoratif) :

1. **`expires_at` n'était jamais vérifié.** Un token expiré depuis 2020 routait vers
   `BackendTarget::Real`, c'est-à-dire le backend *live*. La variante d'erreur `Expired`
   existait mais n'était construite nulle part. Corrigé : `is_expired()` /
   `check_not_expired()`, appelés depuis `resolve_backend()`, avec **fail-closed sur une
   date malformée** (une expiration illisible ne doit pas valoir validité illimitée).
2. **`audience` n'était vérifiable nulle part.** `route_by_decision_token()` ne reçoit
   aucune identité d'agent, donc la claim ne pouvait structurellement pas être appliquée.
   Ajout de `resolve_backend_for(agent_id)` et `route_by_decision_token_for()`, qui
   valident intégrité + expiration + audience ensemble. Au passage, `worker-*` ne
   matche plus le préfixe nu `worker-`, et une audience réduite à `*` ne matche plus
   rien, puisqu'une audience qui matche tout équivaut à pas d'audience.

**Points de conception restants**

- Le budget d'un enfant est **prélevé sur celui du parent**, jamais additionnel. Sinon
  un agent qui se réplique contourne trivialement toute limite.
- Les capacités (profil pledge) ne peuvent que se restreindre en descendant. Même
  propriété monotone que `Role::has_at_least`, à tester explicitement.
- **Pas de token passthrough** parent → enfant, conformément à MCP 2025-06-18 et au
  problème du *confused deputy*. L'enfant reçoit un jeton dérivé d'audience restreinte,
  et c'est désormais réellement applicable puisque l'audience est enfin vérifiée.
- Corollaire de la faille n° 1 : l'expiration des decision tokens est le **mécanisme de
  lease de la PR A2**, déjà présent dans le format. A2 n'a pas à inventer un second
  système de TTL, elle doit réutiliser celui-là.

**Tests** : un enfant ne peut pas dépasser le budget de son parent, ni élargir ses
capacités, ni réutiliser le jeton du parent. Ces trois tests sont le cœur du modèle de
sécurité. Les huit tests d'expiration et d'audience sont déjà écrits et passent.

---

### PR A4 — Surfaces et trajectoire

`agent/spawn|list|inspect|pause|resume|kill|budget|trace` via `ControlEngine`, donc
disponibles d'un coup en CLI, RPC et MCP. `kill` est **récursif** sur la descendance,
sinon il ne sert à rien.

Trajectoire auditée : journal ordonné par agent (requêtes, outils, verdicts DLP, médias
marqués). C'est ce qui rend le post-mortem possible.

---

### PR A5 — Jonction media ↔ agent

`trace_id` d'un média → agent producteur → trajectoire complète. C'est la boucle qui
donne son sens aux deux pistes : d'une image trouvée dans la nature, on remonte à
l'agent, à sa session, à sa policy et à son propriétaire.

---

## Ce qu'on ne fait pas

Écrit ici pour éviter la dérive, puisque c'est la section qui coûte le plus cher quand
elle manque :

- Grob **n'exécute pas** d'agents. Il autorise, borne, observe et coupe. Il n'ordonnance
  rien, il ne relance rien, il n'a pas de boucle d'agent.
- Pas de reconnaissance d'objets ou de visages.
- Pas de transcodage vidéo dans le proxy.
- Pas de prétention à un DRM inviolable : traçabilité dissuasive, pas contrôle d'usage.
- Pas de base de données. Journaux JSONL et fichiers atomiques, comme le reste.

## Ordre recommandé

1. **PR 1 → 2 → 3 → 4** d'abord. C'est le chemin le plus court vers une valeur réelle :
   les screenshots d'agents sont scannés par les règles DLP existantes.
2. **A1** en parallèle, indépendante et immédiatement utile (coût par agent).
3. **PR 5 → 6 → 7** ensuite : blocage, puis provenance interrogeable.
4. **A2 → A3** quand le besoin de contrôle se fait sentir, pas avant.
5. **PR 8 → 9 → 10**, **A4 → A5** en fonction des retours.

Le point de décision qui conditionnait toute la piste média (« l'OCR→DLP attrape-t-il
quelque chose d'utile ? ») **est déjà tranché, avant d'écrire la moindre ligne de
production** : 3 secrets sur 4 détectés sur de la sortie OCR réelle par le moteur
existant, 4 sur 4 avec la normalisation anti-confusion. La piste média est justifiée.

Il reste un vrai point de décision, mais plus loin et de nature différente : **après la
PR 7**, une fois L1 et L3 en place, se demander si L2 mérite son coût (+11,9 MB, sidecar,
65 MB de modèles) alors que la mesure montre qu'il n'apporte que le miroir horizontal par
rapport à pHash. Si la réponse est non, la piste s'arrête à la PR 7 et c'est un très bon
résultat.
