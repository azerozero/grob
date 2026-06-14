# Démo Grob — Conformité IA pour RSSI + Gouvernance des agents

Kit de démonstration **reproductible** et **sans coût d'IA** : il prouve, en
direct et en français clair, que Grob protège les données avant qu'elles
n'atteignent un fournisseur d'IA, **et** qu'il gouverne les agents IA un par un.
Destiné à un public **non technique** (RSSI, conformité, achats).

> La couche **gouvernance** (clé par agent, conso/incidents par agent, coupure
> automatique) est un **aperçu de grob-admin** (offre commerciale) — démo
> uniquement.

## Lancer

Le chemin officiel est **podman + kube play** (couche gouvernance incluse) :

```sh
cd deploy/demo
make demo          # build image outils + régénère le manifeste + podman kube play
```

> `make demo` construit deux images locales (premier lancement plus long) :
> `localhost/grob-demo:local` — grob **patché** depuis l'arbre source
> (`Containerfile`), qui classe les caviardages en `C1`/`C2` (correctif
> `feat(audit)` pas encore dans une release publiée) ; et
> `localhost/grob-demo-tools` (alpine + binaire grob) pour l'init/seed/watcher,
> car l'image grob « scratch » n'a pas de shell. Puis il régénère
> `demo.kube.yaml` (`make gen`) et lance `podman kube play`. Une fois le
> correctif publié, on pourra pinner `ghcr.io/azerozero/grob:<version>` à la
> place (cf. `gen-kube.py` / `docker-compose.yml`).

La démo **de base** (sans gouvernance) reste lançable via Compose :
`docker compose -f docker-compose.yml up -d`.

Puis ouvrir :

| Accès | URL | Pour qui |
|-------|-----|----------|
| **Gouvernance des agents** | <http://localhost:8088/governance> | décideur — le « wow » |
| **Tableau de bord RSSI** | <http://localhost:3000> | décideur (gros chiffres vert/rouge) |
| **Blocages en direct** | <http://localhost:8088> | tout public (flux temps réel) |
| API Grob | <http://localhost:8080> | démonstrateur (`curl`) |

Réinitialiser entre deux passages : `make demo-reset`.
Suivre la coupure en direct : `make demo-logs` (logs seed + watcher).

## Ce que ça montre

**Protection des données (vue RSSI / blocages en direct) :**

- 🟠 **Secrets & PII caviardés** — clé AWS, token GitHub, carte bancaire, IBAN
  masqués **avant** la sortie (la requête aboutit, expurgée).
- 🔴 **Menaces bloquées** — injection de prompt et exfiltration par URL rejetées
  **avant tout envoi** à l'IA (donc zéro fuite, zéro coût).
- 💶 **Dépense IA maîtrisée** — budget mensuel appliqué automatiquement.
- ✅ **Traçabilité signée** — règles vérifiées cryptographiquement.

**Gouvernance des identités (vue `/governance`) :**

- 🔑 **Une clé par identité** — 4 identités, chacune sa clé virtuelle et son
  tenant, en distinguant **humains** et **agents de service**, chacune avec un
  **profil d'incident distinct** :
  - 👤 **alice** — humaine, RH — **baseline exemplaire : trafic 100 % propre**,
    toutes ses lignes d'audit sont classées `Nc` (✅ Propre), 0 incident.
  - 👤 **bob** — humain, Dev — majoritairement propre, **caviarde parfois** un
    secret (`C1` 🟠) ou une PII (`C2` 🟠) collé par mégarde — jamais bloqué.
  - 🤖 **dev-bot** — agent de service, owner=bob, env=dev — propre, avec **un
    caviardage de secret occasionnel** (`C1` 🟠).
  - 🤖 **compta-bot** — agent de service, owner=Finance, env=prod (l'agent qui
    *dérive lentement* : fuites caviardées `C1`/`C2` **puis** exfiltrations `C2`
    + injections `C3` **bloquées** qui s'accumulent jusqu'à la coupure).
- 📊 **Colonnes SecOps** — requêtes, conso indicative, violations, **classe de
  donnée captée** (menace / secret / financier / PII), **type d'incident**
  (classification d'audit : `Nc`/`C1`/`C2`/`C3`), **décision**
  (bloqué/caviardé), **preuve signée** et statut — tout attribué individuellement
  (source : journal d'audit signé `/audit`).
- 🏷️ **Type d'incident par classification** — le champ `classification` du
  journal d'audit (dérivé par grob, `src/server/audit.rs`) est la source de
  vérité du TYPE d'incident, affiché en clair :
  - `Nc` = **✅ Propre** (aucune action DLP) — sérialisé `NC` dans le JSON ;
  - `C1` = **🟠 Caviardé** (secret expurgé, interne) — ligne `DLP_WARN` ;
  - `C2` = **🟠 PII / restreint** (PII caviardée ou requête bloquée) ;
  - `C3` = **🔴 Attaque bloquée** (blocage DLP + injection).
  > Le correctif `feat(audit)` (embarqué dans l'image locale `grob-demo:local`)
  > émet une ligne d'audit **classée** dès qu'un **caviardage** se produit :
  > `DLP_WARN` classée `C1` (secret) ou `C2` (PII), avec les règles nommées dans
  > `dlp_rules_triggered`. Les **blocages** restent `C2` (exfiltration) / `C3`
  > (injection). Ainsi chaque identité expose de *vrais incidents typés* : alice
  > 100 % `NC`, bob/dev-bot des caviardages `C1`/`C2`, compta-bot la dérive
  > complète jusqu'à `C3`. Seuls les **blocages** comptent comme *violations*
  > (le caviardage aboutit) → le watcher ne coupe que sur les blocages.
  > Avec un binaire **antérieur** au correctif, un caviardage retombe en
  > `RESPONSE`/`Nc` et `C1` redevient invisible.
- 🔎 **Drill-down par identité** — chaque ligne a un lien **« Voir les logs »**
  qui ouvre le **tableau de bord d'investigation par agent** (Grafana,
  uid `grob-audit-agent`) pré-filtré sur `{service="grob-audit", tenant="<id>"}`
  via la variable `$tenant`. L'auditeur y voit : le **nombre d'incidents
  classifiés** (hors ✅ Propre), une **répartition par type d'incident**
  (camembert `Nc`/`C1`/`C2`/`C3` → ✅ Propre / 🟠 Caviardé / 🟠 PII-restreint /
  🔴 Attaque bloquée), la **classification dans le temps** (barres empilées qui
  révèlent la dérive lente), et le **journal signé** où chaque ligne montre en
  clair `[classification] action · règle DLP · signature`.
- ⛔ **Coupure automatique** — `compta-bot` est un *slow-burn* : trafic
  majoritairement propre, mais des tentatives bloquées qui **s'accumulent** ;
  quand ses violations dépassent le seuil (8), le *watcher* **révoque sa clé en
  direct** : sa ligne passe à **⛔ RÉVOQUÉ** et ses requêtes suivantes renvoient
  **401**, sans redémarrage.

## Comment c'est gratuit et déterministe

Le service `mock` est un backend « echo » local : Grob y renvoie tout le trafic
fournisseur (`GROB_MOCK_BACKEND`). Aucun appel LLM réel n'est émis. Le moteur DLP
de Grob s'exécutant **avant** le dispatch, les blocages (injection, exfiltration)
sont **réels** mais ne consomment rien. Le générateur de trafic (`seed`) rejoue
un scénario **fixe** : résultat identique à chaque exécution.

## Comment fonctionne la gouvernance

- **Clés virtuelles** : l'`initContainer` crée 4 clés (une par identité/tenant)
  dans un `GROB_HOME` **partagé** (chiffré AES-256-GCM) et persiste les jetons
  en clair dans `demo-agents.txt`. L'auth Grob passe en mode `api_key` : la clé
  admin passe, tout autre jeton `grob_…` est résolu comme clé virtuelle. Les
  métadonnées d'identité (humain/agent, département, owner, env) sont statiques
  et vivent dans le watcher, indexées par tenant — le store de clés n'a pas de
  champ de métadonnées libre.
- **Audit par identité** : `[security] enabled=true` + `audit_dir=/audit` fait
  écrire à Grob `/audit/current.jsonl` (une ligne signée par requête, avec
  `tenant_id`, `dlp_rules_triggered`, `action`, `classification`, `signature`).
  C'est la source de vérité des incidents. Depuis le correctif `feat(audit)`,
  un **caviardage** (`DLP_WARN`) nomme lui aussi ses règles dans
  `dlp_rules_triggered` (`secret: …`, `pii: …`), comme un blocage : la colonne
  « classe de donnée captée » (menace / secret / financier / PII) se dérive donc
  de **toute** ligne à règles, pas seulement des blocages.
- **Drill-down Loki** : le sidecar `audit-loki` tail `/audit/current.jsonl` et
  pousse chaque ligne dans **Loki** (otel-lgtm, `:3100`) avec l'étiquette
  `{service="grob-audit", tenant=<id>}`. Le lien « Voir les logs » de chaque
  ligne ouvre **Grafana Explore** pré-filtré sur ce tenant.
- **Coupure en direct** : Grob relit la clé **du disque à chaque requête**. Le
  `watcher` compte les violations par tenant et, au seuil, exécute
  `grob key revoke <id>` → la requête suivante de l'agent fautif = **401**,
  sans redémarrage. Le watcher écrit aussi `/audit/governance.json`, servi par
  nginx et affiché sur `/governance`.

## Fichiers

| Fichier | Rôle |
|---------|------|
| `demo.kube.yaml` | manifeste `podman kube play` (généré — ne pas éditer à la main) |
| `gen-kube.py` / `gen-kube.sh` | **générateur** du manifeste depuis les sources |
| `Containerfile.tools` | image outils (alpine + binaire grob) pour init/seed/watcher |
| `docker-compose.yml` | démo **de base** (sans gouvernance) : grob, mock, lgtm, web, seed |
| `grob.config.toml` | config Grob (DLP + budget + mock + **auth api_key + audit**) |
| `tools.config.toml` | config minimale init/watcher (port mort → store local garanti) |
| `mock-backend.conf` | backend echo OpenAI-compatible (nginx) |
| `prometheus.yaml` | ajoute le scrape de `grob:/metrics` dans otel-lgtm |
| `grafana/provisioning/demo-dashboards.yaml` | provisionne le tableau de bord |
| `web/index.html` | page « blocages en direct » (SSE `/api/events`) |
| `web/governance.html` | page « gouvernance des agents » (`/governance`) |
| `web/nginx.conf` | sert les pages + relais SSE + `governance.json` |
| `init-keys.sh` | provisionne les 4 clés virtuelles (initContainer) |
| `seed.sh` | trafic dense déterministe par identité + slow-burn de compta-bot |
| `watcher.sh` | agrège l'audit par identité (colonnes SecOps) + coupure auto + `governance.json` |
| `audit-loki.sh` | sidecar : pousse le journal d'audit signé dans Loki, étiqueté par tenant (drill-down) |
| `Makefile` | runner (`make demo` / `gen` / `tools` / `demo-reset` / `demo-logs`) |

> **Régénérer le manifeste** après toute modification d'un fichier source :
> `make gen` (ou `sh gen-kube.sh`). Le manifeste embarque le contenu des sources
> dans des ConfigMaps ; ne l'éditez jamais à la main.

Le tableau de bord métier est versionné à part :
`deploy/grafana/grob-rssi-business.json` (à côté de `grob-overview.json`).

Le script de démonstration (déroulé scénique, répliques, replis) est dans
`docs/demos/showcase-rssi/DEMO.md`.
