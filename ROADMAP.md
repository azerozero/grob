# Grob Roadmap — Priorités par impact business

**Dernière MAJ** : 2026-03-18

## Tier 1 — Sans ça tu ne peux pas vendre (semaines 1-2)

| # | Feature | Pourquoi | Effort | Status |
|---|---------|----------|--------|--------|
| 1 | **Benchmark publié** | Arme #1. Sans chiffres, "Rust = rapide" = marketing vide. Bifrost publie 11µs, LiteLLM publie ses P99. | 2-3j | 📋 Plan prêt |
| 2 | **README "Obviously Awesome"** | Hero section DLP + live TUI + compliance. | 1j | ✅ Livré |

### Détail Tier 1.1 — Benchmark

Fichiers à créer :

| Fichier | Mesure | Comparable à |
|---------|--------|--------------|
| `benches/proxy_overhead.rs` | Overhead par requête en µs (7 scénarios : baseline, DLP, cache, routing, OpenAI compat) | Bifrost 11µs |
| `benches/throughput.rs` | RPS soutenu à 1/10/100/500 concurrency | LiteLLM 1K RPS, Bifrost 5K RPS |
| `benches/memory.rs` | RSS au repos, après 1K/10K requêtes, avec/sans DLP | — |
| `bench/k6_test.js` | Load test externe standard industrie | Kong, LiteLLM |
| Header `x-grob-overhead-duration-ms` | Overhead mesuré dans chaque réponse | LiteLLM `x-litellm-overhead-duration-ms` |

**Cibles** : <100µs overhead, 5000+ RPS sur 4 CPU.

### Détail Tier 1.2 — README

Ressources clés :
- [10-Step Positioning (résumé Dunford)](https://www.heinzmarketing.com/blog/10-step-positioning-process-an-obviously-awesome-book-summary-part-3/)
- [Case study Userlist (Dunford appliqué)](https://userlist.com/blog/positioning-overhaul/)
- [10 READMEs qui cartonnent](https://blog.beautifulmarkdown.com/10-github-readme-examples-that-get-stars)
- Template : [create-go-app/cli](https://github.com/create-go-app/cli)
- Skill Claude : [GitHub Growth Marketing](https://mcpmarket.com/tools/skills/github-growth-marketing)
- Podcast : [Scaling DevTools](https://scalingdevtools.com/podcast) (100+ épisodes, go-to-market dev tools)
- Talk : [April Dunford — Positioning For Growth (BoS 2019)](https://businessofsoftware.org/2020/01/positioning-for-growth-april-dunford-bos2019/)

---

## Tier 2 — Différenciation visible (semaines 3-6)

| # | Feature | Pourquoi | Effort | Status |
|---|---------|----------|--------|--------|
| 3 | **`grob watch` (TUI dashboard)** | Aucun concurrent ne l'a. Démo killer — le prospect *voit* le proxy en temps réel. DLP, fallback, spend. Un screenshot README vaut 1000 mots. | 5-7j | ✅ MVP livré |
| 4 | **OpenTelemetry** | Checkbox enterprise. Premiers clients (défense/OIV) utilisent Prometheus (déjà fait), OTel c'est pour M6-M12. | 3-5j | ✅ Livré (feature `otel`) |

### Détail Tier 2.3 — `grob watch`

```
┌─ Providers ──────────────────────────────────────────────────────────┐
│  anthropic ●  142ms  99.2%  │  openrouter ●  380ms  97.1%           │
│  $12.40 / $200              │  $3.20 / ∞              47 req/min    │
├─ Live ───────────────────────────────────────────────────────────────┤
│  11:24:03  → claude-sonnet-4-6    anthropic   1.2K tok              │
│  11:24:04  ← claude-sonnet-4-6    anthropic   834 tok  1.4s  $0.02 │
│  11:24:05  🛡 DLP: 1 secret redacted (AWS key pattern)              │
│  11:24:09  ⚡ FALLBACK: anthropic 429 → openrouter                   │
├─ Alerts ─────────────────────────────────────────────────────────────┤
│  🛡 DLP: 3 secrets │ 1 PII │ 0 injections  ⚡ Circuit: all OK       │
└──────────────────────────────────────────────────────────────────────┘
```

Architecture :
- Endpoint SSE `/api/events` (réutilise le système `tap`)
- TUI : `ratatui` + `crossterm`
- Commande : `grob watch`
- Clavier : `f` filtre, `d` détail DLP, `p` pause, `q` quitter

---

## Tier 3 — Scale & monétisation (mois 2-4)

| # | Feature | Pourquoi | Effort | Status |
|---|---------|----------|--------|--------|
| 5 | **Virtual keys multi-tenant** | Facturation par équipe/projet. Sans ça, pas de tier Pro viable. | 5-7j | ✅ Complet (data + CLI + auth middleware + rate limiting + tenant extraction) |
| 6 | **Logging vers sinks externes** | Stdout JSON, fichier JSONL, HTTP webhook — configurable par sink | 3-5j | ✅ Livré |
| 7 | **Page pricing + Stripe** | Tier Community / Pro / Enterprise structuré | 2j | 🔲 À faire |

---

## Cleancode — Dette technique (en continu)

**Score actuel** : 7.4/10 (audit 2026-03-17)

Quick wins identifiés :

| Priorité | Fix | Impact |
|----------|-----|--------|
| 1 | Extraire handler boilerplate (3 handlers x 70% identique) | -200 lignes, élimine bug empty-body-on-serde-failure |
| 2 | Consolider scorer/CB dual-check (6 occurrences) | Simplification dispatch pipeline |
| 3 | Déplacer router tests → `router/tests.rs` (560 lignes inline) | Lisibilité |
| 4 | Remplacer `unwrap()` dans crypto (`encrypt.rs`, `audit_signer.rs`) | Sécurité |
| 5 | Tests error-path handlers | Couverture |

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
