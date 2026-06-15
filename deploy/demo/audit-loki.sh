#!/bin/sh
# =============================================================================
# Sidecar audit → Loki — embarque le journal SIGNÉ dans Loki, étiqueté par agent
# =============================================================================
# Tail /audit/current.jsonl (volume PARTAGÉ, écrit par grob) et pousse CHAQUE
# ligne d'audit dans Loki via l'API HTTP « push », avec le jeu d'étiquettes
#   { service="grob-audit", tenant="<tenant_id>" }
# Un auditeur ouvre alors, depuis la page de gouvernance, le tableau de bord
# d'investigation par agent (uid « grob-audit-agent »), pré-filtré sur
# {service="grob-audit", tenant="<id>"} via la variable $tenant, et voit les
# incidents au niveau REQUÊTE de cette identité : règles déclenchées, décision,
# classification, signature.
#
# Pourquoi un sidecar plutôt qu'un collecteur OTLP : la ligne d'audit est DÉJÀ
# du JSON signé ; on la pousse telle quelle (le « log line » Loki = la ligne
# d'audit intégrale), de sorte que la preuve reste vérifiable dans Loki.
#
# Robustesse :
#   - busybox `date` n'a pas %N : on fabrique un horodatage Loki en NANOSECONDES
#     = secondes·1e9 + un compteur 9 chiffres réinitialisé chaque seconde
#     (monotone et unique → Loki n'écarte aucune ligne pour cause de doublon
#     d'horodatage ou de désordre).
#   - les lignes d'audit contiennent des guillemets : on les échappe pour les
#     embarquer comme VALEUR de chaîne JSON dans la charge utile « push ».
#   - on lit la suite du fichier en continu (tail -F) ; à la première passe on
#     pousse aussi l'historique déjà présent (utile après un reset/relance).
#
# Variables d'environnement :
#   AUDIT_FILE   journal d'audit signé      (défaut: /audit/current.jsonl)
#   LOKI_URL     endpoint push Loki         (défaut: http://localhost:3100/loki/api/v1/push)
#   SERVICE      étiquette de service       (défaut: grob-audit)
# =============================================================================

set -eu

AUDIT_FILE="${AUDIT_FILE:-/audit/current.jsonl}"
LOKI_URL="${LOKI_URL:-http://localhost:3100/loki/api/v1/push}"
SERVICE="${SERVICE:-grob-audit}"

echo "[audit-loki] pousse ${AUDIT_FILE} -> ${LOKI_URL} (service=${SERVICE})"

# Attend que le journal d'audit apparaisse (grob l'écrit au premier trafic).
until [ -f "$AUDIT_FILE" ]; do
  echo "[audit-loki] attente du journal d'audit…"
  sleep 2
done

# Attend que Loki réponde (otel-lgtm met quelques secondes à démarrer).
until wget -q -O /dev/null --timeout=3 "${LOKI_URL%/loki/api/v1/push}/ready" 2>/dev/null; do
  echo "[audit-loki] attente de Loki…"
  sleep 2
done
echo "[audit-loki] Loki prêt, démarrage du suivi."

# Extrait la valeur de tenant_id d'une ligne d'audit JSON (sans jq).
tenant_of() {
  printf '%s' "$1" | sed -n 's/.*"tenant_id":"\([^"]*\)".*/\1/p'
}

# Extrait le trace_id OTel (présent quand grob tourne avec --features otel et
# [otel].enabled). Vide sinon (ligne sans trace, ex. attestation au démarrage).
trace_of() {
  printf '%s' "$1" | sed -n 's/.*"trace_id":"\([^"]*\)".*/\1/p'
}

# Dérive un NIVEAU de log (level) de la ligne d'audit, depuis son action et sa
# classification. Sans niveau explicite, Loki affiche « detected_level=unknown »
# (il ne sait pas deviner la gravité d'une ligne JSON métier). En émettant un
# `level` standard, Grafana colore le journal par gravité et la gravité épouse
# le TYPE d'incident : injection bloquée=critical, exfiltration bloquée=error,
# caviardage=warning, trafic normal=info.
#   C3 (blocage + injection)  -> critical
#   blocage DLP (C2 exfil)     -> error
#   DLP_WARN (caviardage C1/C2)-> warning
#   ERROR (échec dispatch)     -> error
#   reste (RESPONSE/NC, …)     -> info
level_of() {
  l="$1"
  act=$(printf '%s' "$l" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p')
  cls=$(printf '%s' "$l" | sed -n 's/.*"classification":"\([^"]*\)".*/\1/p')
  case "$act" in
    *BLOCK*) [ "$cls" = "C3" ] && echo "critical" || echo "error" ;;
    DLP_WARN) echo "warning" ;;
    ERROR)    echo "error" ;;
    *)        echo "info" ;;
  esac
}

# Échappe une ligne pour l'embarquer comme valeur de chaîne JSON : antislash
# d'abord, puis guillemets. (Les lignes d'audit n'ont ni saut de ligne ni
# tabulation : une ligne JSONL = une ligne.)
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Horodatage Loki en nanosecondes, monotone et unique par ligne. Écrit le
# résultat dans la variable GLOBALE TS au lieu de l'émettre sur stdout : appelé
# via $(...), le compteur SEQ vivrait dans un sous-shell et serait perdu, donc
# toutes les lignes d'une même seconde partageraient le même horodatage — Loki
# dédupliquerait alors et perdrait des lignes d'audit. En mutant une globale
# (appel direct, sans substitution de commande), le compteur PERSISTE le long
# de la boucle while-read continue.
LAST_SEC=0
SEQ=0
TS=""
loki_ts() {
  now=$(date +%s)
  if [ "$now" = "$LAST_SEC" ]; then
    SEQ=$((SEQ + 1))
  else
    LAST_SEC="$now"
    SEQ=0
  fi
  # 9 chiffres de « nanosecondes » synthétiques (compteur intra-seconde).
  TS=$(printf '%s%09d' "$now" "$SEQ")
}

# Pousse une ligne d'audit dans Loki, étiquetée par tenant.
push_line() {
  line="$1"
  [ -n "$line" ] || return 0
  tenant=$(tenant_of "$line")
  [ -n "$tenant" ] || tenant="unknown"
  lvl=$(level_of "$line")
  tid=$(trace_of "$line")
  loki_ts            # met à jour TS (globale) sans sous-shell
  ts="$TS"
  esc=$(json_escape "$line")
  # trace_id en STRUCTURED METADATA (3e élément du tuple values), pas en label :
  # forte cardinalité (unique par requête) → jamais un label indexé. Le derived
  # field Loki d'otel-lgtm (matcher sur trace_id) en fait un lien « Voir le trace »
  # vers Tempo. Absent (otel off / ligne hors requête) → tuple à 2 éléments.
  if [ -n "$tid" ]; then
    values=$(printf '[["%s","%s",{"trace_id":"%s"}]]' "$ts" "$esc" "$tid")
  else
    values=$(printf '[["%s","%s"]]' "$ts" "$esc")
  fi
  # `level` est une étiquette de stream standard : Loki la reconnaît comme
  # niveau (plus de detected_level=unknown) et Grafana colore le journal.
  payload=$(printf '{"streams":[{"stream":{"service":"%s","tenant":"%s","level":"%s"},"values":%s}]}' \
    "$SERVICE" "$tenant" "$lvl" "$values")
  # -s silencieux ; on ignore l'échec réseau ponctuel (la prochaine ligne suivra).
  curl -s -o /dev/null -X POST "$LOKI_URL" \
    -H 'Content-Type: application/json' \
    --max-time 5 \
    --data-binary "$payload" || true
}

# Suit le journal en continu, historique inclus (-n +1), et pousse chaque ligne.
# tail -F rouvre le fichier s'il est tourné/recréé (reset de la démo).
tail -n +1 -F "$AUDIT_FILE" 2>/dev/null | while IFS= read -r line; do
  push_line "$line"
done
