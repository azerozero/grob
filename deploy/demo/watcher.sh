#!/bin/sh
# =============================================================================
# Watcher de gouvernance — agrège l'audit par identité et COUPE l'agent fautif
# =============================================================================
# Toutes les POLL secondes :
#   1. relit /audit/current.jsonl (volume PARTAGÉ, écrit par grob) ;
#   2. agrège, par tenant : requêtes totales, VIOLATIONS (lignes de BLOCAGE,
#      action DLP_BLOCK — un caviardage DLP_WARN n'en est PAS une), CLASSES de
#      données captées (dérivées des règles), si une PREUVE SIGNÉE existe ;
#   3. lit l'état des clés (grob key list --json : tenant + revoked) ;
#   4. joint ces comptes aux MÉTADONNÉES D'IDENTITÉ statiques (humain/agent,
#      département, owner, env) — le store de clés grob n'ayant pas de champ
#      libre, ces attributs vivent ici, indexés par tenant ;
#   5. écrit /audit/governance.json (lu par la page /governance) ;
#   6. si compta-bot dépasse le SEUIL de violations, RÉVOQUE sa clé une fois
#      (chemin store local → écrit revoked=true sur disque dans GROB_HOME/vkeys ;
#      grob relit la clé du disque à chaque requête → la requête suivante de
#      compta-bot = 401, EN DIRECT, sans redémarrage).
#
# Source de vérité = le journal d'audit SIGNÉ. Depuis le correctif feat(audit),
# un CAVIARDAGE (ligne DLP_WARN) nomme lui aussi ses règles dans
# dlp_rules_triggered (« secret: … », « pii: … »), tout comme un BLOCAGE. La
# colonne « classe de donnée captée » se dérive donc de TOUTE ligne à règles
# (caviardage ou blocage). En revanche, seules les lignes de BLOCAGE (DLP_BLOCK)
# comptent comme VIOLATIONS pour la coupure : un caviardage aboutit, expurgé.
#
# Conso « € » : avec le backend echo, le coût réel est nul. Pour une colonne
# parlante côté RSSI, on dérive une conso ILLUSTRATIVE = requêtes × PRICE_PER_REQ
# (déterministe). C'est une vue de démo, pas une facturation réelle.
#
# Idempotent / déterministe : on ne révoque qu'UNE fois (drapeau sentinelle),
# et l'état s0 (volume vide) redonne exactement le même déroulé.
#
# Variables d'environnement :
#   AUDIT_FILE       journal d'audit            (défaut: /audit/current.jsonl)
#   STATUS_FILE      sortie JSON gouvernance    (défaut: /audit/governance.json)
#   AGENTS_FILE      tenant/token/key_id        (défaut: /var/lib/grob/demo-agents.txt)
#   THRESHOLD        violations avant coupure   (défaut: 8)
#   ROGUE_TENANT     tenant à surveiller        (défaut: compta-bot)
#   POLL             secondes entre deux passes (défaut: 3)
#   PRICE_PER_REQ    € par requête (illustratif)(défaut: 0.012)
#   GROB_HOME / GROB_CONFIG : store partagé + config outils (port mort)
# =============================================================================

set -eu

AUDIT_FILE="${AUDIT_FILE:-/audit/current.jsonl}"
STATUS_FILE="${STATUS_FILE:-/audit/governance.json}"
AGENTS_FILE="${AGENTS_FILE:-/var/lib/grob/demo-agents.txt}"
THRESHOLD="${THRESHOLD:-8}"
ROGUE_TENANT="${ROGUE_TENANT:-compta-bot}"
POLL="${POLL:-3}"
PRICE_PER_REQ="${PRICE_PER_REQ:-0.012}"
GROB_HOME="${GROB_HOME:-/var/lib/grob}"
GROB_CONFIG="${GROB_CONFIG:-/etc/grob/tools.config.toml}"
GROB_BIN="${GROB_BIN:-grob}"
REVOKED_SENTINEL="${GROB_HOME}/.compta-revoked"

export GROB_HOME GROB_CONFIG

echo "[watcher] seuil=${THRESHOLD} violations pour couper ${ROGUE_TENANT}; audit=${AUDIT_FILE}"

# Attend le provisionnement des identités (le watcher a besoin du key_id rogue).
until [ -s "$AGENTS_FILE" ]; do
  echo "[watcher] attente du provisionnement des identités…"
  sleep 2
done
ROGUE_KEY_ID=$(sed -n "s/^${ROGUE_TENANT} //p" "$AGENTS_FILE" | awk '{print $2}')
echo "[watcher] clé surveillée: ${ROGUE_TENANT} (id=${ROGUE_KEY_ID})"

# -----------------------------------------------------------------------------
# Métadonnées d'identité STATIQUES, indexées par tenant. Émet, pour un tenant
# donné, les champs JSON dédiés au tableau (type, kind, dept/owner/env, label,
# emoji). C'est ici, et non dans le store de clés, parce que `grob key create`
# n'expose pas de champ de métadonnées libre.
#   type  : "human" | "agent"        (différencie humains et agents de service)
#   sub   : sous-titre métier        (département pour un humain ; owner+env sinon)
# -----------------------------------------------------------------------------
identity_json() {
  case "$1" in
    alice)      printf '"type":"human","emoji":"👤","label":"alice","sub":"Département RH","owner":"","env":""' ;;
    bob)        printf '"type":"human","emoji":"👤","label":"bob","sub":"Département Dev","owner":"","env":""' ;;
    dev-bot)    printf '"type":"agent","emoji":"🤖","label":"dev-bot","sub":"Agent de service","owner":"bob","env":"dev"' ;;
    compta-bot) printf '"type":"agent","emoji":"🤖","label":"compta-bot","sub":"Agent de service","owner":"Finance","env":"prod"' ;;
    *)          printf '"type":"agent","emoji":"🤖","label":"%s","sub":"Agent de service","owner":"?","env":"?"' "$1" ;;
  esac
}

# Agrège, par tenant, depuis le journal d'audit signé. Émet une ligne TSV :
#   tenant <TAB> total <TAB> violations <TAB> classes <TAB> signed <TAB> top_class
# où :
#   - total      = nombre de lignes d'audit pour ce tenant ;
#   - violations = lignes de BLOCAGE (action DLP_BLOCK) — un caviardage DLP_WARN
#                  n'en est PAS une (la requête aboutit, expurgée) ;
#   - classes    = ensemble trié de classes de données dérivées des règles
#                  nommées par l'audit (menace sur blocages injection/exfil ;
#                  secret/financier/pii sur caviardages), séparées par virgules ;
#   - signed     = 1 si au moins une ligne de ce tenant porte une signature ;
#   - top_class  = classification d'audit la PLUS GRAVE vue pour ce tenant
#                  (C3 > C2 > C1 > Nc), dérivée du champ `classification` du
#                  journal signé (source de vérité : derive_classification de
#                  grob). Sérialisée « NC » dans le JSON ; on la renvoie telle
#                  quelle (NC|C1|C2|C3) pour que la page de gouvernance affiche
#                  le TYPE d'incident dominant par identité.
# Robuste sans jq : une ligne d'audit = un objet JSON compact (une ligne/req).
# On ignore les tenants "unknown"/"anon" (requêtes non authentifiées / 401).
count_audit() {
  [ -s "$AUDIT_FILE" ] || return 0
  awk '
    BEGIN { OFS="\t" }
    # Rang de gravité d une classification (plus haut = plus grave).
    function rank(c) {
      if (c=="C3") return 3
      if (c=="C2") return 2
      if (c=="C1") return 1
      return 0   # NC ou inconnue
    }
    {
      t=""
      if (match($0, /"tenant_id":"[^"]*"/)) {
        t=substr($0, RSTART+13, RLENGTH-14)
      }
      if (t=="" || t=="unknown" || t=="anon") next
      total[t]++

      # Une signature non vide => preuve signée disponible pour ce tenant.
      if (match($0, /"signature":"[0-9a-fA-F]+"/)) signed[t]=1

      # Type d evenement d audit (RESPONSE / DLP_BLOCK / DLP_WARN / …).
      act=""
      if (match($0, /"action":"[^"]*"/)) act=substr($0, RSTART+10, RLENGTH-11)

      # Classification de la ligne (champ `classification` du JSON d audit).
      # On retient, par tenant, la plus grave rencontrée (C3 > C2 > C1 > NC).
      cl=""
      if (match($0, /"classification":"(NC|C1|C2|C3)"/)) {
        cl=substr($0, RSTART+18, RLENGTH-19)
        if (!(t in top) || rank(cl) > rank(top[t])) top[t]=cl
      }

      # Contenu du tableau dlp_rules_triggered (entre crochets). Depuis le
      # correctif feat(audit), un CAVIARDAGE (DLP_WARN) nomme lui aussi ses
      # regles ("secret: …", "pii: …"), pas seulement un BLOCAGE. On derive donc
      # la classe de donnee captee de TOUTE ligne a regles non vides.
      rules=""
      if (match($0, /"dlp_rules_triggered":\[[^]]*\]/)) {
        rules=substr($0, RSTART, RLENGTH)
      }
      if (rules ~ /\[[^]]/) {
        low=tolower(rules)
        # Cle de classe construite dans une variable (mk) : un indice de tableau
        # contenant une virgule litterale fait echouer certains awk (BWK/nawk).
        if (low ~ /injection|exfiltration|exfil/)               { mk=t"|menace";    cls[mk]=1 }
        if (low ~ /aws|github|openai|secret|token|api[ _-]?key/) { mk=t"|secret";    cls[mk]=1 }
        if (low ~ /iban/)                                        { mk=t"|financier"; cls[mk]=1 }
        if (low ~ /credit|card|pii/)                            { mk=t"|pii";       cls[mk]=1 }
      }

      # VIOLATION (au sens du watcher = ce qui mene a la coupure) = une requete
      # BLOQUEE par le DLP. Un caviardage (DLP_WARN) n est PAS une violation : la
      # requete aboutit, expurgee. On gate donc sur l action de BLOCAGE, et non
      # sur la simple presence de regles (que les caviardages portent desormais).
      if (act ~ /BLOCK/) viol[t]++
    }
    END {
      for (k in total) {
        c=""
        # Ordre stable des classes : menace, secret, financier, pii.
        kk=k"|menace";    if (kk in cls) c=c (c==""?"":",") "menace"
        kk=k"|secret";    if (kk in cls) c=c (c==""?"":",") "secret"
        kk=k"|financier"; if (kk in cls) c=c (c==""?"":",") "financier"
        kk=k"|pii";       if (kk in cls) c=c (c==""?"":",") "pii"
        print k, total[k], (k in viol ? viol[k] : 0), c, (k in signed ? 1 : 0), (k in top ? top[k] : "NC")
      }
    }
  ' "$AUDIT_FILE"
}

# Statut de révocation par tenant (via grob key list --json).
# Émet des lignes "tenant true|false". La sortie JSON est « pretty » : tenant_id
# et revoked sont sur des LIGNES distinctes du même objet, donc on apparie en
# awk (état : on retient le dernier tenant_id vu, on l'émet au revoked suivant).
load_revoked() {
  "$GROB_BIN" key list --json 2>/dev/null | awk '
    /"tenant_id"/ {
      s=$0; sub(/.*"tenant_id"[[:space:]]*:[[:space:]]*"/, "", s); sub(/".*/, "", s)
      cur=s
    }
    /"revoked"/ {
      rv = ($0 ~ /"revoked"[[:space:]]*:[[:space:]]*true/) ? "true" : "false"
      if (cur!="") { print cur, rv; cur="" }
    }
  '
}

# Émet la partie JSON « data_classes » à partir de la liste CSV de classes.
# Tableau JSON de chaînes (ordre déjà stable), [] si aucune.
classes_json() {
  csv="$1"
  if [ -z "$csv" ]; then printf '[]'; return; fi
  printf '['
  first=1
  OLD_IFS="$IFS"; IFS=','
  # shellcheck disable=SC2086  # découpage CSV volontaire sur la virgule
  for c in $csv; do
    [ $first -eq 1 ] || printf ','
    first=0
    printf '"%s"' "$c"
  done
  IFS="$OLD_IFS"
  printf ']'
}

# Écrit /audit/governance.json à partir des comptes + statut des clés + méta.
# Format consommé par governance.html :
#   {"updated":…,"threshold":N,"agents":[{
#       tenant,type,emoji,label,sub,owner,env,
#       requests,spend_eur,violations,data_classes:[…],
#       decision:"caviardé|bloqué|—",incident_type:"NC|C1|C2|C3",
#       signed:bool,revoked:bool}]}
write_status() {
  agg="$1"            # lignes TSV "tenant total violations classes signed top_class"
  revoked_map="$2"    # lignes "tenant true|false"
  tmp="${STATUS_FILE}.tmp"
  {
    printf '{"updated":"%s","threshold":%s,"agents":[' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$THRESHOLD"
    first=1
    # Ordre stable et déterministe : 2 humains puis 2 agents de service.
    for tenant in alice bob dev-bot "$ROGUE_TENANT"; do
      # Extrait la ligne TSV de ce tenant (champs absents → valeurs neutres).
      # Une ligne vide (tenant sans audit) donne une ENTRÉE VIDE à awk, qui ne
      # lit alors AUCUN enregistrement et n'imprime rien : on retombe donc sur
      # une valeur par défaut côté shell (expansion `${x:-…}`) pour garantir des
      # entiers/chaînes valides — sinon `[ "$viol" -gt 0 ]` casserait en busybox
      # (« sh: out of range ») quand le journal d'audit est encore vide.
      line=$(printf '%s\n' "$agg" | awk -F'\t' -v t="$tenant" '$1==t{print; exit}')
      total=$(printf '%s' "$line"  | awk -F'\t' '{print $2}'); total="${total:-0}"
      viol=$(printf '%s' "$line"   | awk -F'\t' '{print $3}'); viol="${viol:-0}"
      classes=$(printf '%s' "$line" | awk -F'\t' '{print $4}')
      signed=$(printf '%s' "$line" | awk -F'\t' '{print $5}'); signed="${signed:-0}"
      top_class=$(printf '%s' "$line" | awk -F'\t' '{print $6}'); top_class="${top_class:-NC}"

      rv=$(printf '%s\n' "$revoked_map" | awk -v t="$tenant" '$1==t{print $2; exit}')
      [ "$rv" = "true" ] && revoked=true || revoked=false
      [ "$signed" = "1" ] && signed_json=true || signed_json=false
      spend=$(awk -v n="$total" -v p="$PRICE_PER_REQ" 'BEGIN{printf "%.2f", n*p}')

      # Décision dominante : si des violations existent → « bloqué » ; sinon si du
      # trafic a circulé MAIS avec au moins une action DLP (classification ≠ Nc)
      # → « caviardé » (le DLP a expurgé) ; sinon → « — » (trafic 100 % propre).
      # On s'appuie sur la classification (source de vérité) pour qu'une identité
      # exemplaire comme alice (toutes lignes Nc) affiche « — » et non « caviardé ».
      if [ "$viol" -gt 0 ]; then decision="bloqué"
      elif [ "$total" -gt 0 ] && [ "$top_class" != "NC" ]; then decision="caviardé"
      else decision="—"; fi

      [ $first -eq 1 ] || printf ','
      first=0
      printf '{"tenant":"%s",%s,"requests":%s,"spend_eur":%s,"violations":%s,"data_classes":' \
        "$tenant" "$(identity_json "$tenant")" "$total" "$spend" "$viol"
      classes_json "$classes"
      printf ',"decision":"%s","incident_type":"%s","signed":%s,"revoked":%s}' \
        "$decision" "$top_class" "$signed_json" "$revoked"
    done
    printf ']}\n'
  } > "$tmp"
  mv "$tmp" "$STATUS_FILE"
}

# Révoque la clé de compta-bot UNE seule fois (sentinelle sur disque partagé).
maybe_revoke() {
  rogue_viol="$1"
  [ -f "$REVOKED_SENTINEL" ] && return 0
  [ "$rogue_viol" -ge "$THRESHOLD" ] || return 0
  [ -n "$ROGUE_KEY_ID" ] || { echo "[watcher] key_id rogue introuvable, révocation impossible" >&2; return 0; }

  echo "[watcher] ⛔ SEUIL ATTEINT — ${ROGUE_TENANT} a ${rogue_viol} violations (≥ ${THRESHOLD}). Révocation de la clé ${ROGUE_KEY_ID}…"
  if "$GROB_BIN" key revoke "$ROGUE_KEY_ID" 2>&1; then
    : > "$REVOKED_SENTINEL"
    echo "[watcher] ✅ Clé de ${ROGUE_TENANT} RÉVOQUÉE — ses prochaines requêtes renverront 401 (coupure en direct)."
  else
    echo "[watcher] ÉCHEC de la révocation de ${ROGUE_TENANT}" >&2
  fi
}

while true; do
  agg=$(count_audit)
  revoked_map=$(load_revoked)
  rogue_viol=$(printf '%s\n' "$agg" | awk -F'\t' -v t="$ROGUE_TENANT" '$1==t{print $3+0; exit}')
  rogue_viol="${rogue_viol:-0}"

  write_status "$agg" "$revoked_map"
  maybe_revoke "$rogue_viol"

  sleep "$POLL"
done
