#!/bin/sh
# =============================================================================
# Provisionnement des clés virtuelles par identité — couche GOUVERNANCE (démo)
# =============================================================================
# S'exécute UNE FOIS au démarrage, AVANT grob (le serveur n'écoute pas encore).
# Comme aucune instance n'est détectée sur host:port, `grob key create` emprunte
# le chemin « store local » : il écrit directement dans GROB_HOME/vkeys/ (chiffré
# AES-256-GCM avec GROB_HOME/encryption.key) ET — contrairement au chemin RPC —
# il ENREGISTRE le tenant fourni par --tenant. Le tenant est indispensable :
# c'est lui qui étiquette chaque ligne du journal d'audit, donc l'attribution
# par identité de la conso et des incidents.
#
# QUATRE identités = quatre clés = quatre tenants. La démo distingue les HUMAINS
# (qui ouvrent une session) des AGENTS DE SERVICE (clés machine non humaines) :
#
#   alice       👤 humain  — département RH    — trafic propre, gros volume
#   bob         👤 humain  — département Dev   — trafic propre, gros volume
#   dev-bot     🤖 agent   — owner=bob  env=dev  — agent de code, trafic propre
#   compta-bot  🤖 agent   — owner=Finance env=prod — l'agent qui DÉRIVE lentement
#                              (fuites IBAN/secret graduelles + injections
#                               occasionnelles) → finit révoqué par le watcher.
#
# Le jeton en clair n'est imprimé qu'UNE fois par grob ; on le capture ici et on
# persiste, dans un fichier du volume PARTAGÉ, une ligne « tenant token key_id »
# par identité. Le seed lit les jetons pour s'authentifier ; le watcher lit le
# key_id (UUID complet) pour révoquer l'agent fautif. Les métadonnées d'identité
# (type humain/agent, département, owner, env) sont statiques : elles vivent dans
# le watcher, indexées par tenant — le store de clés grob n'a pas de champ libre.
#
# Idempotent : si le fichier d'agents existe déjà (relance de la démo sur le
# même volume), on ne recrée rien — l'état s0 est préservé.
#
# Variables d'environnement :
#   GROB_HOME    racine du store partagé (défaut: /var/lib/grob)
#   GROB_CONFIG  config outils (port mort → chemin store local garanti)
#   AGENTS_FILE  fichier de sortie tenant/token/key_id (défaut: $GROB_HOME/demo-agents.txt)
# =============================================================================

set -eu

GROB_HOME="${GROB_HOME:-/var/lib/grob}"
GROB_CONFIG="${GROB_CONFIG:-/etc/grob/tools.config.toml}"
AGENTS_FILE="${AGENTS_FILE:-${GROB_HOME}/demo-agents.txt}"
GROB_BIN="${GROB_BIN:-grob}"

export GROB_HOME GROB_CONFIG

# Idempotence : déjà provisionné → ne rien refaire (relance back-to-back).
if [ -s "$AGENTS_FILE" ]; then
  echo "[init] identités déjà provisionnées ($AGENTS_FILE), rien à faire."
  exit 0
fi

mkdir -p "$GROB_HOME"

# Crée une clé virtuelle et capture (tenant, jeton, key_id) dans AGENTS_FILE.
# `grob key create` imprime, sur le chemin local :
#   ID:       <uuid>
#   ...
#   Key: <grob_xxx...>
# On extrait l'UUID et le jeton de cette sortie déterministe.
provision() {
  name="$1"
  tenant="$2"
  budget="$3"

  out=$("$GROB_BIN" key create --name "$name" --tenant "$tenant" --budget "$budget" 2>/dev/null)

  key_id=$(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*ID:[[:space:]]*//p' | head -n1)
  token=$(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*Key:[[:space:]]*//p' | head -n1)

  if [ -z "$key_id" ] || [ -z "$token" ]; then
    echo "[init] ÉCHEC: impossible de provisionner $tenant" >&2
    printf '%s\n' "$out" >&2
    exit 1
  fi

  # Format: tenant<espace>token<espace>key_id (lu par seed.sh et watcher.sh).
  printf '%s %s %s\n' "$tenant" "$token" "$key_id" >> "$AGENTS_FILE"
  echo "[init] $tenant -> clé créée (id=$key_id)"
}

# Écriture atomique : on construit dans un fichier temporaire puis on renomme,
# pour que le seed/watcher ne lisent jamais un fichier d'agents partiel.
# L'ordre est stable et déterministe : 2 humains, puis 2 agents de service.
TMP="${AGENTS_FILE}.tmp"
rm -f "$TMP"
AGENTS_FILE="$TMP" provision "alice"      "alice"      20
AGENTS_FILE="$TMP" provision "bob"        "bob"        20
AGENTS_FILE="$TMP" provision "dev-bot"    "dev-bot"    20
AGENTS_FILE="$TMP" provision "compta-bot" "compta-bot" 20
mv "$TMP" "$AGENTS_FILE"

echo "[init] 4 identités provisionnées dans $AGENTS_FILE (2 humains + 2 agents)"
"$GROB_BIN" key list 2>/dev/null || true
