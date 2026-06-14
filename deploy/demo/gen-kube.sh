#!/bin/sh
# =============================================================================
# Génère deploy/demo/demo.kube.yaml à partir des fichiers source de la démo
# =============================================================================
# Le manifeste kube embarque le CONTENU de chaque fichier source dans des
# ConfigMaps. Éditer le YAML à la main est fragile (échappement). Ce script est
# la SOURCE DE VÉRITÉ : il relit les fichiers source et régénère le manifeste.
#
# Lance-le après toute modification d'un fichier source (config, scripts, web,
# dashboards). Idempotent : même entrée → même sortie.
#
#   sh gen-kube.sh        # régénère demo.kube.yaml
#
# Dépend de python3 + PyYAML (présents sur la machine de dev ; non requis pour
# EXÉCUTER la démo, seulement pour la régénérer).
# =============================================================================
set -eu
cd "$(dirname "$0")"
exec python3 gen-kube.py
