# =============================================================================
# Runner de la démo grob — conformité RSSI + GOUVERNANCE des agents
# =============================================================================
# Le chemin d'exécution officiel est podman + kube play :
#
#   make demo        Construit les images, régénère le manifeste, déploie
#   make demo-logs   Suit les logs du seed (trafic) et du watcher (coupure)
#   make demo-reset  Remet la démo à l'état s0 (idempotent)
#   make demo-stop   Arrête le pod sans supprimer les images
#   make gen         Régénère demo.kube.yaml depuis les fichiers source
#   make grob-img    (Re)construit l'image grob patchée (caviardages C1/C2)
#   make tools       (Re)construit l'image localhost/grob-demo-tools
#   make urls        Rappelle les adresses d'accès
#
# Compose (docker compose / podman-compose) reste disponible pour la démo de
# BASE (sans gouvernance) via docker-compose.yml ; la couche gouvernance, elle,
# vit dans le manifeste kube (volumes partagés + initContainer + watcher).
# =============================================================================

PODMAN     ?= podman
KUBE       := demo.kube.yaml
GROB_IMG   := localhost/grob-demo:local
TOOLS_IMG  := localhost/grob-demo-tools:latest
POD        := grob-demo
# Racine du dépôt (contexte de build pour l'image grob : le Containerfile fait
# COPY . . sur tout l'arbre source). Le Makefile vit dans deploy/demo.
REPO_ROOT  := $(abspath $(CURDIR)/../..)

.PHONY: demo grob-img tools gen demo-logs demo-stop demo-reset urls

# Image grob PATCHÉE, buildée depuis l'arbre source local : elle embarque le
# correctif feat(audit) qui classe les caviardages en C1/C2 (DLP_WARN), encore
# absent d'une release publiée. Premier build long (compilation Rust complète) ;
# mis en cache par podman ensuite tant que les sources ne changent pas. Une fois
# le correctif publié, on pourra pinner ghcr.io/azerozero/grob:<version> à la place.
grob-img: ## (Re)construit l'image grob patchée (caviardages typés C1/C2).
	$(PODMAN) build -t $(GROB_IMG) -f Containerfile $(REPO_ROOT)

# Image « outils » : alpine + binaire grob (l'image grob publiée est scratch,
# sans shell ; init/seed/watcher ont besoin d'un shell). Construite une fois,
# mise en cache ensuite.
tools: ## (Re)construit l'image outils (grob CLI + shell).
	$(PODMAN) build -t $(TOOLS_IMG) -f Containerfile.tools .

# Régénère le manifeste depuis les fichiers source (config, scripts, web, dashboards).
gen: ## Régénère demo.kube.yaml depuis les sources.
	sh gen-kube.sh

demo: grob-img tools gen ## Construit, régénère, puis déploie la démo complète.
	$(PODMAN) kube play $(KUBE)
	@$(MAKE) --no-print-directory urls

demo-logs: ## Suit le trafic (seed) et la coupure en direct (watcher).
	$(PODMAN) logs -f $(POD)-seed $(POD)-watcher

demo-stop: ## Arrête le pod (conserve images et manifeste).
	$(PODMAN) kube down $(KUBE)

# Reset idempotent : `kube down` retire pod + volumes (emptyDir éphémères →
# clés, audit et governance.json repartent de zéro = état s0). Le relancer deux
# fois de suite aboutit au même état propre.
demo-reset: ## Réinitialise totalement la démo (pod + volumes éphémères).
	-$(PODMAN) kube down $(KUBE)
	@echo "État s0 restauré. Relancez avec : make demo"

urls: ## Affiche les adresses d'accès de la démo.
	@echo ""
	@echo "  Gouvernance des agents ->  http://localhost:8088/governance   (le « wow »)"
	@echo "  Blocages en direct     ->  http://localhost:8088"
	@echo "  Tableau de bord RSSI   ->  http://localhost:3000  (admin / admin)"
	@echo "  API grob               ->  http://localhost:8080"
	@echo ""
