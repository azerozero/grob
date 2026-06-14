#!/usr/bin/env python3
"""Génère demo.kube.yaml à partir des fichiers source de la démo grob.

Le manifeste « podman kube play » embarque le contenu de chaque fichier source
(config, scripts shell, pages web, dashboards Grafana) dans des ConfigMaps,
montées en subPath dans les conteneurs du pod « grob-demo ».

Éditer ce manifeste à la main est fragile (échappement YAML/JSON imbriqué). Ce
script relit les fichiers source et régénère le manifeste de façon déterministe.
Il est la SOURCE DE VÉRITÉ du manifeste.

La couche GOUVERNANCE ajoute, par rapport à la démo de base :
  - un volume GROB_HOME PARTAGÉ (clés virtuelles chiffrées + clé de chiffrement
    + fichier d'agents) entre l'init, grob, le seed et le watcher ;
  - un volume /audit PARTAGÉ (journal d'audit signé + governance.json) entre
    grob (écrit l'audit), le watcher (lit l'audit, écrit governance.json) et le
    conteneur web (sert governance.json) ;
  - un initContainer qui provisionne les 4 clés virtuelles AVANT grob ;
  - un conteneur watcher qui coupe l'agent fautif en direct ;
  - un sidecar audit-loki qui embarque le journal d'audit signé dans Loki,
    étiqueté par tenant, pour le drill-down par identité depuis la page de
    gouvernance.
"""

import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - message d'aide hors test
    sys.exit("PyYAML requis : pip install pyyaml (ou brew install python-yaml)")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "demo.kube.yaml")

# Image « outils » (alpine + binaire grob) pour init/seed/watcher : ces étapes
# ont besoin d'un shell, absent de l'image grob « scratch » publiée.
IMG_TOOLS = "localhost/grob-demo-tools:latest"
# Image grob PATCHÉE buildée localement (cf. Containerfile + `make grob-img`) :
# elle classe les caviardages en C1/C2, contrairement à la release publiée.
IMG_GROB = "localhost/grob-demo:local"
IMG_NGINX = "docker.io/library/nginx:1.27-alpine"
IMG_LGTM = "docker.io/grafana/otel-lgtm:0.11.10"

# ── ConfigMaps : nom logique -> { clé de données : fichier source } ──────────
# L'ordre est conservé (sort_keys=False) pour un diff stable.
CONFIGMAPS = [
    ("cm-grob-config", "config.toml", "grob.config.toml"),
    ("cm-tools-config", "tools.config.toml", "tools.config.toml"),
    ("cm-mock", "default.conf", "mock-backend.conf"),
    ("cm-prom", "prometheus.yaml", "prometheus.yaml"),
    ("cm-dash-prov", "custom.yaml", "grafana/provisioning/demo-dashboards.yaml"),
    ("cm-dash-json", "grob-rssi-business.json", "../grafana/grob-rssi-business.json"),
    ("cm-dash-overview", "grob-overview.json", "../grafana/grob-overview.json"),
    ("cm-dash-audit-agent", "audit-agent.json", "grafana/audit-agent.json"),
    ("cm-web-html", "index.html", "web/index.html"),
    ("cm-web-gov", "governance.html", "web/governance.html"),
    ("cm-web-nginx", "default.conf", "web/nginx.conf"),
    ("cm-init", "init-keys.sh", "init-keys.sh"),
    ("cm-seed", "seed.sh", "seed.sh"),
    ("cm-watcher", "watcher.sh", "watcher.sh"),
    ("cm-audit-loki", "audit-loki.sh", "audit-loki.sh"),
]

# ConfigMap inline (pas de fichier source) : neutralise les dashboards par
# défaut de l'image otel-lgtm.
EMPTY_DASHBOARDS = "apiVersion: 1\nproviders: []\n"


def read_source(rel):
    """Renvoie le contenu texte d'un fichier source relatif au dossier démo."""
    path = os.path.join(HERE, rel)
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def configmap(name, key, content):
    """Construit un dict ConfigMap Kubernetes."""
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name},
        "data": {key: content},
    }


def env(pairs):
    """Convertit une liste (nom, valeur) en liste d'entrées env Kubernetes."""
    return [{"name": k, "value": str(v)} for k, v in pairs]


def cm_mount(vol, mount_path, sub_path):
    """Montage subPath en lecture seule d'une ConfigMap."""
    return {
        "name": vol,
        "mountPath": mount_path,
        "subPath": sub_path,
        "readOnly": True,
    }


def build_pod():
    """Construit le Pod « grob-demo » (initContainer + 6 conteneurs)."""

    # ── initContainer : provisionne les 3 clés virtuelles dans GROB_HOME ──
    init_container = {
        "name": "init-keys",
        "image": IMG_TOOLS,
        "command": ["sh", "/init-keys.sh"],
        "env": env([
            ("GROB_HOME", "/var/lib/grob"),
            ("GROB_CONFIG", "/etc/grob/tools.config.toml"),
        ]),
        "volumeMounts": [
            {"name": "grob-data", "mountPath": "/var/lib/grob"},
            cm_mount("vol-init", "/init-keys.sh", "init-keys.sh"),
            cm_mount("vol-tools-config", "/etc/grob/tools.config.toml", "tools.config.toml"),
        ],
    }

    grob = {
        "name": "grob",
        "image": IMG_GROB,
        "args": ["run", "--json-logs", "--host", "0.0.0.0", "--port", "8080"],
        "env": env([
            ("GROB_CONFIG", "/etc/grob/config.toml"),
            ("GROB_HOME", "/var/lib/grob"),
            # Le mock écoute sur 8889 : dans le pod (pile réseau partagée),
            # otel-lgtm occupe déjà 127.0.0.1:8888 (self-métriques du collecteur).
            ("GROB_MOCK_BACKEND", "http://localhost:8889"),
            ("RUST_LOG", "info"),
        ]),
        "ports": [{"containerPort": 8080, "hostPort": 8080}],
        "volumeMounts": [
            cm_mount("vol-grob-config", "/etc/grob/config.toml", "config.toml"),
            {"name": "grob-data", "mountPath": "/var/lib/grob"},
            {"name": "audit-data", "mountPath": "/audit"},
        ],
    }

    mock = {
        "name": "mock",
        "image": IMG_NGINX,
        "volumeMounts": [
            cm_mount("vol-mock", "/etc/nginx/conf.d/default.conf", "default.conf"),
        ],
    }

    lgtm = {
        "name": "lgtm",
        "image": IMG_LGTM,
        "env": env([
            ("GF_AUTH_ANONYMOUS_ENABLED", "true"),
            ("GF_AUTH_ANONYMOUS_ORG_ROLE", "Viewer"),
            ("GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH",
             "/otel-lgtm/grafana/conf/provisioning/dashboards/custom/grob-rssi-business.json"),
        ]),
        "ports": [{"containerPort": 3000, "hostPort": 3000}],
        "volumeMounts": [
            cm_mount("vol-prom", "/otel-lgtm/prometheus.yaml", "prometheus.yaml"),
            cm_mount("vol-dash-prov",
                     "/otel-lgtm/grafana/conf/provisioning/dashboards/custom.yaml", "custom.yaml"),
            cm_mount("vol-dash-json",
                     "/otel-lgtm/grafana/conf/provisioning/dashboards/custom/grob-rssi-business.json",
                     "grob-rssi-business.json"),
            cm_mount("vol-dash-overview",
                     "/otel-lgtm/grafana/conf/provisioning/dashboards/custom/grob-overview.json",
                     "grob-overview.json"),
            cm_mount("vol-dash-audit-agent",
                     "/otel-lgtm/grafana/conf/provisioning/dashboards/custom/audit-agent.json",
                     "audit-agent.json"),
            cm_mount("vol-dash-empty",
                     "/otel-lgtm/grafana/conf/provisioning/dashboards/grafana-dashboards.yaml",
                     "empty.yaml"),
            cm_mount("vol-dash-empty",
                     "/otel-lgtm/grafana/conf/provisioning/dashboards/sample.yaml", "empty.yaml"),
        ],
    }

    web = {
        "name": "web",
        "image": IMG_NGINX,
        "ports": [{"containerPort": 80, "hostPort": 8088}],
        "volumeMounts": [
            cm_mount("vol-web-html", "/usr/share/nginx/html/index.html", "index.html"),
            cm_mount("vol-web-gov", "/usr/share/nginx/html/governance.html", "governance.html"),
            cm_mount("vol-web-nginx", "/etc/nginx/conf.d/default.conf", "default.conf"),
            # /audit (governance.json) servi par nginx en lecture seule.
            {"name": "audit-data", "mountPath": "/srv/governance", "readOnly": True},
        ],
    }

    seed = {
        "name": "seed",
        "image": IMG_TOOLS,
        "command": ["sh", "/seed.sh"],
        "env": env([
            ("GROB_URL", "http://localhost:8080"),
            # Trafic dense (1 s entre requêtes) ; la dérive de compta-bot démarre
            # après BURN_AFTER cycles propres (slow burn, pas un pic).
            ("INTERVAL", "1"),
            ("BURN_AFTER", "3"),
            ("AGENTS_FILE", "/var/lib/grob/demo-agents.txt"),
        ]),
        "volumeMounts": [
            cm_mount("vol-seed", "/seed.sh", "seed.sh"),
            # Lecture seule du fichier d'agents (jetons par agent).
            {"name": "grob-data", "mountPath": "/var/lib/grob", "readOnly": True},
        ],
    }

    watcher = {
        "name": "watcher",
        "image": IMG_TOOLS,
        "command": ["sh", "/watcher.sh"],
        "env": env([
            ("GROB_HOME", "/var/lib/grob"),
            ("GROB_CONFIG", "/etc/grob/tools.config.toml"),
            ("AUDIT_FILE", "/audit/current.jsonl"),
            ("STATUS_FILE", "/audit/governance.json"),
            ("AGENTS_FILE", "/var/lib/grob/demo-agents.txt"),
            ("THRESHOLD", "8"),
            ("ROGUE_TENANT", "compta-bot"),
            ("POLL", "3"),
        ]),
        "volumeMounts": [
            cm_mount("vol-watcher", "/watcher.sh", "watcher.sh"),
            cm_mount("vol-tools-config", "/etc/grob/tools.config.toml", "tools.config.toml"),
            # Lecture/écriture : révoque (vkeys) + lit le fichier d'agents.
            {"name": "grob-data", "mountPath": "/var/lib/grob"},
            # Lecture/écriture : lit l'audit, écrit governance.json.
            {"name": "audit-data", "mountPath": "/audit"},
        ],
    }

    # ── audit-loki : sidecar qui embarque le journal d'audit signé dans Loki ──
    # Tail /audit/current.jsonl et pousse chaque ligne vers l'API push de Loki
    # (otel-lgtm, :3100), étiquetée { service="grob-audit", tenant=<id> }, pour
    # le drill-down par identité (« Voir les logs » → Grafana Explore). Tourne
    # dans l'image outils (alpine + curl) ; n'a besoin que de l'audit (RO).
    audit_loki = {
        "name": "audit-loki",
        "image": IMG_TOOLS,
        "command": ["sh", "/audit-loki.sh"],
        "env": env([
            ("AUDIT_FILE", "/audit/current.jsonl"),
            ("LOKI_URL", "http://localhost:3100/loki/api/v1/push"),
            ("SERVICE", "grob-audit"),
        ]),
        "volumeMounts": [
            cm_mount("vol-audit-loki", "/audit-loki.sh", "audit-loki.sh"),
            # Lecture seule : le sidecar ne fait que LIRE l'audit pour le pousser.
            {"name": "audit-data", "mountPath": "/audit", "readOnly": True},
        ],
    }

    volumes = [
        {"name": "vol-grob-config", "configMap": {"name": "cm-grob-config"}},
        {"name": "vol-tools-config", "configMap": {"name": "cm-tools-config"}},
        {"name": "vol-mock", "configMap": {"name": "cm-mock"}},
        {"name": "vol-prom", "configMap": {"name": "cm-prom"}},
        {"name": "vol-dash-prov", "configMap": {"name": "cm-dash-prov"}},
        {"name": "vol-dash-json", "configMap": {"name": "cm-dash-json"}},
        {"name": "vol-dash-overview", "configMap": {"name": "cm-dash-overview"}},
        {"name": "vol-dash-audit-agent", "configMap": {"name": "cm-dash-audit-agent"}},
        {"name": "vol-dash-empty", "configMap": {"name": "cm-dash-empty"}},
        {"name": "vol-web-html", "configMap": {"name": "cm-web-html"}},
        {"name": "vol-web-gov", "configMap": {"name": "cm-web-gov"}},
        {"name": "vol-web-nginx", "configMap": {"name": "cm-web-nginx"}},
        {"name": "vol-init", "configMap": {"name": "cm-init"}},
        {"name": "vol-seed", "configMap": {"name": "cm-seed"}},
        {"name": "vol-watcher", "configMap": {"name": "cm-watcher"}},
        {"name": "vol-audit-loki", "configMap": {"name": "cm-audit-loki"}},
        # Volumes PARTAGÉS (clé de la couche gouvernance).
        {"name": "grob-data", "emptyDir": {}},
        {"name": "audit-data", "emptyDir": {}},
    ]

    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "grob-demo", "labels": {"app": "grob-demo"}},
        "spec": {
            "restartPolicy": "Always",
            "initContainers": [init_container],
            "containers": [grob, mock, lgtm, web, seed, watcher, audit_loki],
            "volumes": volumes,
        },
    }


def main():
    docs = []
    for name, key, src in CONFIGMAPS:
        docs.append(configmap(name, key, read_source(src)))
    docs.append(configmap("cm-dash-empty", "empty.yaml", EMPTY_DASHBOARDS))
    docs.append(build_pod())

    with open(OUT, "w", encoding="utf-8") as fh:
        yaml.safe_dump_all(
            docs,
            fh,
            default_flow_style=False,
            allow_unicode=False,
            sort_keys=False,
            width=80,
            explicit_start=False,
        )
    print(f"[gen-kube] {OUT} régénéré ({len(docs)} documents).")


if __name__ == "__main__":
    main()
