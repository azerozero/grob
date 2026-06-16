# Pré-vol — Démo Grob RSSI

> À dérouler **avant** chaque représentation. Une scène préparée ne s'improvise
> pas. Comptez 10 minutes de marge.

## La veille / une fois

- [ ] **Images récupérées** : `docker compose -f deploy/demo/docker-compose.yml pull`
      (évite un téléchargement de plusieurs centaines de Mo devant le public).
- [ ] **Doublure enregistrée** : `make -C deploy/demo demo-cast`, puis
      `asciinema play docs/demos/showcase-rssi/demo.cast` rejoué en entier au
      moins une fois (voir DEMO.md → La doublure).
- [ ] **GIF visuel optionnel** : `make -C deploy/demo demo-gif` produit
      `docs/demos/showcase-rssi/demo.gif` si `agg` est installé.
- [ ] **Captures de secours** du tableau de bord et de la page de blocages
      placées dans ce dossier (mode hors-ligne).

## 10 minutes avant

- [ ] **Lancer la stack** : `cd deploy/demo && make demo`.
- [ ] **Vérifier les 3 accès** :
      - [ ] `http://localhost:8088/governance` — les 4 identités apparaissent ;
            `compta-bot` finit par passer en statut révoqué.
      - [ ] `http://localhost:8088` — des lignes tombent (rouge + ambre).
      - [ ] `http://localhost:3000` — le tableau de bord RSSI s'ouvre en page
            d'accueil, les chiffres montent (auto-refresh 5 s).
      - [ ] `curl -s http://localhost:8080/health` répond.
- [ ] **Laisser tourner 1 à 2 minutes** pour que les compteurs soient non nuls
      et que les graphes aient de la matière (pas de scène sur des zéros).
- [ ] **Vérifier le générateur de trafic** : `make demo-logs` montre des lignes
      `[seed] … -> HTTP 200` (propre/caviardé) et `-> HTTP 403` (bloqué).

## 2 minutes avant (la scène)

- [ ] **Notifications coupées** (Ne pas déranger / mode présentation).
- [ ] **Police du terminal agrandie** (≥ 18 pt) et zoom navigateur à ~125 %.
- [ ] **Trois onglets** ouverts et positionnés : `8088/governance`, `8088`,
      puis `3000`.
- [ ] **Un terminal** prêt, dans `deploy/demo/`, historique des commandes des
      actes 2 et 3 pré-chargé (flèche haut).
- [ ] **Plan réseau** : tout est local (`localhost`) — aucune dépendance
      Internet pendant la démo une fois les images récupérées.
- [ ] **Reset testé** : `make demo-reset && make demo` a été lancé une fois pour
      confirmer le retour à l'état `s0`.

## Filet de sécurité pendant la démo

- Page figée → **F5** (EventSource se reconnecte seul).
- `curl` en échec → pointer un événement **déjà présent** dans le flux 24/7.
- Grafana lent → revenir à l'onglet `8088` (temps réel) le temps de l'agrégation.
- Échec > 45 s → **doublure** (`asciinema play demo.cast`) ou captures.

## Après

- [ ] `make demo-stop` (conserve les données) ou `make demo-reset` (état propre).
