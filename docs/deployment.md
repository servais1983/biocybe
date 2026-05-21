# Guide de déploiement BioCybe

Guide consolidé pour déployer BioCybe en production. Couvre les trois
cibles supportées (systemd, Docker/Compose, Kubernetes), la
configuration, la sécurité, l'observabilité et l'exploitation courante.

> **Cible** : SOC d'entreprise / MSSP. Linux prioritaire (psutil +
> watchdog y sont mieux supportés). Windows/macOS fonctionnent pour le
> dev et les postes.

---

## 1. Modèle de déploiement

BioCybe se déploie en **deux process complémentaires** :

| Process | Rôle | Endpoint |
|---|---|---|
| **Daemon** (`biocybe` sans sous-commande) | surveillance temps-réel : watcher, network monitor, cellules, mémoire, régénération | `:9091/metrics` (opt-in) |
| **API** (`biocybe api serve`) | intégration SIEM/SOAR : scan à la demande, gestion quarantaine | `:8080` (`/healthz`, `/readyz`, `/api/v1/*`, `/metrics`) |

Les deux partagent les volumes `db/`, `quarantine/`, `logs/`. Un
**CronJob/timer** rafraîchit les feeds threat intel (voir §6).

---

## 2. Installation

### Via pip (VM / bare-metal)

```bash
git clone https://github.com/servais1983/biocybe.git
cd biocybe
python -m venv /opt/biocybe && source /opt/biocybe/bin/activate
pip install -e ".[soc]"     # profil SOC complet (ML + web + fileanalysis + network)
biocybe --help
```

Profils d'extras : `.` (core), `.[ml]`, `.[web]`, `.[fileanalysis]`,
`.[network]`, `.[soc]`, `.[all]`. L'API et le dashboard exigent `[web]`.

### Via Docker

```bash
# Image core (scan + daemon)
docker build -t biocybe:latest .
# Image avec API/dashboard
docker build --build-arg BIOCYBE_EXTRAS=web -t biocybe:web .
```

L'image est multi-stage, non-root (uid 10001), avec tini en PID 1, le
cache YARA précompilé (démarrage ~200 ms) et des labels OCI de provenance.

---

## 3. Configuration

Source de vérité : `config/biocybe.yaml`. Sections clés :

| Section | Rôle | Défaut prod conseillé |
|---|---|---|
| `core` | cellules, dossiers surveillés | `watch_directories` selon le SI |
| `audit` | log immuable SHA-256 | `enabled: true` (compliance) |
| `notify` | Slack / syslog / webhook | au moins syslog vers le SIEM |
| `netmon` | surveillance connexions sortantes | `enabled: true`, `interval: 5` |
| `memory` | mémoire immunitaire (suppression FP) | `enabled: true` |
| `regeneration` | auto-régénération anti-ransomware | `enabled: true`, `auto_heal` selon politique |
| `metrics` | endpoint Prometheus du daemon | `daemon_enabled: true` |

**Secrets — jamais dans le YAML ni le repo** :

```bash
export BIOCYBE_API_TOKEN="$(openssl rand -hex 32)"      # auth API
export BIOCYBE_QUARANTINE_KEY="$(biocybe crypto generate-key)"  # chiffrement quarantaine
export ABUSECH_AUTH_KEY="..."                            # feeds threat intel
```

---

## 4. Déploiement par cible

### A. systemd (VM / bare-metal)

Daemon as-a-service + timer de refresh intel (templates dans
`deploy/refresh/`). Exemple d'unité daemon :

```ini
# /etc/systemd/system/biocybe.service
[Unit]
Description=BioCybe daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=biocybe
Group=biocybe
WorkingDirectory=/opt/biocybe
EnvironmentFile=/etc/biocybe/biocybe.env       # secrets en 0600
ExecStart=/opt/biocybe/.venv/bin/biocybe --config /etc/biocybe/biocybe.yaml \
          --watch /var/www --watch /etc --netmon --metrics-port 9091
Restart=on-failure
# Durcissement
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/biocybe/db /opt/biocybe/quarantine /opt/biocybe/logs
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now biocybe.service
# + le refresh intel
sudo cp deploy/refresh/biocybe-intel-refresh.{service,timer} /etc/systemd/system/
sudo systemctl enable --now biocybe-intel-refresh.timer
```

### B. Docker Compose

`docker-compose.yml` (fourni, déjà durci : `read_only`, `tmpfs`,
`cap_drop: ALL`, `no-new-privileges`, limites CPU/mémoire) :

```bash
docker compose up -d                              # daemon
docker compose run --rm scanner scan /samples     # scan ad-hoc
docker compose logs -f biocybe
```

### C. Kubernetes

Manifestes durcis dans `deploy/k8s/` (Deployment API + Service + PVC +
NetworkPolicy) et `deploy/refresh/` (CronJob intel). Voir
`deploy/k8s/README.md` pour le détail.

```bash
kubectl create secret generic biocybe-api \
  --from-literal=api-token="$(openssl rand -hex 32)" \
  --from-literal=quarantine-key="$(openssl rand -base64 32)"
kubectl create secret generic biocybe-intel --from-literal=abusech-auth-key=VOTRE_CLE
kubectl apply -f deploy/k8s/biocybe-api.yaml
kubectl apply -f deploy/refresh/biocybe-intel-refresh-cronjob.yaml
```

Durcissement appliqué : `runAsNonRoot`, `readOnlyRootFilesystem`,
`drop ALL`, `seccompProfile: RuntimeDefault`, limites cgroups, probes
`/healthz` (liveness) + `/readyz` (readiness, 4 checks réels).

---

## 5. Mise en service — séquence recommandée

```bash
# 1. Feeds threat intel (sinon netmon/sentinelle sont vides)
biocybe intel update --source all
biocybe intel rules update --source signature-base --yes --verify   # +733 règles YARA

# 2. Baseline d'intégrité pour l'auto-régénération (anti-ransomware)
biocybe regen baseline /var/www /etc/nginx /home/shared

# 3. Entraîner le lymphocyte T (détection comportementale) — optionnel
biocybe tcell train --duration 1800

# 4. Évaluation SANS risque avant d'activer les actions
biocybe scan /data --dry-run --network-scan          # détecte sans agir
biocybe --watch /var/www --watch-dry-run             # watcher en simulation

# 5. Activation progressive (config) :
#    netmon.enabled: true → memory.enabled: true →
#    regeneration.enabled: true (auto_heal: false d'abord) →
#    watch-quarantine, puis regeneration.auto_heal: true
```

> **Principe SOC** : toujours valider en `--dry-run` / `auto_heal:false`
> avant d'activer les actions destructives (quarantaine, kill NK,
> restauration auto). Voir aussi `scripts/validate_*.py`.

---

## 6. Refresh des feeds threat intel

Le threat intel est périssable. Planifier `biocybe intel update --source all`
toutes les 6h (templates systemd/k8s/cron dans `deploy/refresh/`) et
surveiller la fraîcheur :

```bash
biocybe intel age                  # exit 1 si un feed > 48h (healthcheck)
```

Le daemon recharge automatiquement les IOCs après un refresh (sans
redémarrage). Voir `deploy/refresh/README.md`.

---

## 7. Observabilité

### Prometheus — deux endpoints

```bash
curl http://api:8080/metrics       # scan, quarantine, latence, feed age, mémoire
curl http://daemon:9091/metrics    # watcher, NK, netmon, mémoire, régénération, uptime
```

Métriques clés à grapher :
- `biocybe_intel_feed_age_seconds{source}` — alerter si > 86400
- `biocybe_memory_disposition_total{disposition="confirmed_benign"}` — FP supprimés (réduction de bruit)
- `biocybe_watcher_regen_healed` — fichiers restaurés après ransomware
- `biocybe_watcher_detections` — détections temps-réel

Règles Alertmanager d'exemple dans `deploy/refresh/README.md`.

### Dashboard SOC

```bash
biocybe dashboard serve --host 0.0.0.0 --port 8050
```

UI de triage (lecture seule) : KPI + onglets Quarantaine / Audit
(intégrité chaîne SHA-256 en live) / Threat Intel / Mémoire. À placer
derrière un reverse-proxy authentifié.

### Audit immuable

```bash
biocybe audit show --limit 50
biocybe audit verify               # vérifie la chaîne SHA-256 (anti-tampering)
```

---

## 8. Exploitation courante

```bash
# Quarantaine
biocybe quarantine list
biocybe quarantine restore <id>                # avec vérification SHA-256

# Mémoire : marquer un faux positif (ne réalertera plus jamais)
biocybe memory mark <sha256> --type sha256 --as benign

# Réponse active (cellules NK) — dry-run par défaut
biocybe nk respond --pid <PID> --action suspend          # gèle (réversible)
biocybe nk respond --pid <PID> --action kill --allow-kill --execute

# Régénération après incident
biocybe regen drift                            # qu'est-ce qui a changé ?
biocybe regen heal --execute                   # restaure depuis la baseline

# Lookup IOC
biocybe intel lookup <hash|ip|hostname|url>
```

---

## 9. Sécurité du déploiement

- **Secrets** via env / secret manager / K8s Secret — jamais en clair.
- **`/metrics` et l'API** : protéger par NetworkPolicy / mTLS / reverse-proxy
  (l'API a un Bearer token ; `/metrics` et `/healthz` n'en ont pas par design).
- **Quarantaine chiffrée** (`BIOCYBE_QUARANTINE_KEY`) : sans la clé, les
  fichiers en quarantaine sont irrécupérables, y compris pour root.
- **Actions destructives** opt-in et graduées : `--dry-run`, `auto_heal:false`,
  `allow_kill:false` par défaut.
- **Supply chain** : SBOM (SPDX + CycloneDX) + scan grype générés à chaque
  build CI (artefacts archivés 30j). Voir `SECURITY.md`.

---

## 10. Validation avant release

Les scripts `scripts/validate_*.py` trouvent de vrais bugs en conditions
réelles. À lancer avant chaque release majeure :

```bash
python scripts/validate_scan.py             # TP/FP sur IOCs réels
python scripts/validate_daemon.py --duration 120   # fuite mémoire / CPU
python scripts/validate_api_load.py         # 1000 req, p99 < 2s
python scripts/validate_watcher_batch.py    # 1000 fichiers en rafale
python scripts/validate_cache_speedup.py    # cold vs warm start
python scripts/validate_intel_pipeline.py   # pipeline E2E (35 checks réels)
```

Le pipeline E2E tourne aussi en CI (job `pipeline-validation`).

---

## Récapitulatif des ports

| Port | Service | Auth |
|---|---|---|
| 8080 | API REST (`/api/v1/*`) | Bearer token |
| 8080 | `/healthz`, `/readyz`, `/metrics` | non (par design) |
| 8050 | Dashboard SOC | reverse-proxy |
| 9091 | `/metrics` du daemon | non (NetworkPolicy) |
