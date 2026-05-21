# Refresh automatique des feeds threat intel (Phase 3.g)

Le threat intel est une denrée périssable : un domaine flaggé il y a
6 mois a probablement été nettoyé ou repris par un service légitime.
Sans refresh régulier **et monitoring de la fraîcheur**, un cron qui
casse silencieusement transforme BioCybe en passoire sans alerte.

Ce dossier fournit des templates de déploiement prêts à l'emploi pour
les trois ordonnanceurs les plus courants, plus le monitoring associé.

## Principe

```
┌────────────────┐   toutes les 6h    ┌──────────────────────┐
│  ordonnanceur  │ ─────────────────► │ biocybe intel update │
│ (systemd/cron/ │                    │      --source all    │
│   k8s CronJob) │                    └──────────┬───────────┘
└────────────────┘                               │ écrit
                                                  ▼
                                       db/signatures/<feed>/
                                       └─ last_update.txt (timestamp)
                                                  │
              ┌───────────────────────────────────┼───────────────────┐
              ▼                                   ▼                     ▼
   biocybe intel age                  /metrics (Prometheus)     /readyz (warning)
   (exit 1 si stale)         biocybe_intel_feed_age_seconds   intel_feeds_fresh
```

## Fichiers

| Fichier | Pour |
|---|---|
| `biocybe-intel-refresh.service` + `.timer` | **systemd** (VM, bare-metal, Linux) |
| `biocybe-intel-refresh-cronjob.yaml` | **Kubernetes** CronJob |
| `crontab.example` | **cron** classique (legacy, conteneurs simples) |

## Installation systemd (recommandé sur VM/bare-metal)

```bash
sudo cp biocybe-intel-refresh.service /etc/systemd/system/
sudo cp biocybe-intel-refresh.timer   /etc/systemd/system/

# Clé abuse.ch (mode 0600)
sudo install -m 0600 /dev/stdin /etc/biocybe/intel.env <<'EOF'
ABUSECH_AUTH_KEY=votre_cle
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now biocybe-intel-refresh.timer

# Vérifs
systemctl list-timers biocybe-intel-refresh.timer
sudo systemctl start biocybe-intel-refresh.service   # run manuel immédiat
journalctl -u biocybe-intel-refresh.service -n 50
```

### Alerter sur échec (systemd)

Crée `/etc/systemd/system/biocybe-intel-refresh.service.d/onfailure.conf` :

```ini
[Unit]
OnFailure=biocybe-alert@%n.service
```

…et un service `biocybe-alert@.service` qui envoie un mail/webhook.

## Installation Kubernetes

```bash
# Secret avec la clé abuse.ch
kubectl create secret generic biocybe-intel \
  --from-literal=abusech-auth-key=VOTRE_CLE

# Le PVC db/signatures doit être RWX et monté sur les pods scanner
kubectl apply -f biocybe-intel-refresh-cronjob.yaml

# Vérifs
kubectl get cronjob biocybe-intel-refresh
kubectl create job --from=cronjob/biocybe-intel-refresh refresh-now  # run manuel
kubectl logs job/refresh-now
```

## Monitoring de la fraîcheur

### Prometheus

L'API BioCybe expose au scrape `/metrics` (Phase 3.g) :

```
biocybe_intel_feed_age_seconds{source="malwarebazaar"} 3421
biocybe_intel_feed_age_seconds{source="urlhaus"}       3500
biocybe_intel_feed_age_seconds{source="threatfox"}     3600
biocybe_intel_feed_iocs_total{source="threatfox"}      18742
biocybe_intel_feed_stale{source="urlhaus"}             0      # 1=stale, -1=jamais récupéré
```

Règle d'alerte Alertmanager suggérée :

```yaml
groups:
  - name: biocybe-intel
    rules:
      - alert: BioCybeIntelFeedStale
        expr: biocybe_intel_feed_age_seconds > 86400
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Feed threat intel {{ $labels.source }} stale (> 24h)"
          description: "Le refresh automatique a peut-être cassé. Vérifier le CronJob/timer."
      - alert: BioCybeIntelFeedNeverFetched
        expr: biocybe_intel_feed_stale == -1
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Feed {{ $labels.source }} jamais récupéré"
```

### CLI (cron / healthcheck)

```bash
biocybe intel age                      # tableau lisible, exit 1 si un feed stale
biocybe intel age --json               # pour parsing machine
biocybe intel age --stale-after 86400  # seuil custom (ici 24h)
```

Exit codes : `0` tous frais · `1` au moins un stale · `2` aucun feed jamais récupéré.

### /readyz

Le check `intel_feeds_fresh` apparaît dans `warnings` de `/readyz`
(jamais bloquant — un feed stale ne sort pas le pod du load balancer,
le scan YARA/signature continue de fonctionner).
