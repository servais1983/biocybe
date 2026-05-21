# CLAUDE.md — Mémoire projet BioCybe

> Ce fichier est lu par Claude au début de chaque session. Il contient le minimum
> nécessaire pour reprendre le travail sans relire tout le code. Garde-le concis :
> les décisions et conventions, pas la doc utilisateur (qui est dans `README.md`).

## 1. Ce qu'est BioCybe (en 3 lignes)

Système de cyberdéfense open-source bio-inspiré. Métaphore du système immunitaire :
chaque type de cellule (macrophage, lymphocyte B/T, cellule NK, mémoire) est un
module Python qui communique avec les autres via un bus de messages (`CellMessage`).
Objectif final : alternative transparente, modulaire et explicable aux EDR fermés.

## 2. État réel du code (mai 2026 — Phase 2.2 en cours)

### Implémenté et intégré au pipeline (Phase 2.3)
- `src/biocybe/biocybe_core/core.py` — `BioCybeCore`, `BiologicalCell`, `CellMessage` (bus pub/sub entre cellules)
- `src/biocybe/macrophages/macrophage.py` — monitoring système via `psutil`
- `src/biocybe/lymphocytes_b/b_cell.py` — détection par signatures (hash + YARA), `SignatureDatabase`
- `src/biocybe/lymphocytes_t/t_cell.py` — détection comportementale ML (IsolationForest)
- `src/biocybe/scanner.py` — pipeline scan-quarantaine-rapport
- `src/biocybe/isolation/` — quarantaine + restore avec vérif SHA-256
- `src/biocybe/watcher.py` — real-time monitoring (watchdog)
- `src/biocybe/intel/abusech.py` — feed MalwareBazaar (hashes)
- `src/biocybe/intel/urlhaus.py` — feed URLhaus (URLs malveillantes, CSV public)
- `src/biocybe/intel/threatfox.py` — feed ThreatFox (IOCs structurés C2/payload, Auth-Key)
- `src/biocybe/intel/ioc_lookup.py` — IOCLookup en mémoire (Phase 3.e), agrège tous les feeds, lookup O(1)
- `src/biocybe/network_sentinel.py` — NetworkSentinel (Phase 3.e), extrait + matche IOCs dans contenu fichiers
- `src/biocybe/network_monitor.py` — NetworkMonitor + HostsBlocker (Phase 3.f) + NetworkMonitorService (Phase 3.h, intégré au daemon avec auto-reload IOCs + audit + notify)
- `src/biocybe/intel/feed_age.py` — mesure âge/staleness des feeds (Phase 3.g), CLI `intel age` + gauges Prometheus
- `deploy/refresh/` — templates refresh auto (systemd .service+.timer, k8s CronJob, crontab) + monitoring
- `deploy/k8s/biocybe-api.yaml` — déploiement K8s durci (securityContext complet, probes /healthz+/readyz, limites cgroups, NetworkPolicy, Secret)
- `src/biocybe/metrics_daemon.py` — endpoint Prometheus du daemon (collecteur custom live : watcher/NK/netmon/mémoire), `--metrics-port` ou `config.metrics.daemon_enabled`
- `src/biocybe/regeneration/healer.py` — **auto-régénération / self-healing** (capacité phare anti-ransomware) : baseline intègre + détection drift + restauration depuis coffre, dry-run/audit/atomique/vérif intégrité. `biocybe regen {baseline,drift,heal,status}`
- `src/biocybe/dashboard/{data,app}.py` — dashboard SOC (Phase 2.3.c), couche données testable + UI Dash, `biocybe dashboard serve`
- `src/biocybe/nk_cells/nk_cell.py` — Cellules NK (réponse active : suspend/terminate/kill + isolation réseau), ULTRA-conservateur (dry-run + protégés + audit), `biocybe nk {respond,resume,status}`
- `src/biocybe/memory/immune_memory.py` — Mémoire immunitaire SQLite (réponse secondaire, suppression FP, apprentissage cross-session), intégrée au scanner + watcher + daemon + dashboard (onglet Mémoire), `biocybe memory {stats,recall,recent,mark,forget}`
- `src/biocybe/intel/rules.py` — import opt-in règles YARA communautaires
- `src/biocybe/api/app.py` — **API REST Flask production-ready** (Bearer auth, /healthz, /api/v1/scan, /api/v1/quarantine/*, /metrics)
- `src/biocybe/notify/` — **NotifierManager** (Slack / syslog RFC 5424 / webhook HTTP) avec failover, retry, rate limit, hook isolation automatique
- `src/biocybe/audit.py` — **Audit log immuable** (JSONL append-only + chaîne SHA-256 anti-tampering)
- `src/biocybe/crypto.py` — **Quarantaine chiffrée AES-256-GCM** (format BCE1, env `BIOCYBE_QUARANTINE_KEY`)
- `src/biocybe/cli.py` — point d'entrée `biocybe`, sous-commandes : `scan` (+`--network-scan`), `quarantine list/restore`, `intel update/rules .../lookup/stats/age`, `netmon scan/watch/block`, `nk respond/resume/status`, `dashboard serve`, `tcell train/status/evaluate`, `api serve`, `notify list/test`, `audit show/verify`, `crypto generate-key` ; daemon flags `--watch/--watch-quarantine/--netmon`
- `rules/yara/ransomware.yar` + `eicar.yar` — 7 règles compilées activement (+ 733 communautaires opt-in)

### Codé mais non encore intégré au pipeline (héritage à recycler)
- `src/biocybe/detection/signature_detector.py`
- `src/biocybe/learning/reinforcement_learning.py`
- `src/biocybe/explainability/{explainer,ethical_framework}.py`
- `src/biocybe/swarm_intelligence/__init__.py`

### Stub explicite (lève `NotImplementedError`)
- `src/isolation/` — quarantaine
- `src/neutralization/` — élimination de menace

### Annoncé dans le README mais **zéro code**
- ~~Lymphocytes T (anomalies sans signature)~~ ✅ livré Phase 2.2.d
- ~~Cellules NK (action sur les processus malveillants détectés)~~ ✅ livré (suspend/kill + garde-fous + audit)
- ~~Mémoire immunitaire persistante (apprentissage cross-session)~~ ✅ livré (SQLite, réponse secondaire, suppression FP)
- Modules « épigénétique / coévolutif »
- ~~Tableau de bord web (deps Flask/Dash listées mais aucun code)~~ ✅ livré Phase 2.3.c

## 3. Commandes utiles

```powershell
# Installation editable (à faire une fois)
pip install -e .                # core
pip install -e ".[soc]"         # profil SOC (ML + web + ...)
pip install -e ".[all]"         # tout + dev

# CLI (après install)
biocybe --help
biocybe scan ./dossier --quarantine
biocybe                          # daemon, Ctrl+C pour stopper

# Sans install (dev local) — nécessite quand même une install une fois
python -m biocybe scan ./dossier

# Tests
python -m pytest tests/ -v

# Lint / format
ruff check src tests
ruff format src tests

# Docker
docker build -t biocybe:latest .
docker compose up -d
```

## 3 bis. Structure du dépôt (à jour Phase 2.1)

```
biocybe/
├── pyproject.toml          # PEP 621, source de vérité des deps
├── requirements.txt        # core seulement (compat / CI rapide)
├── conftest.py             # ajoute src/ à sys.path pour pytest
├── Dockerfile              # multi-stage builder + runtime python:slim
├── docker-compose.yml      # daemon + scanner one-shot
├── .github/workflows/ci.yml  # matrix OS × Python, security, docker
├── .pre-commit-config.yaml
├── CHANGELOG.md            # Keep a Changelog + SemVer
├── CLAUDE.md               # ce fichier
├── README.md
├── config/biocybe.yaml
├── rules/yara/             # règles livrées (eicar, ransomware)
├── docs/
├── src/biocybe/            # LE PACKAGE
│   ├── __init__.py
│   ├── __main__.py         # python -m biocybe
│   ├── cli.py              # main(), entry-point biocybe
│   ├── scanner.py          # scan_path, sync_yara_rules
│   ├── biocybe_core/core.py
│   ├── macrophages/        # implémenté
│   ├── lymphocytes_b/      # implémenté
│   ├── isolation/          # quarantine_file impl + isolate() stub
│   ├── neutralization/     # stub NotImplementedError
│   ├── detection/          # non-intégré au pipeline
│   ├── explainability/     # non-intégré
│   ├── learning/           # non-intégré
│   └── swarm_intelligence/ # non-intégré
└── tests/
    ├── test_smoke.py       # 8 tests anti-régression structurelle
    └── test_scan_eicar.py  # 3 tests intégration end-to-end
```

## 4. Environnement

- **OS de dev** : Windows 11, PowerShell. Tester aussi sous Linux à terme (psutil + watchdog y sont mieux supportés).
- **Python** : 3.13.2 fonctionne. `tensorflow` listé dans requirements.txt est **incompatible** avec 3.13 (à virer ou rendre optionnel quand on touchera au ML).
- **Dépendances installées et validées** : `pyyaml`, `psutil`, `yara-python` (4.5.4, wheel native), `pytest`.
- **Pas encore installées** mais listées : `scikit-learn`, `tensorflow`, `flask`, `dash`, `shap`, `lime`, `scapy`, `watchdog`, etc. Installer à la demande, module par module.

## 5. Conventions et décisions prises

### Imports
- Tous les modules internes utilisent des **imports relatifs** (`from ..biocybe_core import …`), jamais absolus depuis `biocybe_core`. Sinon ça crashe si `src/` n'est pas dans `sys.path`.
- `src/__init__.py` n'importe **rien** de façon eager. Chaque sous-package doit être importé explicitement. Raison : un sous-module non implémenté ou avec dep manquante (TF, yara) ne doit pas casser `import src`.

### Stubs vs vide
- Un module annoncé mais pas codé doit avoir un `__init__.py` qui **lève `NotImplementedError`** avec un message clair. Pas de fonction qui retourne silencieusement `None`, pas de `pass`. Voir `src/isolation/__init__.py` comme référence.

### Encodage Windows
- `biocybe.py` force `sys.stdout/stderr.reconfigure(encoding="utf-8")` en début. Cp1252 par défaut ne peut pas imprimer le logo ASCII ni les accents des logs. **Ne pas retirer**.

### Logs
- Logger racine : `biocybe`. Sous-loggers : `biocybe.core`, `biocybe.macrophage.<name>`, `biocybe.b_cell.<name>`, etc.
- Fichier de log : `biocybe.log` à la racine (ignorer dans `.gitignore` à ajouter).

### Tests
- `tests/test_smoke.py` doit toujours rester vert. Ce sont les tests anti-régression structurelle (imports, classes, stubs). N'y ajoute que des tests qui ne nécessitent aucune dépendance lourde.

## 6. Roadmap (du concept au démontrable)

**Cible utilisateur prioritaire : SOC d'entreprise / MSSP.** Conséquences sur les choix :
API REST non-négociable, déploiement container-first, Linux prio, audit trail strict,
mode detect-only obligatoire pour évaluation en prod sans risque.

| Phase | Statut | Objectif livrable |
|---|---|---|
| 0 — Déverrouillage | ✅ | Le système démarre, 8 smoke tests verts |
| 1 — MVP démontrable | ✅ | CLI `scan` + détection YARA + quarantaine + tests EICAR end-to-end |
| 2.1 — Distribution sans friction | ✅ | `pip install`, Docker, CI multi-OS×Python, pyproject PEP 621, pre-commit, CHANGELOG |
| 2.2.a — Real-time watcher | ✅ | `--watch` daemon, watchdog cross-OS, débouncing, anti-boucle, 6 tests |
| 2.2.b — Threat intel (MalwareBazaar) | ✅ | Hashes malwares depuis abuse.ch |
| 2.2.c — Règles YARA communautaires | ✅ | signature-base + yara-rules ; 733/746 règles compilent en réel |
| 2.2.d — Lymphocyte T (ML) | ✅ | IsolationForest sur 13 features psutil, persistence joblib, explication z-scores, intégration bus |
| 2.2.e — `--dry-run` + restore | ✅ | Réversibilité totale, exigence SOC pour éval prod |
| 2.2.f — Fix `ransomware.yar` | ✅ | math.entropy au lieu de pe.entropy, 6 règles actives |
| **2.3.a — API REST + Prometheus** | ✅ | Flask + waitress/gunicorn, Bearer token, /healthz /api/v1/scan /quarantine /metrics, 20 tests, 15/15 CI verts |
| **2.3.b — Notifications sortantes** | ✅ | NotifierManager (failover/retry/rate-limit), Slack + syslog RFC 5424 + webhook HTTP générique, hook automatique sur quarantaine/RT/anomalie, 19 tests |
| **2.4.a — Audit log immuable** | ✅ | JSONL append-only + chaîne SHA-256, `verify` détecte modification/suppression/swap, intégré quarantine/restore, 12 tests |
| **2.4.b — Quarantaine chiffrée AES-256-GCM** | ✅ | Format BCE1, AAD=SHA-256 du clair, env `BIOCYBE_QUARANTINE_KEY`, CLI `crypto generate-key`, 17 tests (tampering ciphertext/AAD/clé tous détectés) |
| **2.4.c — Supply chain (SBOM + scan)** | ✅ | syft SBOM SPDX+CycloneDX par build, grype scan vulns, pip-audit strict, SECURITY.md complet (modèle menace, conformités, signalement) |
| **3.a — Cache compilation YARA** | ✅ | `compiled.yarc` invalidé par fingerprint SHA-256 (yara_version + sorted(path/size/mtime)). Cold 311s → warm 0.19s, speedup x1626 mesuré (748 règles, Windows + Defender) |
| **3.b — Pré-compile cache au build** | ✅ | CLI `biocybe intel rules build-cache` + intégration `Dockerfile` runtime stage. Image démarre en ~200 ms même au 1er run |
| **3.c — K8s readiness probe réel** | ✅ | `/readyz` (no auth, K8s-compatible) avec 4 checks réels : `quarantine_dir`, `rules_yara_compilable`, `metrics`, `auth` (≥16 chars). HTTP 200/503 + diagnostic JSON |
| **3.d — Threat intel multi-source** | ✅ | URLhaus (CSV public, URLs+hostnames) + ThreatFox (JSON Auth-Key, IOCs structurés). CLI `intel update --source {malwarebazaar,urlhaus,threatfox,all}`. Index `by_type/{hash,url,domain,ip}.json` pour lookup O(1). 16 tests |
| **3.e — Sentinelle réseau IOC-aware** | ✅ | `IOCLookup` (en mémoire, multi-feeds, parent-domain fallback, merge keep-best). `NetworkSentinel` (regex ASCII anti-binaire, denylist 30+ hosts, dédup, cap 50MB). Intégré scanner `--network-scan`. CLI `intel lookup <value>` + `intel stats`. 23 tests |
| **3.f — Surveillance live + sinkhole DNS** | ✅ | `NetworkMonitor` (polling psutil.net_connections, cross-OS, rate-limit anti-storm, filtre IPs locales, callback on_match, reverse-DNS opt). `HostsBlocker` (sinkhole DNS, écriture atomique, backup, validation hostnames, cap 50k). CLI `netmon {scan,watch}` + `netmon block {apply,clear,status}`. 21 tests |
| **3.g — Refresh auto + monitoring fraîcheur** | ✅ | `feed_age` (âge/staleness/IOC count par source). CLI `intel age` (exit 0/1/2). Gauges Prometheus `biocybe_intel_feed_age_seconds`/`_iocs_total`/`_stale`. Check `/readyz` non bloquant. Templates `deploy/refresh/` (systemd/k8s/cron + Alertmanager). 11 tests |
| **2.3.c — Dashboard SOC (Dash)** | ✅ | Couche données découplée+testable (`dashboard/data.py`) + UI Dash dark (`dashboard/app.py`). Cartes KPI + onglets Quarantaine/Audit/Intel, vérif chaîne audit live, charts Plotly, auto-refresh, servi waitress, lecture seule. CLI `dashboard serve`. 11 tests |
| **3.h — Daemon unifié (netmon live)** | ✅ | `NetworkMonitorService` (monitor + auto-reload IOCs via fingerprint last_update). Intégré `cmd_daemon` : `on_match` → audit `network_ioc_detected` + notify (critical si conf≥90). Flags `--netmon`/`--netmon-interval`, config `netmon.*`. Combinable avec `--watch`. 9 tests |
| **Cellules NK — réponse active** | ✅ | `NKCell` suspend/terminate/kill + isolation réseau. Garde-fous : désactivée+dry-run défaut, process protégés, seuil confiance, anti-PID-recycling, rate-limit, audit. CLI `nk {respond,resume,status}` + auto-respond opt-in sur netmon. 22 tests + smoke test réel (suspend/resume/kill d'un vrai process) |
| **Validation E2E intel** | ✅ | `scripts/validate_intel_pipeline.py` 35 checks réels (vraie connexion socket), IOCs RFC 5737/2606, 0 mock métier |
| **Mémoire immunitaire** | ✅ | `ImmuneMemory` SQLite : recall instantané (réponse secondaire), suppression FP confirmés, renforcement confiance récurrence, persistance cross-session. Intégrée scanner. CLI `memory {stats,recall,recent,mark,forget}`. 16 tests + smoke réel |
| 3 — Adaptabilité (R&D) | ⏳ | Mémoire immunitaire persistante, swarm P2P, modules expérimentaux |

### Ce qui a été livré en Phase 1
- `src/scanner.py` : `scan_path()`, `sync_yara_rules()`, `format_report()`, dataclass `FileVerdict`
- `src/isolation/__init__.py` : `quarantine_file()`, `list_quarantine()`, manifeste JSON, dataclass `QuarantineEntry`
- `rules/yara/eicar.yar` : règle de référence pour tests
- `biocybe.py` : sous-commande `scan PATH` avec `--quarantine`, `--no-recursive`, `--json` ; exit code 1 si menace
- `tests/test_scan_eicar.py` : 3 tests d'intégration (détection, faux positif, sync)
- `.gitignore` : exclusion des artefacts runtime

## 6 bis. Scripts de validation prod-grade

`scripts/validate_*.py` — à lancer avant chaque release majeure.
Chacun **trouve de vrais bugs** (la première exécution en a sorti 9
dans les phases 0-2.4 que les tests unitaires n'avaient pas vus).

  - `validate_daemon.py --duration 120` — observe RSS/CPU/erreurs du
    daemon, vérifie pas de fuite, arrêt propre. PASS critères : RSS
    drift < 30%, CPU moyen < 20%, 0 traceback.
  - `validate_scan.py` — crée 8 fichiers (5 IOCs réels signature-base
    + 3 bénins), vérifie 5/5 TP et 0/3 FP. Requiert
    `biocybe intel rules update --source signature-base --yes` au préalable.
  - `validate_api_load.py [--per-endpoint 250] [--concurrency 32]` —
    démarre l'API (waitress), envoie 1000 req mixtes, vérifie 0 erreur
    et p99 < 2s sur scan. Mesure RSS drift.
  - `validate_watcher_batch.py` — 1000 fichiers créés en rafale dans
    le dossier surveillé. Vérifie 100% recall sur IOCs, 0% FP,
    latence p99 < 5s, 0 perte d'événement.
  - `validate_full_stack.py [DAEMON_VALIDATION_DURATION=300]
    [V5_WITH_COMMUNITY=1]` — daemon complet avec cells + watcher +
    auto-quarantine. Injecte des IOCs périodiquement, vérifie
    quarantaine + audit chaîne SHA-256.
  - `validate_cache_speedup.py` — mesure cold/warm startup daemon avec
    les 748 community rules. Critère : warm < 10s (mesure réelle x1626
    speedup grâce au cache `compiled.yarc` ajouté en Phase 3.a).
  - `validate_intel_pipeline.py` — valide le pipeline threat intel
    complet (Phases 3.d→3.h) end-to-end : feeds → IOCLookup → feed_age
    → NetworkSentinel → NetworkMonitor (**vraie connexion socket vers
    1.1.1.1:443 observée par psutil**) → NetworkMonitorService on_match
    (audit immuable + notify) → maybe_reload → DashboardData. IOCs de
    test RFC 5737/2606 uniquement. 35 vérifications, 0 mock de logique
    métier. Critère PASS : 0 FAIL (SKIP toléré sur l'étape réseau si
    offline, jamais masqué).

## 7. Pièges connus / dette technique

- ~~Compilation YARA des 748 règles communautaires prend ~1m15 sur
  Windows + Defender actif~~ ✅ **résolu Phase 3.a** : cache
  `compiled.yarc` invalidé par fingerprint des sources (mtime+size+yara
  version). Cold 311s, warm 0.19s. Mesure x1626 speedup.
- Le daemon ne quarantine pas en mode `--watch` si le watcher n'a pas
  fini de démarrer (compilation YARA en cours). Fix : ne pas signaler
  "Système démarré" avant que `watcher.start()` retourne ; faire
  attendre les producteurs sur un `event.is_set()`.
- `tools/review_code.py` utilise l'API `openai.ChatCompletion.create` **obsolète** (openai>=1.0 a cassé). Et il référence `main.py` qui n'existe pas. À supprimer ou réécrire.
- `src/swarm_intelligence/__init__.py` contient **826 lignes de code métier** dans un `__init__.py`. À refactorer en `src/swarm_intelligence/swarm.py` quand on touchera à ce module.
- `tensorflow` dans `requirements.txt` casse l'install sur Python 3.13. À séparer en `requirements-ml.txt` optionnel.
- Le `setup.py` n'a pas été testé (pas sûr qu'il s'installe en mode editable proprement).
- `config/biocybe.yaml` référence des chemins relatifs (`db/`, `quarantine/`) — le système ne marche que si lancé **depuis la racine du repo**. À normaliser plus tard.
- `rules/yara/ransomware.yar` (ligne 205) utilise `pe.sections[0].entropy` qui requiert un build YARA avec module entropy. Sur yara-python 4.5.4 standard ça **ne compile pas**. Workaround actuel : le loader saute le fichier en mode tolérant. À résoudre proprement : soit retirer la condition entropy, soit imposer un build avec ce module.
- `BCell._scan_file` retournait des erreurs avec yara-python ≥4.3 (`StringMatch` n'a plus `.offset` direct, mais `.instances[]`). **Corrigé** dans `src/lymphocytes_b/b_cell.py` avec branche compat ancienne API.
- Les logs `yara-python` ne sont pas désactivables proprement — bruit normal en dev.

## 8. Préférences utilisateur (à respecter)

- Communication en **français**.
- Le user veut du **concret**, pas de la flatterie. Diagnostic honnête > optimisme.
- Préfère les petites étapes vérifiables aux grands plans abstraits.
- Ne pas réécrire le code existant sans raison : intégrer ce qui est déjà là avant d'ajouter du neuf.
