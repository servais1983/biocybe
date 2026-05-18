# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ;
versioning [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

### Phase 2.3.b : Notifications sortantes Slack / syslog / webhook

#### Ajouté
- **Nouveau package `biocybe.notify`** : transports sortants vers SIEM/SOAR/chat ops.
- **3 transports** :
    - `SlackNotifier` — Incoming Webhook HTTPS, message formaté avec couleur par sévérité, fields auto-extraits du payload, channel/username configurables.
    - `SyslogNotifier` — RFC 5424 UDP ou TCP, facility local0 par défaut, STRUCTURED-DATA avec payload JSON intégré (compatible Splunk, Elastic, QRadar, Sentinel, rsyslog…).
    - `WebhookNotifier` — POST JSON vers URL arbitraire (n8n, Zapier, Cortex XSOAR, scripts custom), headers configurables, refus HTTP non chiffré sauf opt-in.
- **`NotifierManager`** orchestrateur :
    - **Failure isolation** : un notifier qui plante n'empêche pas les autres → on ne perd jamais une alerte critique parce que Slack hiccupe.
    - **Retry exponential backoff** (3 tentatives × 0.5/1/2 s).
    - **Rate limiting** par notifier (60 events/min par défaut, fenêtre glissante) → anti-storm SOC quand un ransomware déclenche 1000 alertes/sec.
    - **Async** via `ThreadPoolExecutor` → la détection n'attend jamais le réseau.
    - **Stats par notifier** : `sent`, `failed`, `rate_limited`, `last_error`, timestamps.
- **`build_from_config(dict)`** : parsing YAML standard avec substitution de variables d'environnement (`${SLACK_WEBHOOK_URL}` etc.). Filtrage par `min_severity` par notifier.
- **Intégration automatique au pipeline** via un **hook isolation** non couplant :
    - `quarantine_file()` → notify `quarantine_created` (warning)
    - `restore_file()` → notify `quarantine_restored` (notice)
    - `FileSystemWatcher` détection real-time → notify `realtime_detection` (warning/error selon sévérité YARA)
    - `TCell._maybe_alert()` → notify `behavioral_anomaly` (warning)
    - Le hook est tolérant aux exceptions : un échec de notification ne casse JAMAIS la quarantaine ni le scan.
- **CLI** :
    - `biocybe notify list [--json]` — voir ce qui est configuré
    - `biocybe notify test [--severity warning] [--message ...]` — envoi sync à tous les notifiers, rapport ok/failed par notifier
- **Daemon** : `cli._build_notifier_manager_from_config(config)` branche tout au démarrage, shutdown propre à l'arrêt.

#### Tests (`tests/test_notify.py` — 19 tests)
- Slack : refuse HTTP non chiffré, payload bien formé, échec HTTP → `NotifyError`
- **Syslog : vrai socket UDP local** dans un thread, valide format RFC 5424 (`<132>1 ts hostname biocybe-test - quarantine_created [sd] msg`), TCP unreachable → `NotifyError`
- Webhook : POST JSON, headers custom, refus scheme invalide
- Manager : failover (notifier cassé n'empêche pas les OK), filtres severity par notifier, rate limit drops bien les overflow
- `build_from_config` : Slack+syslog, substitution `${ENV_VAR}`, skip silencieux des configs invalides
- **Hook isolation end-to-end** : `quarantine_file()` déclenche bien le hook ; un hook qui plante ne casse pas la quarantaine

### Phase 2.3.a : API REST production-ready (intégration SIEM/SOAR)

#### Ajouté
- **Nouveau package `biocybe.api`** : Flask app prête pour la prod, montable par n'importe quel WSGI (waitress / gunicorn / uwsgi).
- **Endpoints REST** :
    - `GET /healthz` — liveness, sans auth (Kubernetes-style)
    - `GET /readyz` — readiness (avec auth)
    - `GET /api/v1/info` — version
    - `POST /api/v1/scan` — scan un chemin, options `quarantine` et `dry_run`
    - `GET /api/v1/quarantine` — liste du manifeste
    - `GET /api/v1/quarantine/<id>` — détail d'une entrée
    - `POST /api/v1/quarantine/<id>/restore` — restauration avec vérification SHA-256
    - `GET /metrics` — exposition Prometheus (registry dédié par instance, pas global → multi-app safe)
- **Auth Bearer token** obligatoire (env `BIOCYBE_API_TOKEN`), comparaison via `hmac.compare_digest` (anti timing attack). Refus de démarrer en prod sans token (`require_auth=True` par défaut).
- **WSGI prod** : `waitress` sur Windows, `gunicorn` sur Linux/macOS via `run_production()`. Pas de Flask dev server en prod.
- **Métriques Prometheus** : `biocybe_scan_total{outcome}`, `biocybe_scan_malicious_total`, `biocybe_quarantine_action_total{action}`, `biocybe_scan_duration_seconds` histogramme, `biocybe_api_requests_total{method,endpoint,status}`, `biocybe_quarantine_size` gauge.
- **CLI** : `biocybe api serve [--host] [--port] [--token] [--no-auth] [--cors-origin] [--workers] [--dev]`. Lazy import de Flask : pas d'erreur si `[web]` pas installé jusqu'à la commande.
- **Codes HTTP propres** : 401 unauthorized, 400 bad_request, 404 not_found, 409 conflict (restore destination occupée, integrity), 410 gone (fichier quarantaine manquant), 500 internal. Toujours JSON.
- **Tests d'intégration réels** (`tests/test_api.py`, 20 tests) : Flask TestClient, vraies opérations (EICAR créé → scan → quarantine → list → get → restore), auth full coverage (sans token, token incorrect, header malformé, token correct), validation Prometheus (compteurs incrémentés après scan), validation lifecycle complet.
- **Démo réelle live** validée localement : waitress + curl → /healthz 200, /api/v1/info 401 sans auth puis 200 avec, /metrics format Prometheus exposition.

#### Corrigé (Dockerfile)
- **CI Docker** : ajout de `load: true` dans `docker/build-push-action@v5` (buildx ne charge pas l'image dans le daemon Docker local par défaut, donc `docker run biocybe:ci-...` échouait avec "image not found" — explication du smoke test rouge sur les 3 derniers pushs).
- Smoke test découpé en steps unitaires pour diagnostic : `inspect image`, `biocybe --help`, `biocybe scan --help`, puis test HTTP complet `api serve` + curl healthz/info/auth.

### Phase 2.2 : Capacités de détection sérieuses

#### Ajouté
- **`biocybe scan --dry-run`** : détecte sans agir, indispensable pour
  évaluation SOC en prod sans risque (Phase 2.2.e).
- **`biocybe quarantine list` / `restore`** : réversibilité totale de
  la quarantaine, avec vérification SHA-256 anti-tampering. Options
  `--no-verify` (forensique), `--keep-manifest` (audit trail),
  `--to PATH` (restauration alternative) (Phase 2.2.e).
- **Real-time filesystem monitoring** : nouveau module
  `biocybe.watcher` qui branche `watchdog` (inotify Linux, FSEvents
  macOS, ReadDirectoryChangesW Windows) sur le pipeline BCell.
  Daemon : flags `--watch`, `--watch-quarantine`, `--watch-dry-run`.
  Architecture 2 threads + débouncing + exclusions anti-boucle (Phase 2.2.a).
- **Threat Intel abuse.ch / MalwareBazaar** : nouveau module
  `biocybe.intel.abusech` avec `MalwareBazaarClient` et
  `update_signatures_from_malwarebazaar()`. CLI : `biocybe intel update
  [--selector time|100|1000]`. Auth via env `ABUSECH_AUTH_KEY`.
  Indexe par sha256+sha1+md5 (Phase 2.2.b).
- **Règles YARA communautaires opt-in** : nouveau module
  `biocybe.intel.rules` qui télécharge et extrait les zipballs GitHub
  de signature-base (Neo23x0/Florian Roth, ~3000 règles APT/ransomware/
  webshells) et yara-rules (YARA-Rules project, ~5000 règles).
  Hardening : limite de taille (50 Mo, anti zip-bomb), validation des
  noms de membres (anti zip-slip), pas d'exécution. Sortie dans
  `rules/yara/community/<source>/` automatiquement picked up par BCell
  via le walk récursif. `verify_source()` compile chaque règle pour
  rapporter le taux de succès. Test réel signature-base : 746 règles
  téléchargées, 733 compilent (98%). CLI : `biocybe intel rules
  list/update/verify` avec `--yes` requis (opt-in explicite) (Phase 2.2.c).
- **Lymphocyte T — détection comportementale ML** : nouveau package
  `biocybe.lymphocytes_t` avec `TCell` (extend `BiologicalCell`),
  `MetricsCollector` (13 features psutil : CPU%, load_1m, mémoire,
  swap, IO disque/réseau en bytes/s, processus running/zombie, threads,
  connexions), `TCellModel` persisté via `joblib`.
  - Cycle de vie : `learning` (collecte buffer) → auto-`armed` quand
    `training_samples` atteints. `disarmed` proprement si modèle
    corrompu (mauvaise version, etc.).
  - IsolationForest 200 arbres + StandardScaler, contamination
    configurable (défaut 0.01).
  - Explicabilité : chaque alerte porte les 5 features avec le plus
    grand |z-score| vs baseline (mean+std mémorisés à l'entraînement).
    `human_summary()` lisible : `cpu_percent=98.5 (z=+4.5σ)`.
  - Anti-storm : cooldown 60 s par défaut entre 2 alertes.
  - Intégration bus : envoie `alert_anomaly` que `BCell._handle_anomaly_alert`
    (Phase 1) consomme déjà pour déclencher un scan signature ciblé.
  - sklearn/numpy/joblib en imports lazy : pas de breakage si l'extra
    `[ml]` n'est pas installé. Message d'erreur clair (`MLDepsMissing`).
  - CLI : `biocybe tcell train [--duration]/status/evaluate`.
  - Test d'intégration RÉEL : entraîne sur 120 vraies mesures psutil,
    puis injecte une charge CPU (4 threads burner), vérifie que (1) le
    score sous charge est < score calme - 0.05 et (2) cpu_percent
    apparaît dans le top features avec z-score positif. Pas de
    fixture synthétique (Phase 2.2.d).

#### Corrigé
- **`rules/yara/ransomware.yar`** : remplace `pe.sections[].entropy`
  (requiert build YARA custom) par `math.entropy(pe.sections[].
  raw_data_offset, raw_data_size)` (module math standard). Les 6 règles
  ransomware sont désormais actives (Phase 2.2.f).
- **Boucle de re-quarantaine** : `scan_path` et `FileSystemWatcher`
  excluent par défaut `quarantine/`, `db/`, `logs/`, `models/`, `.git/`,
  `__pycache__/`, `.venv/`, `venv/`, `node_modules/`.
- **JSON serialization** : `BCell.check_file_yara` encode désormais
  `matched_data` en hex au lieu de bytes bruts, permettant
  `--json` et l'intégration SIEM.
- **YARA 4.3+ compat** : `StringMatch.instances[]` au lieu de
  `.offset`/`.data` direct.

#### Tests
27 → 34 tests verts (+ 6 watcher + 7 intel + correctifs).


---

## [0.2.0] — 2026-05-17

### Phase 2.1 : Distribution sans friction (cible SOC / MSSP)

#### Ajouté
- **Packaging moderne** : migration `setup.py` → `pyproject.toml` PEP 621.
  - Extras `[ml]`, `[web]`, `[fileanalysis]`, `[network]`, `[dev]`, `[soc]`, `[all]`.
  - Entry-point `biocybe = biocybe.cli:main` → commande système après `pip install -e .`.
  - Support `python -m biocybe` via `__main__.py`.
- **Image Docker** : `Dockerfile` multi-stage (builder + runtime python:slim),
  utilisateur non-root, healthcheck, `tini` PID 1, libyara système.
- **docker-compose.yml** : daemon limité en ressources (1 CPU / 512 Mo),
  read-only FS, `no-new-privileges`, `cap_drop ALL`, volumes nommés
  pour quarantaine/db/logs. Service `scanner` profil `tools` pour scans ad-hoc.
- **CI GitHub Actions** : matrix `ubuntu / windows / macos` × `python 3.10–3.13` ;
  jobs séparés `lint` (ruff), `test` (pytest + couverture), `security`
  (pip-audit), `docker` (build + smoke test).
- **Pre-commit** : ruff (lint + format), bandit (sécurité), hygiène fichiers.
- `CHANGELOG.md` (ce fichier).

#### Modifié — refactor structurel
- **`src/<modules>/` → `src/biocybe/<modules>/`** : passage au src-layout
  standard. Le package distribué s'appelle `biocybe` (import propre :
  `from biocybe.scanner import scan_path`).
- **`biocybe.py` racine supprimé** : remplacé par `src/biocybe/cli.py`.
  Conflit de nom résolu (un .py au root masquait le package).
- `conftest.py` racine : ajout de `src/` à `sys.path` pour tests sans install.
- Imports `from src.*` → `from biocybe.*` dans tests + ex-`biocybe.py`.
- `requirements.txt` réduit aux dépendances core ; source de vérité = `pyproject.toml`.

#### Supprimé
- `setup.py` (remplacé par `pyproject.toml`).
- `biocybe.py` racine (remplacé par entry-point + `__main__.py`).

---

## [0.1.0] — 2026-05-17

### Phase 1 : MVP démontrable

#### Ajouté
- **CLI `scan`** : `biocybe scan <path> [--quarantine] [--no-recursive] [--json]`.
  Exit code 1 si menace détectée.
- **`src/scanner.py`** : module CLI réutilisable (`scan_path`, `sync_yara_rules`,
  `format_report`, dataclass `FileVerdict`).
- **Quarantaine fonctionnelle** (`src/isolation/__init__.py`) :
  déplacement de fichier + manifeste JSON avec hash SHA-256, raison,
  horodatage, cellule détectrice. `chmod 600` best-effort.
- **Règle YARA EICAR** (`rules/yara/eicar.yar`) : standard de test industriel.
- **Tests d'intégration EICAR** (`tests/test_scan_eicar.py`) : 3 tests
  end-to-end (détection + quarantaine + manifeste, faux négatif sur fichier
  propre, sync règles idempotente).

#### Corrigé
- **Compilation YARA tolérante** : si un fichier de règles est cassé
  (ex. `ransomware.yar` utilise `pe.sections[0].entropy` non supporté par
  certains builds yara-python), le loader retombe sur compilation
  fichier par fichier et ne désactive plus la détection globale.
- **Compat yara-python ≥4.3** : `StringMatch.offset` n'existe plus,
  branche `.instances[]` ajoutée dans `BCell.check_file_yara`.

#### Modifié
- `README.md` : ajout en tête d'une section Quickstart (ce qui marche
  aujourd'hui) + roadmap par phases.
- `.gitignore` : exclusion des artefacts runtime
  (`quarantine/`, `db/`, `logs/`, `demo_samples/`).

---

## [0.0.1] — 2026-05-17

### Phase 0 : Déverrouillage

#### Corrigé
- **`src/__init__.py`** : suppression des imports eager de modules non
  implémentés (`utils` inexistant ; `isolation`, `neutralization` vides)
  qui empêchaient `python biocybe.py` de démarrer
  (`ImportError: cannot import name 'utils' from 'src'`).
- **`src/macrophages/macrophage.py`** : import absolu `from biocybe_core`
  remplacé par relatif `from ..biocybe_core` (sinon plante hors PYTHONPATH).
- **`biocybe.py`** : force UTF-8 sur stdout/stderr (cp1252 Windows
  ne pouvait pas imprimer le logo ASCII ni les accents des logs).

#### Ajouté
- **`src/neutralization/__init__.py`** : stub explicite qui lève
  `NotImplementedError` au lieu d'une fonction silencieusement absente.
- **`tests/test_smoke.py`** : 8 smoke tests anti-régression structurelle
  (imports, classes accessibles, core instanciable, sérialisation `CellMessage`).
- **`CLAUDE.md`** : mémoire projet pour reprise rapide en session future.

[Unreleased]: https://github.com/servais1983/biocybe/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/servais1983/biocybe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/servais1983/biocybe/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/servais1983/biocybe/releases/tag/v0.0.1
