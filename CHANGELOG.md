# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ;
versioning [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

### Phase 2.2 (en cours) : Capacités de détection sérieuses

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
