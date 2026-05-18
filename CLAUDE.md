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
- `src/biocybe/intel/abusech.py` — feed MalwareBazaar
- `src/biocybe/intel/rules.py` — import opt-in règles YARA communautaires
- `src/biocybe/api/app.py` — **API REST Flask production-ready** (Bearer auth, /healthz, /api/v1/scan, /api/v1/quarantine/*, /metrics)
- `src/biocybe/notify/` — **NotifierManager** (Slack / syslog RFC 5424 / webhook HTTP) avec failover, retry, rate limit, hook isolation automatique
- `src/biocybe/audit.py` — **Audit log immuable** (JSONL append-only + chaîne SHA-256 anti-tampering)
- `src/biocybe/crypto.py` — **Quarantaine chiffrée AES-256-GCM** (format BCE1, env `BIOCYBE_QUARANTINE_KEY`)
- `src/biocybe/cli.py` — point d'entrée `biocybe`, sous-commandes : `scan`, `quarantine list/restore`, `intel update/rules`, `tcell train/status/evaluate`, `api serve`, `notify list/test`, `audit show/verify`, `crypto generate-key`
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
- Cellules NK (action sur les processus malveillants détectés)
- Mémoire immunitaire persistante (apprentissage cross-session)
- Modules « épigénétique / coévolutif »
- Tableau de bord web (deps Flask/Dash listées mais aucun code — Phase 2.3)

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
| 2.2.b — Threat intel | 🚧 partiel | MalwareBazaar ✅. À faire : URLhaus, ThreatFox |
| 2.2.c — Règles YARA communautaires | ✅ | signature-base + yara-rules ; 733/746 règles compilent en réel |
| 2.2.d — Lymphocyte T (ML) | ✅ | IsolationForest sur 13 features psutil, persistence joblib, explication z-scores, intégration bus |
| 2.2.e — `--dry-run` + restore | ✅ | Réversibilité totale, exigence SOC pour éval prod |
| 2.2.f — Fix `ransomware.yar` | ✅ | math.entropy au lieu de pe.entropy, 6 règles actives |
| **2.3.a — API REST + Prometheus** | ✅ | Flask + waitress/gunicorn, Bearer token, /healthz /api/v1/scan /quarantine /metrics, 20 tests, 15/15 CI verts |
| **2.3.b — Notifications sortantes** | ✅ | NotifierManager (failover/retry/rate-limit), Slack + syslog RFC 5424 + webhook HTTP générique, hook automatique sur quarantaine/RT/anomalie, 19 tests |
| **2.4.a — Audit log immuable** | ✅ | JSONL append-only + chaîne SHA-256, `verify` détecte modification/suppression/swap, intégré quarantine/restore, 12 tests |
| **2.4.b — Quarantaine chiffrée AES-256-GCM** | ✅ | Format BCE1, AAD=SHA-256 du clair, env `BIOCYBE_QUARANTINE_KEY`, CLI `crypto generate-key`, 17 tests (tampering ciphertext/AAD/clé tous détectés) |
| **2.4.c — Supply chain (SBOM + scan)** | ✅ | syft SBOM SPDX+CycloneDX par build, grype scan vulns, pip-audit strict, SECURITY.md complet (modèle menace, conformités, signalement) |
| 2.3.c — Dashboard Dash | ⏳ | UI visuelle pour triage SOC |
| 2.4 — Hardening production | ⏳ | Quarantaine chiffrée AES-GCM, image distroless + SBOM, limites ressources, benchmark MalwareBazaar public |
| 3 — Adaptabilité (R&D) | ⏳ | Mémoire immunitaire persistante, swarm P2P, modules expérimentaux |

### Ce qui a été livré en Phase 1
- `src/scanner.py` : `scan_path()`, `sync_yara_rules()`, `format_report()`, dataclass `FileVerdict`
- `src/isolation/__init__.py` : `quarantine_file()`, `list_quarantine()`, manifeste JSON, dataclass `QuarantineEntry`
- `rules/yara/eicar.yar` : règle de référence pour tests
- `biocybe.py` : sous-commande `scan PATH` avec `--quarantine`, `--no-recursive`, `--json` ; exit code 1 si menace
- `tests/test_scan_eicar.py` : 3 tests d'intégration (détection, faux positif, sync)
- `.gitignore` : exclusion des artefacts runtime

## 7. Pièges connus / dette technique

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
