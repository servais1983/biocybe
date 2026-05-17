# CLAUDE.md — Mémoire projet BioCybe

> Ce fichier est lu par Claude au début de chaque session. Il contient le minimum
> nécessaire pour reprendre le travail sans relire tout le code. Garde-le concis :
> les décisions et conventions, pas la doc utilisateur (qui est dans `README.md`).

## 1. Ce qu'est BioCybe (en 3 lignes)

Système de cyberdéfense open-source bio-inspiré. Métaphore du système immunitaire :
chaque type de cellule (macrophage, lymphocyte B/T, cellule NK, mémoire) est un
module Python qui communique avec les autres via un bus de messages (`CellMessage`).
Objectif final : alternative transparente, modulaire et explicable aux EDR fermés.

## 2. État réel du code (mai 2026)

### Implémenté et fonctionnel
- `src/biocybe_core/core.py` — `BioCybeCore`, `BiologicalCell`, `CellMessage` (bus pub/sub entre cellules)
- `src/macrophages/macrophage.py` — monitoring système via `psutil` (CPU, mémoire, réseau, processus)
- `src/lymphocytes_b/b_cell.py` — détection par signatures (hash + YARA), `SignatureDatabase`
- `src/detection/signature_detector.py`, `src/learning/reinforcement_learning.py`, `src/explainability/{explainer,ethical_framework}.py`, `src/swarm_intelligence/__init__.py` — code substantiel mais **non intégré au pipeline principal** (jamais appelés par `biocybe.py`)
- `rules/yara/ransomware.yar` — vraies règles YARA (237 lignes)
- `biocybe.py` — orchestrateur CLI, démarre macrophages + B-cells

### Stub explicite (lève `NotImplementedError`)
- `src/isolation/` — quarantaine
- `src/neutralization/` — élimination de menace

### Annoncé dans le README mais **zéro code**
- Lymphocytes T (anomalies sans signature)
- Cellules NK
- Mémoire immunitaire
- Modules « épigénétique / coévolutif »
- Tableau de bord web (deps Flask/Dash listées mais aucun code)

## 3. Commandes utiles

```powershell
# Lancer le système (depuis la racine du repo)
python biocybe.py
python biocybe.py --debug
python biocybe.py -c config/biocybe.yaml

# Tests
python -m pytest tests/ -v

# Vérifier juste les imports
python -c "import sys; sys.path.insert(0,'.'); from src.biocybe_core import BioCybeCore"
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

| Phase | Statut | Objectif livrable |
|---|---|---|
| 0 — Déverrouillage | ✅ fait | `python biocybe.py` démarre, 8 smoke tests verts |
| 1 — MVP démontrable | ✅ fait | `biocybe scan <path>` + détection EICAR via YARA + quarantaine + manifeste JSON + 3 tests d'intégration |
| 2 — Observabilité | ⏳ | Dashboard Dash, SHAP/LIME, API REST Flask, Dockerfile |
| 3 — Adaptabilité (R&D) | ⏳ | Lymphocytes T, mémoire immunitaire persistante, swarm P2P |

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
