# Politique de sécurité — BioCybe

BioCybe est un outil de **cyberdéfense**. Sa sécurité interne doit être
exemplaire, sinon l'outil devient une vulnérabilité de plus dans
l'écosystème. Ce document décrit notre posture supply chain et les
procédures de signalement.

## Signaler une vulnérabilité

**Ne PAS ouvrir d'issue GitHub publique** pour une vulnérabilité.

- E-mail : ouvrir une discussion sur le tab Security du repo
  ([Security Advisories](https://github.com/servais1983/biocybe/security/advisories/new))
  ou contact direct via la page maintainer.
- Inclure : PoC minimal, version BioCybe, environnement (OS, Python,
  Docker base image), impact estimé.
- Délai de réponse : 72 h pour acknowledge, fix coordonné dans les
  30 jours pour les vulnérabilités < critique, 7 j pour critique.

## Modèle de menace adressé

BioCybe protège contre :
- **Exfiltration des payloads en quarantaine** : chiffrement
  AES-256-GCM optionnel (Phase 2.4.b) — un attaquant root sur la
  machine ne peut pas récupérer les malwares sans la clé.
- **Modification du log d'audit** : chaîne SHA-256 append-only
  (Phase 2.4.a) — toute altération détectée par `biocybe audit verify`.
- **Token API leak via timing attack** : `hmac.compare_digest` sur
  l'auth Bearer (Phase 2.3.a).
- **HTTP en clair pour les feeds threat intel** : HTTPS uniquement
  (URLs codées en dur dans `intel.rules.KNOWN_SOURCES`).
- **Zip-bomb / zip-slip dans les feeds YARA communautaires** :
  validation taille + chemin (Phase 2.2.c).

BioCybe **ne protège PAS contre** (modèle de menace volontairement
explicite) :
- Compromission du serveur de mise à jour upstream (abuse.ch,
  signature-base). Mitigation : ne télécharger que sur HTTPS, vérifier
  les hashes des releases (à venir Phase 2.4.d).
- Vol de la clé AES `BIOCYBE_QUARANTINE_KEY` via memory dump,
  /proc/<pid>/environ, history shell. Mitigation : utiliser un KMS
  (Vault, AWS Secrets Manager) avec rotation.
- Supply chain attack sur PyPI (typosquatting, package compromis).
  Mitigation : utiliser `pip-audit` régulièrement (intégré CI),
  pinner les versions en prod via `requirements-lock.txt`.

## Supply chain — artefacts disponibles à chaque build

Chaque run CI sur `main` génère et archive :

- **SBOM SPDX 2.3** (`sbom-spdx.json`) : inventaire complet des
  packages installés dans l'image Docker, format standard NIST
  d'inventaire logiciel.
- **SBOM CycloneDX 1.5** (`sbom-cyclonedx.json`) : même chose au
  format OWASP CycloneDX (compatible Dependency-Track, etc.).
- **Vulnerability scan SARIF** : sortie de `grype` (Anchore) sur
  l'image runtime, avec sévérités CVSS.
- **Couverture de tests** : `coverage.xml` (Linux/py3.12).

Téléchargeables depuis l'onglet Actions, artifact
`supply-chain-<sha>`, rétention 30 jours.

Outils utilisés (open source, auditables) :
- [`syft`](https://github.com/anchore/syft) — Apache 2.0
- [`grype`](https://github.com/anchore/grype) — Apache 2.0
- [`pip-audit`](https://github.com/pypa/pip-audit) — Apache 2.0
- [`ruff`](https://github.com/astral-sh/ruff) — MIT (lint + sécurité bandit-like)
- [`bandit`](https://github.com/PyCQA/bandit) — Apache 2.0 (pre-commit)

## Pratiques internes

- **Pas de secrets en code** : tous les tokens / clés / webhooks
  sont lus depuis l'environnement ou des fichiers ignorés par git
  (`.env`, `secrets.json` jamais commités).
- **Pre-commit hooks** : `detect-private-key`, `bandit` sur le code
  hors tests.
- **Dependabot** : Dependency Graph activé (visible dans Insights).
- **Tests d'intégration RÉELS** sur toutes les opérations destructives
  (quarantine, restore, encrypt/decrypt, audit verify) — pas de mock
  qui masquerait une régression critique.
- **Détection comportementale supply-chain** : la TCell de BioCybe
  peut elle-même servir à détecter une compromission de BioCybe via
  un comportement anormal de son propre process (méta-monitoring).

## Plan de rotation des clés

- Token API `BIOCYBE_API_TOKEN` : à rotater à chaque changement
  d'équipe ou tous les 90 j.
- Clé quarantaine `BIOCYBE_QUARANTINE_KEY` : ne PAS rotater sans
  d'abord restaurer tous les fichiers en quarantaine et les
  re-chiffrer avec la nouvelle clé (sinon perte irrécupérable des
  payloads sous l'ancienne clé). Outil `biocybe crypto rotate-key`
  à venir Phase 3.

## Conformité visée

- **SOC 2 Type II** — audit log immuable (✅ Phase 2.4.a),
  vérification d'intégrité (✅), traçabilité opérateur (actor field).
- **ISO/IEC 27001** — politique de classification (mise en quarantaine
  des actifs malveillants), gestion d'incident (notifications
  sortantes ✅), revue indépendante (SBOM + scan ✅).
- **GDPR** — pas de PII collectée par défaut. Les chemins de fichiers
  scannés peuvent contenir des données personnelles ; l'opérateur est
  responsable du contrôle d'accès aux logs.
- **NIS2** (UE, à partir d'oct. 2024) — capacités de détection +
  notification d'incident + traçabilité.

## Hall of fame

À venir — premier rapport responsable de vulnérabilité accepté =
mention dans ce fichier (avec accord du reporteur).
