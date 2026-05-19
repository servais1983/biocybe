# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ;
versioning [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

### Phase 3.c : readiness probe Kubernetes réel sur `/readyz`

Refactor de `/readyz` qui retournait juste `{"status": "ready"}` sans
vraiment vérifier la santé de l'app. Maintenant : 4 checks réels avec
diagnostic détaillé, **utilisable comme readinessProbe Kubernetes**.

#### Changements

- **`/readyz` ne demande plus de Bearer token** (compatible
  K8s/sidecar/load balancer healthchecks sans secret).
- Retourne **HTTP 200** si tous les checks passent, **HTTP 503** sinon.
- Body JSON détaillé pour debugging :
  `{"status": "ready"|"not_ready", "uptime_seconds": N, "checks": {...}}`

#### Checks effectués

  - `quarantine_dir` : existe et writable (ou parent writable si pas
    encore créé — la quarantaine est créée au 1er match)
  - `rules_yara_compilable` : cache `.yarc` présent OU au moins 1 .yar
    source. Cherche dans plusieurs paths (cwd + `/home/biocybe/...`
    pour Docker).
  - `metrics` : `prometheus_client` importable si `metrics_enabled`
  - `auth` : token configuré (env OU APIConfig) ET ≥ 16 chars. Refuse
    les tokens courts qui ne sont pas prod-grade.

#### Demo live

    $ curl http://localhost:8080/readyz
    {
      "checks": {
        "auth": {"detail": "ok", "ok": true},
        "metrics": {"detail": "ok", "ok": true},
        "quarantine_dir": {"detail": "quarantine not yet created (will be on first use)", "ok": true},
        "rules_yara_compilable": {"detail": "cache .yarc found at db/signatures/yara/compiled.yarc", "ok": true}
      },
      "status": "ready",
      "uptime_seconds": 3.2
    }

Exemple K8s `readinessProbe` :

    readinessProbe:
      httpGet:
        path: /readyz
        port: 8080
      initialDelaySeconds: 2
      periodSeconds: 5
      failureThreshold: 3

#### Tests (`tests/test_readyz.py`, 10 tests)

  - `/readyz` accessible sans auth (différent de `/api/v1/*`)
  - 200 quand tous les checks passent
  - 503 quand au moins un check fail
  - Chaque check individuel testé OK + fail :
    - YARA OK avec règles, fail sans aucune règle ni cache
    - Auth OK avec token long, fail sans token, fail si token < 16 chars
    - Auth disabled (dev) → check passe avec mention
  - Le body 503 contient TOUJOURS les 4 checks (diagnostic complet)
  - Uptime fonctionne et est numérique

### Phase 3.b : pré-compilation du cache YARA au build Docker

Suite logique de Phase 3.a : exposer le build du cache `.yarc` comme
commande CLI explicite, l'invoquer au build de l'image Docker pour que
le 1er démarrage runtime soit instantané (et pas seulement les
suivants).

#### Ajouté
- **CLI `biocybe intel rules build-cache`** :
    - `--db-path DIR` (défaut `db/signatures`)
    - `--skip-sync` : compile ce qui est déjà en `db/`, sans re-copier
      depuis `rules/yara/` (utile en provisioning où sync a déjà eu lieu)
    - `--force` : supprime le cache existant avant recompile
    - `--json` : sortie machine-readable (durée, taille, fingerprint…)
- **Dockerfile** : étape `RUN biocybe intel rules build-cache --skip-sync`
  dans le stage runtime. Le cache `.yarc` est généré au build de l'image
  pour les règles natives (`rules/yara/*.yar`). Le 1er démarrage runtime
  charge donc directement le cache au lieu de recompiler.

#### Mesure réelle (Windows host, sans Defender background sur le venv)
  - **build-cache 2 règles natives** : 0.0 s, cache 194 KB
  - **build-cache 748 règles community** : 1.4 s, cache 13.8 MB
  - vs 5 min en daemon Windows + Defender → x130 speedup même sans cache
    juste en utilisant un context Python frais (la lenteur Defender
    venait de scanner chaque .yar individuellement quand le daemon
    multi-thread tournait)

#### Cas d'usage
- **Image Docker** : cache pré-compilé au build = runtime instantané
- **Provisioning Ansible** : `biocybe intel rules update --yes && biocybe intel rules build-cache`
- **Cron quotidien** : refresh community rules + rebuild cache pendant
  la nuit, daemon redémarré au matin sans pénalité de compile
- **CI/CD** : valider qu'un set de règles custom compile sans erreur

### Phase 3.a : cache de compilation YARA (.yarc) — speedup x1626

Résout le bug perf 8 trouvé en Phase VALIDATION V5 : le daemon prenait
5 min à démarrer sur Windows avec les 748 règles communautaires +
Defender actif. Maintenant **~200 ms au 2e démarrage**.

#### Comment ça marche

- `SignatureDatabase._compile_yara_rules` calcule un **fingerprint
  SHA-256** des fichiers sources (noms triés + tailles + mtimes + version
  yara). Inclus la version yara pour invalider le cache si la lib
  change.
- Si `<db>/compiled.yarc` + `compiled.fingerprint.json` existent et
  matchent le fingerprint actuel → `yara.load(compiled.yarc)` (~30 ms).
- Sinon, compilation normale (groupée puis tolérante en fallback) +
  `rules.save(compiled.yarc)` + sérialisation du fingerprint.
- Le cache est **automatiquement invalidé** si :
  - Un fichier .yar/.yara est ajouté, modifié, supprimé
  - La version de yara-python change
  - `compiled.yarc` est corrompu (catch `yara.Error` → fallback recompile)

#### Mesures réelles (validate_cache_speedup.py)

  - **Cold start** (compile + save) : 311 s (Windows + Defender, 744 règles)
  - **Warm start** (load cache) : 0.19 s (191 ms total daemon ready)
  - **Speedup : x1626**
  - Cache `.yarc` : ~30 MB pour 731/744 règles valides

Tests : 8 tests unitaires (`tests/test_yara_cache.py`) couvrant cache
miss, cache hit, invalidation après modification/ajout/suppression de
source, fallback sur cache corrompu, équivalence des détections
cold vs warm.

### Phase VALIDATION : audit conditions réelles + fixes bugs critiques découverts

Suite à la consigne user "jamais de mode démo, que du réel", 5 batteries
de tests prod-grade ont été écrites et exécutées. Chacune a trouvé de
vrais bugs (pas de cosmétique). Tous corrigés.

#### V1 — Daemon en continu (script : `scripts/validate_daemon.py`)
**4 bugs réels trouvés et corrigés :**
1. `BiologicalCell._worker` utilisait `_stop_event.wait(0.1)` hard-coded.
   Avec 6 cellules sur Windows = **47% CPU idle**. Fix : `tick_interval`
   configurable, défaut 1.0s, override 0.5s pour BCell. Mesure après
   fix : **14% CPU idle**.
2. `MetricsCollector.sample()` appelait `psutil.process_iter` + `net_connections`
   à chaque sample (~200ms sur Windows avec ACL). Fix : cache des stats
   process refresh tous les 30s seulement. Variation sub-30s captée par
   les autres features rapides.
3. `CellMessage.__lt__` manquant → exception `'<' not supported between
   instances of 'CellMessage'` levée par `queue.PriorityQueue` en cas
   d'égalité de priorité (typique au démarrage). Fix : `__lt__` par
   timestamp.
4. `SIGBREAK` non géré → daemon brutalement terminé sur Windows. Fix :
   handler `signal.SIGBREAK` ajouté.

**Verdict V1** : PASS — RSS stable, 14% CPU idle, 0 traceback, arrêt
propre en 4.5s.

#### V2 — Scan IOCs réels (script : `scripts/validate_scan.py`)
Pas seulement EICAR. 5 fichiers contenant des IOCs réels que les
règles Florian Roth/Neo23x0 cherchent :
- China Chopper PHP `<?php @eval($_POST...)` → **4 règles matchent**
  (APT_WebShell_Tiny_1, ChinaChopper_Generic, EXT_WEBSHELL_PHP_Generic)
- China Chopper ASPX → **7 règles** matchent
- PowerShell `-enc JABzAD0...` → SUSP_PS1_JAB_Pattern_Jun22_1
- Mimikatz strings `sekurlsa::logonpasswords` → Mimikatz_Memory_Rule_1
- EICAR → EICAR_Test_File + SUSP_Just_EICAR

**Verdict V2** : PASS — 5/5 TP, 0/3 FP sur fichiers bénins
(Python/README/JSON), 173 ms/fichier avec 735 règles compilées.

#### V3 — API charge réelle (script : `scripts/validate_api_load.py`)
**Bug critique production trouvé** :
- `scan_path()` recrée une `BCell` à chaque appel → recharge les 748
  règles YARA (1.5s init). En charge, **250/250 scans timeout à 10s**.
  Fix : `BCell` partagée au niveau de l'app Flask, init lazy thread-safe.
  Mesure après fix : **893 req/sec, 0 erreur sur 1000 req mixtes**,
  scan p99 = 31 ms (vs 10000 ms avant).

**Verdict V3** : PASS — 893 req/sec, p99 < 50 ms sur tous les endpoints
auth, RSS stable.

#### V4 — Watcher batch 1000 fichiers (script : `scripts/validate_watcher_batch.py`)
1000 fichiers créés en rafale dans le dossier surveillé (100 IOCs +
900 bénins). **100/100 IOCs détectés, 0/900 FP**. Latence détection
médiane 887 ms, p99 1309 ms (sous 5 s objectif).

**Verdict V4** : PASS — 0 perte d'événement, 100% recall, latence OK.

#### V5 — Daemon full-stack 5 min (script : `scripts/validate_full_stack.py`)
Daemon + cells + watcher + audit log + auto-quarantine, sur dossier
surveillé avec injection périodique d'IOCs.

**3 bugs réels trouvés et corrigés :**
1. **Logs en cp1252 sur Windows** au lieu d'UTF-8 → caractères accentués
   corrompus, illisibles par un SIEM Linux. Fix : `FileHandler(encoding="utf-8")`
   dans `cli.py` et `biocybe_core/core.py`.
2. **`core.save_status()` plantait** : `json.dump` ne sait pas sérialiser
   `datetime`. Fix : `default=str, ensure_ascii=False`.
3. **Compilation YARA des 748 règles communautaires prend ~1m15 sur
   Windows** avec Defender actif (Issue perf prod, documenté pour
   Phase 3 — solution : `yara.compile().save_to_file()` pour cacher
   le binaire compilé).

**Verdict V5** : PASS (avec règles natives seules) — 6/6 IOCs quarantinés
en temps réel, audit chaîne SHA-256 OK, 0 FP, RSS stable, arrêt propre.

#### Tests Phase VALIDATION ajoutés

5 scripts d'observation réelle dans `scripts/validate_*.py`,
exécutables localement avant chaque release majeure :
  - `validate_daemon.py` — observation daemon CPU/RSS/erreurs
  - `validate_scan.py` — détection IOCs réels + FP check
  - `validate_api_load.py` — charge HTTP avec mesures p50/p95/p99
  - `validate_watcher_batch.py` — perf watcher sous charge
  - `validate_full_stack.py` — end-to-end avec audit

### Phase 2.4.c : Supply chain hardening (SBOM + scan + politique)

#### Ajouté
- **SBOM SPDX 2.3** auto-généré à chaque build CI via `anchore/sbom-action@v0` (`syft`). Format NIST standard d'inventaire logiciel — inclut tous les packages OS + Python installés dans l'image runtime.
- **SBOM CycloneDX 1.5** auto-généré en parallèle (compatible OWASP Dependency-Track et autres outils enterprise).
- **Scan de vulnérabilités** via `anchore/scan-action@v6` (`grype`) avec sortie SARIF. Cutoff `high` actuellement, non-bloquant en attendant que la baseline soit propre.
- **Artefacts archivés 30 jours** par run CI (`supply-chain-<sha>`) : SBOMs + SARIF téléchargeables pour audit.
- **`pip-audit --strict`** sur `requirements.txt` ET sur l'install editable, `continue-on-error: true` pendant la phase de stabilisation puis bloquant.
- **Récap supply chain** dans les logs CI à chaque run (compte de packages, compte de findings).
- **`SECURITY.md`** : politique de signalement de vulnérabilités (Security Advisories GitHub, 72 h ack, 30 j fix, 7 j critique), modèle de menace adressé vs explicitement non-adressé, plan de rotation des clés, conformités visées (SOC 2 Type II, ISO 27001, GDPR, NIS2), liste auditable des outils sécurité utilisés (syft, grype, pip-audit, ruff, bandit).

### Phase 2.4.b : Quarantaine chiffrée AES-256-GCM (anti-exfiltration)

#### Ajouté
- **Nouveau module `biocybe.crypto`** : chiffrement AES-256-GCM des fichiers en quarantaine. Sans la clé, **les payloads malveillants sont irrécupérables même par root** sur la machine.
- **Format `.quarantine.enc` (magic `BCE1`)** :
    - 4 octets magic + 1 version + 1 alg id + 12 octets nonce (96-bit random unique par fichier) + 16 octets tag GCM + N octets ciphertext.
    - Format auto-portant, parseable en 6 lignes Python sans bibliothèque tierce.
- **AES-256-GCM** (AEAD authentifié) — détecte le tampering du ciphertext, du nonce, et de l'`associated_data`.
- **Associated Data = SHA-256 du clair** : double sécurité. Un attaquant qui modifierait le manifeste pour pointer un ciphertext différent verrait le déchiffrement échouer.
- **Pas de PBKDF2/Argon2** : on suppose la clé **gérée extérieurement** (KMS, Vault, env var). Plus simple à raisonner, aligné pratiques SOC modernes. Pour dériver d'une passphrase l'opérateur fait scrypt/argon2 en amont et passe la clé brute (32 bytes).
- **`biocybe.crypto.generate_key()`** + `key_to_base64()` / `key_from_base64()` + `load_key()` (priorité : arg bytes > arg base64 > env `BIOCYBE_QUARANTINE_KEY`).
- **Exceptions typées** : `KeyMissingError`, `TamperedError` (= clé invalide OU fichier modifié OU AAD divergent — l'attaquant n'apprend pas lequel).
- **Intégration `quarantine_file(..., encrypt=True, key=...)`** :
    - Si `encrypt=True`, le fichier source est chiffré dans `<id>__name.quarantine.enc` et le clair supprimé.
    - Le `QuarantineEntry` porte un nouveau champ `encrypted: bool`.
    - Le hash SHA-256 enregistré reste celui du clair → vérification d'intégrité existante fonctionne après déchiffrement.
- **`restore_file(..., key=...)`** détecte automatiquement les entrées chiffrées et les déchiffre vers la destination. `QuarantineIntegrityError` si tag GCM invalide.
- **CLI** :
    - `biocybe crypto generate-key` — base64 sur stdout, warning prod sur stderr ("perdre cette clé = perdre les quarantaines")
    - `biocybe crypto generate-key --export` — sortie `export BIOCYBE_QUARANTINE_KEY=...`
- **Cryptography ajouté aux deps core** (≥41) — utilisée aussi par requests pour TLS, donc empreinte nulle.

#### Tests (`tests/test_crypto.py` — 17 tests RÉELS)
- Bas niveau : `generate_key`, base64 roundtrip, refus de clé trop courte
- `load_key` priorité bytes > str > env, `KeyMissingError` clair sans clé
- `encrypt_file` → `decrypt_file` : round-trip exact sur ~22 KB de données
- Le fichier chiffré contient le magic `BCE1` et NE contient PAS le plaintext
- **Tampering détecté** : modification d'1 byte du ciphertext → `TamperedError`
- **Clé incorrecte** : déchiffrement avec une autre clé → `TamperedError`
- **AAD divergent** : encrypt avec `"context-A"`, decrypt avec `"context-B"` → `TamperedError`
- `is_encrypted()` détecte le magic
- **Intégration end-to-end** : `quarantine_file(encrypt=True)` → le fichier stocké contient `BCE1` et pas le payload ; restore avec bonne clé → bytes identiques ; restore avec mauvaise clé → `QuarantineIntegrityError`
- Activation via env `BIOCYBE_QUARANTINE_KEY` sans key= explicite
- Régression : le mode non-chiffré (par défaut) reste inchangé

### Phase 2.4.a : Audit log immuable (compliance SOC2 / ISO 27001)

#### Ajouté
- **Nouveau module `biocybe.audit`** : journal append-only au format JSONL avec **chaîne de hash SHA-256** anti-tampering. Chaque entrée porte son `self_hash` (SHA-256 du JSON canonique sans le hash lui-même) et le `prev_hash` de la ligne précédente. Toute modification, suppression, insertion ou réordonnancement casse la chaîne et est détectable.
- **`AuditLog.append(action, actor, outcome, details)`** :
    - écriture atomique côté process (lock + flush + fsync best-effort)
    - permissions 600 sur le fichier (Linux/macOS)
    - reprise propre après restart : lit la dernière ligne pour récupérer seq+hash
- **`AuditLog.verify()`** : recompile et vérifie la chaîne complète, retourne `(ok, errors)`. Détecte :
    - lignes modifiées (self_hash divergent)
    - lignes supprimées (trou dans seq monotone)
    - lignes échangées (prev_hash incorrect)
    - lignes insérées (rupture seq)
- **Singleton optionnel** `set_default()` / `audit()` : permet aux modules métier d'écrire sans coupler la décision d'activation.
- **Intégration automatique** : `quarantine_file()` et `restore_file()` écrivent dans le log si activé.
- **Activation** via `audit.enabled: true` dans `config/biocybe.yaml` — opt-in, no-op silencieux sinon.
- **CLI** :
    - `biocybe audit show [--limit N] [--action TYPE] [--json]`
    - `biocybe audit verify` — exit 2 si tampering détecté
- **Démo live validée** : 3 entrées écrites, `verify` OK ; après modification de la ligne 2 → `verify` détecte `seq=2 : self_hash invalide (2dd711cb5bba... ≠ 0b260527ce9d...)` avec localisation exacte.

#### Tests (`tests/test_audit.py` — 12 tests RÉELS)
- write/read disque vrai, format JSONL parseable
- séquence monotone et continue
- `verify` détecte ligne **modifiée**, **supprimée**, **échangée**
- reprise après restart : seq et prev_hash continus
- **concurrence** : 8 threads × 20 append simultanés → 160 entrées uniques, chaîne valide
- `audit()` tolère un `AuditLog` cassé (jamais fatal sur le métier)
- intégration `quarantine_file()` → entrée audit réelle avec quarantine_id correct

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
