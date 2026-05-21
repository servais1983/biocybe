# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ;
versioning [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

### Nettoyage de dette technique

Assainissement du repo — trois landmines historiques neutralisées,
toutes vérifiées par un test de non-régression.

- **`tools/review_code.py` supprimé** : utilisait `openai.ChatCompletion`
  (API cassée depuis openai≥1.0) et référençait `main.py` inexistant.
- **`swarm_intelligence/__init__.py` (845 lignes) refactoré** : le code
  métier déplacé dans `legacy_swarm.py` ; `__init__.py` devient un lazy
  loader PEP 562. `import biocybe.swarm_intelligence` ne crashe **plus**
  sans numpy/networkx (import eager de ces deps = ancien landmine) — un
  message clair pointe vers `pip install numpy networkx` ou vers
  `biocybe.swarm` (le module propre, production-ready).
- **Import TensorFlow guardé** dans `learning/reinforcement_learning.py` :
  TF (incompatible Python 3.13) est désormais importé en `try/except` avec
  un `_require_tf()` qui lève un message actionnable à l'usage seulement.
  `import biocybe.learning.reinforcement_learning` passe sur Py3.13.
- **`biocybe/__init__.py`** : version alignée `0.1.0 → 0.2.0` (matche
  pyproject), docstring des sous-packages remise à jour (modules livrés
  vs héritage non-intégré).
- **Test `test_heritage_modules_import_without_heavy_deps`** : garantit
  que ces imports ne régressent pas.

### Immunité collective (swarm) — partage de renseignement entre nœuds

Interprétation **production-ready** de l'intelligence en essaim : quand
un nœud BioCybe découvre une menace, les autres gagnent l'immunité sans
l'avoir rencontrée (herd immunity). Pas de P2P fragile —
**transport-agnostique** via bundles signés, partageables par n'importe
quel canal (volume NFS/S3, pull HTTP, rsync, CronJob).

#### Nouveau module `biocybe.swarm.SwarmSync`

- **Export** : `export_bundle()` / `write_bundle()` — sérialise les
  indicateurs **à haute confiance** de la mémoire immunitaire locale
  dans un bundle JSON signé HMAC-SHA256.
- **Import** : `import_bundle()` / `read_and_import()` / `import_dir()`
  — fusionne les bundles des pairs dans la mémoire locale.
- `ImmuneMemory.iter_shareable(min_confidence)` — sélectionne les
  menaces confirmées OU malveillantes ≥ seuil.

GARDE-FOUS :
  - **On ne partage JAMAIS les faux positifs** (décision locale propre à
    l'environnement du nœud) — seulement les menaces.
  - **Signature HMAC** (`BIOCYBE_SWARM_KEY`) : un nœud n'importe que les
    bundles d'un pair partageant la clé du swarm. Bundle falsifié /
    mauvaise clé / non signé (si clé requise) → **rejeté**.
  - **L'analyste local garde la priorité** : un indicateur marqué FP
    localement n'est pas réintroduit par un pair.
  - **Pas de boucle** : on ignore notre propre bundle ; provenance
    taguée `swarm:<node_id>`.
  - Une confirmation malveillante d'un pair **propage** la confirmation
    (immunité collective renforcée).

#### CLI

  - `biocybe swarm export <file> [--min-confidence N] [--node-id ID]`
  - `biocybe swarm import <file|dir> [--json]` (exit 1 si signature KO)
  - `biocybe swarm status` — combien d'indicateurs partageables + état signature

#### Tests (`tests/test_swarm.py`, 14 tests)

  - Export : haute confiance partagée, **FP jamais partagés**, basse
    confiance exclue
  - **Immunité collective** : node A → node B apprend sans avoir vu la
    menace ; FP local respecté ; propre bundle ignoré ; confirmation propagée
  - **Sécurité HMAC** : bundle signé vérifié, falsifié rejeté, mauvaise
    clé rejetée, non signé rejeté si clé requise
  - `import_dir` agrège ; CLI cycle export→import complet

Smoke test réel : Paris confirme LockBit → bundle signé → Lyon (vierge)
importe → immunisé ; bundle forgé (mauvaise clé) → rejeté.

> NB : module distinct du legacy `swarm_intelligence/` (826 lignes non
> intégrées, à refactorer). `biocybe.swarm` est la voie propre.

### Auto-régénération automatique dans le daemon (anti-ransomware live)

Prolongement spectaculaire : le daemon **restaure les fichiers sans
intervention humaine** quand il détecte une attaque ransomware en cours.

#### Détection de rafale ransomware

Le watcher temps-réel reçoit un `SelfHealer` optionnel. Sur chaque
événement fichier visant un chemin **baseliné**, il vérifie le drift
(hash ≠ baseline — un ransomware chiffre des fichiers sains qui ne
matchent aucune signature, d'où une détection indépendante du scan
malware). Les drifts sont comptés dans une **fenêtre glissante** :
au-delà du seuil de rafale (défaut 5 fichiers en 10s = signature
ransomware), l'attaque est suspectée.

#### Réponse graduée (sécurité d'abord)

  - **`auto_heal: false` (défaut)** : alerte critique via NotifierManager
    (« ransomware suspecté, lancez `regen heal --execute` ») — l'humain
    décide. Une modification isolée sous le seuil ne déclenche rien
    (respect des éditions légitimes).
  - **`auto_heal: true`** : restauration **automatique** de tous les
    fichiers en drift depuis le coffre intègre. La fenêtre est réinitialisée
    après le heal.

#### Intégration daemon

  - `_build_self_healer_from_config` (opt-in `config.regeneration.enabled`)
  - Passé au `FileSystemWatcher` (`regen_healer`, `regen_auto_heal`,
    `regen_burst_threshold`, `regen_burst_window`)
  - Section `regeneration` dans `config/biocybe.yaml`
  - `WatcherStats` : `regen_drift_detected` + `regen_healed`, exposés dans
    les métriques Prometheus du daemon (`biocybe_watcher_regen_*`)

#### Tests (`tests/test_regen_watcher.py`, 9 tests)

  - Drift sur fichier baseliné compté, fichier intact / non-baselinés
    ignorés
  - **Rafale → auto-heal restaure TOUS les fichiers** ; mode alerte
    (auto_heal off) → drift compté mais aucune restauration
  - Sous le seuil → pas de heal (édition légitime respectée)
  - Sans healer → aucun effet, pas de crash
  - Wiring daemon : désactivé/activé via config

### Auto-régénération (self-healing) — capacité phare anti-ransomware

LA capacité la plus innovante, jusqu'ici manquante. BioCybe savait
**retirer** la menace (quarantaine, NK) mais pas **réparer les dégâts**.
Analogie biologique complète : après élimination du pathogène, le tissu
se **régénère** vers son état sain. Cas d'usage tueur : **ransomware**.

#### Nouveau module `biocybe.regeneration.SelfHealer`

Trois phases (FIM + remédiation automatique) :

1. **Baseline** — capture l'état sain de fichiers/dossiers critiques :
   hash SHA-256 + copie du contenu dans un **coffre dédupliqué**
   (`db/regeneration/vault/`, shardé par préfixe de hash). Manifeste
   JSON avec path/sha256/size/mtime/permissions. Cap taille par fichier
   (100 Mo défaut).
2. **Détection de drift** — compare l'état courant à la baseline :
   `intact` / `modified` (chiffrement ransomware, tampering) / `deleted`.
3. **Heal** — restaure les fichiers en drift depuis le coffre.

GARDE-FOUS (mêmes principes que la cellule NK) :
  - **dry-run par défaut** : `heal()` décrit sans agir
  - **vérification d'intégrité** : le contenu restauré est re-hashé et
    comparé à la baseline AVANT de remplacer (un coffre corrompu →
    restauration refusée, le fichier endommagé n'est pas écrasé par du
    contenu invalide)
  - **écriture atomique** : tempfile + os.replace, jamais de fichier à
    moitié restauré
  - **cap** restaurations/run (10 000 défaut, anti-emballement)
  - **audit systématique** : baseline + chaque heal journalisés
  - permissions d'origine restaurées (best-effort)

#### CLI

  - `biocybe regen baseline <paths...> [--no-recursive]` — capture l'état sain
  - `biocybe regen drift` — détecte les écarts (exit 1 si drift, healthcheck-friendly)
  - `biocybe regen heal [--execute] [--path P]` — restaure (dry-run sans `--execute`)
  - `biocybe regen status` — état de la baseline

#### Tests (`tests/test_regeneration.py`, 15 tests)

  - Baseline : capture, cap taille, persistance cross-instance
  - Drift : intact / modifié / supprimé
  - Heal : dry-run ne touche rien, restaure modifié + supprimé, filtre
    `only_paths`, cap par run, **intégrité bloque un coffre corrompu**
  - **Scénario ransomware end-to-end** : 3 fichiers chiffrés → drift
    détecté → restauration complète → 0 drift résiduel
  - CLI : cycle complet baseline→drift→heal dry-run→heal execute

Smoke test réel validé : baseline 3 fichiers → "ransomware LockBit"
chiffre tout → drift=3 → `heal --execute` → 3 restaurés → drift résiduel 0.

### Observabilité : endpoint Prometheus du daemon (runtime watcher/NK/netmon)

Le process API exposait déjà `/metrics`, mais le **daemon** (watcher
temps-réel, network monitor, cellule NK) tourne dans un process séparé
sans serveur HTTP — ses compteurs runtime étaient invisibles. Cette
itération lui donne son propre endpoint.

#### Nouveau module

- **`biocybe.metrics_daemon.DaemonMetricsServer`** — serveur HTTP
  Prometheus léger (`prometheus_client.start_http_server`) avec un
  **collecteur custom** qui lit l'état live au scrape (pas de double
  comptabilité — les compteurs des composants sont la source de vérité) :
  - `biocybe_daemon_uptime_seconds`
  - `biocybe_watcher_{events_scanned,events_skipped,detections,quarantined,memory_suppressed,errors}`
  - `biocybe_nk_actions_total{outcome}` (executed/dry_run/refused/rate_limited/…)
  - `biocybe_netmon_iocs_loaded`
  - `biocybe_memory_indicators_total{verdict}` + `biocybe_memory_disposition_total{disposition}`
  - Sources injectées via callables (découplé, testable) ; un provider
    qui lève n'interrompt pas le scrape (les autres métriques passent).

#### Cellule NK

- `NKCell.action_counts` — compteur cumulé par outcome, incrémenté à
  chaque `_audit` (donc pour toute action : exécutée, dry-run, refusée,
  rate-limited). Exposé en métrique via le service.

#### Intégration daemon

- `cmd_daemon` construit/démarre le serveur via
  `_build_daemon_metrics_server` (opt-in `config.metrics.daemon_enabled`
  ou flag `--metrics-port`), arrêt propre dans le `finally`.
- `_build_network_monitor_service_from_config` attache la NK cell au
  service (`service.nk_cell`) pour l'observabilité.
- Section `metrics` dans `config/biocybe.yaml`
  (`daemon_enabled`, `daemon_port` défaut 9091).

#### Tests (`tests/test_metrics_daemon.py`, 9 tests)

  - Collecteur : uptime toujours présent, watcher stats, NK actions par
    outcome, netmon IOCs, mémoire verdict/disposition
  - Provider en échec → scrape robuste (autres métriques OK)
  - **Vrai serveur HTTP démarré + scrapé via socket + arrêté**
  - Wiring : désactivé par défaut, activé via `--metrics-port`

### Observabilité : métriques Prometheus de la mémoire immunitaire

Complète le volet monitoring. Deux nouvelles Gauges exposées sur
`/metrics`, peuplées au scrape par lecture légère de la DB SQLite (même
pattern robuste que `feed_age` en Phase 3.g — DB absente = gauges
inchangées, jamais d'erreur sur `/metrics`) :

    biocybe_memory_indicators_total{verdict="malicious"}   42
    biocybe_memory_indicators_total{verdict="benign"}       7
    biocybe_memory_disposition_total{disposition="confirmed_benign"} 5   # = FP supprimés
    biocybe_memory_disposition_total{disposition="unreviewed"}      44

Permet de mesurer dans Grafana l'efficacité de la **réduction de bruit**
(courbe des faux positifs supprimés) et la croissance de la base de
connaissances. Exemple de query : `biocybe_memory_disposition_total
{disposition="confirmed_benign"}` pour suivre les FP éliminés.

- `APIConfig.memory_db_path` (défaut `db/memory/immune_memory.db`)
- CLI : `biocybe api serve --memory-db-path ... --db-path ...` pour
  override (les défauts matchent le layout standard, donc out-of-the-box)

#### Tests (`tests/test_memory_metrics.py`, 2 tests)

  - Gauges exposées avec les bonnes valeurs (`malicious=2`,
    `confirmed_benign=1`)
  - DB mémoire absente → `/metrics` reste fonctionnel (200)

### Durcissement déploiement : Kubernetes + labels OCI

Consolide le déploiement production. Le `docker-compose.yml` était déjà
durci (read_only, tmpfs, no-new-privileges, cap_drop ALL, limites) ;
cette itération ajoute le pendant Kubernetes et la provenance d'image.

#### Manifestes Kubernetes (`deploy/k8s/`)

- **`biocybe-api.yaml`** — déploiement production-ready de l'API REST :
  Deployment (2 replicas) + Service ClusterIP + 2 PVC + NetworkPolicy.
  Durcissement defense-in-depth :
  - `runAsNonRoot` + uid/gid 10001, `fsGroup`, `seccompProfile: RuntimeDefault`
  - `readOnlyRootFilesystem: true` (writes uniquement sur volumes + tmpfs
    mémoire pour `/tmp`)
  - `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false`
  - `automountServiceAccountToken: false`
  - **limites cgroups** CPU/mémoire (un agent de sécu ne doit jamais OOM
    le nœud)
  - probes **liveness `/healthz`** (redémarre si mort) + **readiness
    `/readyz`** (Phase 3.c, 4 checks réels, retire du LB sans tuer) +
    startupProbe
  - token API via Secret (jamais en clair), clé quarantaine optionnelle
  - **NetworkPolicy** : `/metrics` + API joignables seulement par
    ingress + namespace monitoring
- **`README.md`** — guide de déploiement, tableau des mesures de
  durcissement, explication des deux probes.

#### Labels OCI (Dockerfile)

Métadonnées de provenance pour la corrélation SBOM et la traçabilité
supply-chain : `org.opencontainers.image.{title,description,source,
licenses,version,created,revision}`. `BUILD_DATE` et `VCS_REF` injectés
au build CI. Vérification CI ajoutée : `image.source` correct + user
non-root (`biocybe`).

### CI : job de validation E2E du pipeline threat intel

Ajoute un job `pipeline-validation` au workflow GitHub Actions, qui
exécute `scripts/validate_intel_pipeline.py` (35 vérifications réelles,
Phases 3.d→3.h) à chaque push/PR. Protège tout le pipeline threat intel
contre les régressions futures : feeds → IOCLookup → feed_age →
NetworkSentinel → NetworkMonitor (vraie connexion socket) →
NetworkMonitorService (audit + notify) → maybe_reload → DashboardData.

  - `needs: [test]` — ne tourne qu'après la matrice de tests unitaires
  - Installe YARA système + le package core (`pip install -e .`) ; les
    imports critiques (notify, dashboard.data) marchent en core, pas
    besoin des extras
  - Le script gère le SKIP gracieux si pas de réseau (étape connexion
    socket) ; les runners GitHub ayant un accès sortant, la connexion
    réelle vers 1.1.1.1:443 passe normalement — jamais de faux PASS

### Mémoire immunitaire : intégration daemon + watcher + dashboard

Boucle la mémoire immunitaire dans le runtime live (elle n'était câblée
qu'au scan one-shot). Désormais la réponse secondaire et la suppression
des faux positifs opèrent en continu.

#### Watcher temps-réel

- `FileSystemWatcher(..., memory=ImmuneMemory(...))` : chaque détection
  RT est croisée avec la mémoire par SHA-256.
  - Faux positif confirmé → détection **étouffée** (pas d'alerte, pas de
    quarantaine), compteur `WatcherStats.memory_suppressed`.
  - Vraie détection → mémorisée (`watcher:realtime`) pour renforcer les
    futures réponses.

#### Daemon

- `cmd_daemon` construit la mémoire via `_build_immune_memory_from_config`
  (opt-in `config.memory.enabled`), la passe au watcher, l'affiche au
  démarrage, la ferme proprement à l'arrêt.
- Nouvelle section `memory` dans `config/biocybe.yaml`.

#### Dashboard SOC — onglet « Mémoire »

- `DashboardData.memory_summary()` : total, répartition verdict/
  disposition, top familles, indicateurs les plus vus.
- Nouvel onglet Dash : bannière (total + FP supprimés), charts verdict/
  disposition/familles, table triable des indicateurs récurrents.
- Ajouté au `snapshot()` complet.

#### Tests (`tests/test_memory_integration.py`, 9 tests)

  - Watcher : `_apply_memory` supprime un FP / apprend une détection ;
    `_process` end-to-end (FP confirmé → `memory_suppressed=1`,
    `detections=0`) ; sans mémoire, comportement inchangé
  - Dashboard : `memory_summary` présent/absent, inclus dans snapshot
  - Daemon wiring : `_build_immune_memory_from_config` désactivé/activé

Smoke test réel : onglet Mémoire du dashboard rend les vraies données
(familles, FP supprimés).

### Mémoire immunitaire persistante — apprentissage cross-session

Dernier grand pilier bio-inspiré annoncé et non codé. Reproduit la
**réponse secondaire** du système immunitaire : un pathogène déjà
rencontré déclenche une réaction plus rapide et plus forte qu'à la
première exposition.

#### Nouveau module

- **`biocybe.memory.ImmuneMemory`** — store SQLite (WAL, thread-safe) :
  - `remember(indicator, ...)` — enregistre/met à jour une observation.
    Sur ré-exposition : incrémente `times_seen`, garde la confiance MAX,
    ne régresse jamais un verdict `malicious` vers `benign`.
  - `recall(indicator)` — verdict instantané pour un indicateur connu
    (réponse secondaire rapide, sans relancer YARA/ML).
  - `set_disposition(...)` — feedback analyste : `confirmed_benign`
    (= faux positif) ou `confirmed_malicious`.
  - `adjust_confidence(indicator, base)` — cœur de la réponse
    secondaire : **0** si FP confirmé (supprimé), **100** si malveillant
    confirmé (réponse maximale immédiate), **base + min(times_seen, 10)**
    si récurrent (renforcement progressif), base sinon.
  - `is_known_benign`, `forget`, `stats`, `top_families`, `recent`,
    `most_seen`.
  - Persistance cross-session : la mémoire survit au redémarrage du
    daemon (validé par smoke test réel).

#### Intégration scanner

`scanner.scan_path(..., memory=ImmuneMemory(...))` :
  - Un fichier flaggé dont le SHA-256 est un **faux positif confirmé** en
    mémoire est **supprimé** (`verdict.suppressed_by_memory=True`) — on
    n'alerte plus jamais sur un FP connu, la plaie n°1 des SOC.
  - Les vraies détections sont **mémorisées** (famille, confiance,
    sévérité) pour renforcer les futures réponses.
  - Ne hashe que les fichiers déjà flaggés (coût négligeable).

#### CLI

  - `biocybe memory stats [--json]` — compteurs par verdict/disposition
    + top familles
  - `biocybe memory recall <indicator> [--type T]` — ce que la mémoire
    sait (type auto-deviné si omis)
  - `biocybe memory recent [--limit N] [--most-seen]` — récents ou plus
    fréquents
  - `biocybe memory mark <indicator> --type T --as benign|malicious`
    — feedback analyste (benign = supprime les futures alertes)
  - `biocybe memory forget <indicator> --type T` — purge

#### Tests (`tests/test_immune_memory.py`, 16 tests)

  - `remember` création + mise à jour (times_seen, conf MAX, pas de
    régression de verdict), recall par type/auto, dispositions, persistance
    cross-session (réouverture DB), forget, stats/top_families/most_seen
  - `adjust_confidence` : tous les cas de la réponse secondaire
    (inconnu/récurrent/confirmé malveillant/FP)
  - Intégration scanner : suppression FP confirmé + apprentissage d'une
    nouvelle détection
  - CLI : stats, mark+recall, recall inconnu, forget, recent

#### Smoke test réel validé

Persistance SQLite cross-session (fermeture/réouverture), réponse
secondaire (confiance 60 → 63 après récurrence), suppression FP
(confiance 99 → 0 après marquage analyste).

### Cellules NK (Natural Killer) — réponse active sur processus malveillants

Premier module BioCybe qui passe de la **détection** à la **réponse
active**. Une `NKCell` peut suspendre, terminer ou tuer un processus
identifié malveillant (par le NetworkMonitor 3.h, le scanner, ou une
décision d'analyste). C'est le SEUL module qui pose des actions
destructives — d'où une obsession de la sécurité.

#### Garde-fous (défense en profondeur, chacun bloque indépendamment)

1. **Désactivée par défaut** (`enabled=False`) — rien ne s'exécute sans
   activation explicite.
2. **Dry-run par défaut** (`dry_run=True`) — même activée, décrit ce
   qu'elle ferait sans agir.
3. **Liste de process protégés** : ne touche JAMAIS init/systemd/kernel/
   lsass/csrss/services/svchost/explorer, le shell de l'admin, BioCybe
   lui-même ni son parent. PIDs 0/1/4 intouchables. Cross-platform.
4. **Seuil de confiance** (défaut 90/100) — n'agit que sur les
   détections fiables.
5. **`kill` opt-in séparé** (`allow_kill=True`) — sinon downgrade
   automatique vers l'action par défaut. L'action par défaut est
   `SUSPEND`, **réversible** (`resume`), idéale pour figer un process en
   attendant une décision humaine/forensique.
6. **Anti-PID-recycling** : re-vérifie le nom du process au moment
   d'agir ; si le PID a été recyclé pour un autre process entre
   `evaluate()` et `respond()`, refus.
7. **Rate-limit** (défaut 10 actions/min) — anti-emballement.
8. **Audit systématique** : chaque décision ET action (exécutée,
   refusée, dry-run, en échec) dans la chaîne immuable.

#### API

- `NKCell.evaluate(...)` → `NKDecision` (décide, ne touche rien)
- `NKCell.respond(decision)` → exécute (sauf dry-run)
- `NKCell.resume_process(pid)` → annule un SUSPEND
- `NKCell.isolate_host(hostname)` → sinkhole DNS via `HostsBlocker` (3.f)
- `NKAction` : NONE / SUSPEND / TERMINATE / KILL / ISOLATE_NETWORK

#### CLI

  - `biocybe nk respond --pid PID [--action suspend|terminate|kill]
    [--execute] [--allow-kill] [--confidence N] [--min-confidence N]` —
    dry-run par défaut (sans `--execute`)
  - `biocybe nk resume --pid PID` — réveille un process suspendu
  - `biocybe nk status [--pid PID]` — config effective + test de
    protection d'un PID

#### Intégration daemon (opt-in)

Si `nk.enabled` + `nk.auto_respond` dans la config, le `on_match` du
NetworkMonitor (3.h) appelle la NK cell : un process qui contacte un C2
connu est suspendu automatiquement (selon la config). Chaîne complète
**détection → réponse** en un daemon. Reste dry-run tant qu'on ne l'a
pas explicitement désactivé.

#### Tests (`tests/test_nk_cell.py`, 22 tests)

  - Garde-fous : désactivée refuse, seuil de confiance, PIDs protégés
    (0/1/4), noms protégés (lsass/systemd/svchost/init/explorer), process
    propre, noms extra, downgrade kill sans allow_kill, kill avec opt-in
  - Exécution : dry-run n'appelle pas psutil, suspend/kill réels (mockés)
    appellent les bonnes primitives, PID recyclé refusé, NoSuchProcess /
    AccessDenied gérés, rate-limit (2 exécutés / 3 bloqués), resume,
    isolate_host préserve l'existant
  - CLI : dry-run par défaut, process protégé → exit 1, status, test PID

#### Smoke test réel validé

Suspend/resume/kill exécutés sur un **vrai process** (python sleep) :
status `running` → `stopped` (suspend) → `running` (resume) → terminé
(kill). Le garde-fou refuse bien `python.exe`. Pipeline daemon
détection→réponse (dry-run) validé sans crash.

### Validation end-to-end du pipeline threat intel (Phases 3.d → 3.h)

Nouveau `scripts/validate_intel_pipeline.py` — harnais de validation
**réelle** (principe BioCybe : jamais de mode démo) qui exerce toute la
chaîne threat intel avec de vrais composants, 0 mock de la logique
métier. 35 vérifications en 8 étapes :

  1. **Feeds** — écrit MalwareBazaar + URLhaus + ThreatFox au format
     EXACT des updaters
  2. **IOCLookup** — lookups hash/ip(+port)/hostname/url, parent-domain
     fallback, `lookup_auto` typé, **0 faux positif** sur IP bénigne
  3. **feed_age** — feeds frais détectés frais, feeds vieillis de 5j
     détectés stale
  4. **NetworkSentinel** — IP+URL+hash détectés dans un script, fichier
     bénin non flaggé
  5. **NetworkMonitor** — **vraie connexion socket sortante** vers
     `1.1.1.1:443` (ajoutée au feed), réellement observée par
     `psutil.net_connections` et matchée. SKIP explicite si offline
     (jamais masqué en faux PASS)
  6. **NetworkMonitorService** — `on_match` écrit l'audit immuable
     `network_ioc_detected` (chaîne SHA-256 **vérifiée intègre**) +
     émet la notification (sévérité critical pour conf 100)
  7. **maybe_reload** — ajout d'un IOC + bump timestamp → rechargé, le
     monitor voit le nouvel IOC ; no-op si inchangé
  8. **DashboardData** — reflète l'état audit + intel, action
     `network_ioc_detected` visible

IOCs de test réservés par la RFC uniquement (IPs RFC 5737
`203.0.113.0/24` etc., domaines RFC 2606 `.test`). Le workdir temporaire
est nettoyé en fin de run. Exécution validée : **35 PASS, 0 FAIL,
0 SKIP** (la vraie connexion réseau a fonctionné). Script clean au lint
ruff.

### Phase 3.h : daemon unifié — surveillance réseau live intégrée

Unifie les briques réseau (3.e/3.f), threat intel (3.d/3.g) et
notifications (2.3.b) dans le runtime live du daemon. Jusqu'ici le
`NetworkMonitor` n'était accessible qu'en one-shot (`netmon scan`) ou
en commande dédiée (`netmon watch`). Désormais le daemon principal le
fait tourner en continu, câblé aux notifications et à l'audit.

#### Nouveau : `NetworkMonitorService`

`biocybe.network_monitor.NetworkMonitorService` — wrapper daemon-friendly :

  - bundle `NetworkMonitor` + `IOCLookup` + callback `on_match`
  - **rechargement auto des feeds** : `maybe_reload()` compare un
    fingerprint SHA-256 des `last_update.txt` de chaque feed et ne
    relit le disque que si un `intel update` (cron Phase 3.g) a tourné.
    Comme `IOCLookup.reload()` mute l'instance en place, le monitor voit
    les nouveaux IOCs **sans redémarrage du daemon**.
  - `start()` / `stop()` / `ioc_total`

#### Intégration daemon

  - `cmd_daemon` construit et démarre le service via
    `_build_network_monitor_service_from_config(config, notify_mgr)`
  - Le callback `on_match` fait deux choses pour chaque connexion vers
    un IOC connu :
    1. **audit immuable** : entrée `network_ioc_detected` (PID, process,
       remote, malware, confidence, source) dans la chaîne SHA-256
    2. **notification sortante** : `Event(REALTIME_DETECTION)` vers le
       NotifierManager. Sévérité `critical` si confidence ≥ 90, sinon
       `warning`
  - La boucle principale appelle `maybe_reload()` toutes les 5 min
  - Arrêt propre du service dans le `finally` (avant `core.stop()`)

#### Activation

  - Flag CLI : `biocybe --netmon [--netmon-interval N]`
  - Config : section `netmon` dans `config/biocybe.yaml`
    (`enabled`, `interval`, `reverse_dns`, `db_path`)
  - Combinable : `biocybe --watch /tmp --watch-quarantine --netmon`
    = stack complète live (fichiers + réseau + quarantaine + alertes +
    audit)

#### Tests (`tests/test_network_monitor_service.py`, 9 tests)

  - `NetworkMonitorService` : construction, `ioc_total`, `maybe_reload`
    no-op quand inchangé / reload quand `last_update.txt` change, le
    monitor voit les nouveaux IOCs après reload (snapshot)
  - Wiring : désactivé par défaut, activé via config OU flag CLI,
    intervalle CLI prioritaire
  - `on_match` : écrit l'audit `network_ioc_detected` (vérifié dans la
    chaîne) ET notifie ; sévérité critical (conf≥90) vs warning (conf<90)
  - Smoke test réel validé : flags parsés, service start/stop propre

### Phase 2.3.c : dashboard SOC (Dash) — UI de triage en lecture seule

Première interface visuelle de BioCybe. Console de triage pour un
analyste SOC, agrégeant les artefacts produits par les phases
précédentes : quarantaine, audit log, threat intel. **Lecture seule** :
aucune action destructive depuis l'UI — la remédiation (restore, purge)
reste dans la CLI/API avec audit trail, parce qu'un opérateur ne
supprime pas une preuve d'un clic sans traçabilité.

#### Architecture en deux couches

- **`biocybe.dashboard.data`** — couche données **découplée de Dash**.
  `DashboardData` lit les artefacts disque et renvoie des structures
  Python simples : `quarantine_summary()`, `audit_summary()`,
  `intel_summary()`, `overview()`, `snapshot()`. Testable sans
  navigateur, réutilisable pour export JSON/SIEM. `import
  biocybe.dashboard` fonctionne **même sans l'extra [web]**.
- **`biocybe.dashboard.app`** — UI Dash (imports gardés). Cartes KPI +
  3 onglets, charts Plotly, auto-refresh `dcc.Interval`. `create_dashboard()`
  lève `DashboardUnavailable` proprement si dash/plotly/dbc absents.

#### Contenu de l'UI

  - **Cartes KPI** : total quarantaine (couleur = pire sévérité),
    entrées audit (couleur = état chaîne), IOCs chargés (couleur =
    fraicheur feeds)
  - **Onglet Quarantaine** : table triable/filtrable + barres par
    sévérité / famille / cellule détectrice
  - **Onglet Audit** : bannière d'intégrité de chaîne SHA-256 vérifiée
    **en live** (rouge si altération détectée), barres par action /
    résultat, table des événements récents
  - **Onglet Threat Intel** : bannière fraicheur, barres IOCs par type
    + âge des feeds, table des feeds (réutilise la Phase 3.g)

#### CLI

  - `biocybe dashboard serve [--host] [--port] [--refresh-seconds]
    [--quarantine-dir] [--audit-path] [--db-path] [--debug]`
  - Servi en prod via **waitress** (le serveur Dash intégré n'est utilisé
    qu'en fallback avec warning). Bind `127.0.0.1` par défaut — pensé
    pour tourner derrière un reverse-proxy authentifié ou sur réseau
    d'admin isolé.

#### Tests (`tests/test_dashboard.py`, 11 tests + skips conditionnels)

  - Couche données : quarantine summary (tri, agrégats, taille,
    chiffré), audit summary avec **détection de tampering live**, audit
    manquant, intel summary, overview KPIs, snapshot JSON-sérialisable
  - `import biocybe.dashboard` sans dash → pas de crash
  - Construction Dash (skip si [web] absent) : layout présent, serveur
    Flask exposé, 2 callbacks enregistrés
  - Smoke test manuel validé : `GET /` 200, callback KPI rend les vraies
    données seedées (LockBit/critical), waitress disponible

### Phase 3.g : refresh auto des feeds + monitoring de fraîcheur

Le threat intel est périssable : un domaine flaggé il y a 6 mois a
probablement été nettoyé. Sans refresh régulier **et alerte si le cron
casse**, BioCybe devient une passoire silencieuse. Cette phase ajoute
la mesure de fraîcheur (CLI + Prometheus + readyz) et les templates de
déploiement pour l'automatisation.

#### Nouveau module

- **`biocybe.intel.feed_age`** :
  - `read_feed_ages(db_path, stale_threshold_s, now=None)` lit les
    `last_update.txt` de chaque feed (MalwareBazaar/URLhaus/ThreatFox)
    et renvoie un `FeedAgeReport` avec, par source : `last_update`,
    `age_seconds`, `age_human` (ex. `3d04h`), `ioc_count` (estimation
    sans charger les index), `stale` (bool), `error`
  - Fail-safe : feeds absents → `all_missing`, pas de crash sur
    déploiement neuf. Timestamp invalide → `error` + traité comme stale
  - `now` injectable pour des tests déterministes

#### CLI

  - `biocybe intel age [--json] [--stale-after SECONDS]` — tableau
    lisible ou JSON. Exit codes : `0` tous frais · `1` ≥ 1 stale ·
    `2` aucun feed jamais récupéré. Directement utilisable comme
    healthcheck cron (`|| alerter`).

#### Métriques Prometheus (`/metrics`)

Trois nouvelles Gauges, rafraîchies au scrape (lecture disque légère) :

    biocybe_intel_feed_age_seconds{source="malwarebazaar"}  3421
    biocybe_intel_feed_iocs_total{source="threatfox"}       18742
    biocybe_intel_feed_stale{source="urlhaus"}              0     # 1=stale, -1=jamais récupéré

Permet une alerte Alertmanager `feed_age > 86400` (exemple fourni dans
`deploy/refresh/README.md`).

#### Readiness probe

Check `intel_feeds_fresh` ajouté à `/readyz`, dans une section
`warnings` **non bloquante** : un feed stale ne sort pas le pod du
load balancer (le scan YARA/signature continue), mais l'info est
exposée pour observabilité.

#### Templates de déploiement (`deploy/refresh/`)

  - `biocybe-intel-refresh.service` + `.timer` — **systemd**, refresh
    toutes les 6h, durcissement (NoNewPrivileges, ProtectSystem=strict,
    ReadWritePaths limité à db/), rebuild cache YARA en ExecStartPost,
    jitter anti-thundering-herd
  - `biocybe-intel-refresh-cronjob.yaml` — **Kubernetes** CronJob,
    `concurrencyPolicy: Forbid`, securityContext durci (runAsNonRoot,
    readOnlyRootFilesystem, drop ALL caps), PVC RWX partagé
  - `crontab.example` — **cron** classique avec healthcheck quotidien
  - `README.md` — guide d'install des 3 ordonnanceurs + règles
    Alertmanager + monitoring CLI/readyz

#### Tests (`tests/test_intel_feed_age.py`, 11 tests)

  - `read_feed_ages` : tous présents, partiellement stale, tous
    manquants, timestamp invalide, freshest/oldest
  - CLI : exit 0 (fresh) / 1 (stale) / 2 (missing), sortie JSON
  - Prometheus : gauges peuplées et exposées sur `/metrics`, valeurs
    stale=1 et stale=-1 (jamais récupéré) correctes
  - `/readyz` : warning intel_feeds_fresh présent et non bloquant

### Phase 3.f : surveillance live des connexions sortantes + sinkhole DNS

Couche temps-réel qui complète la sentinelle statique de la Phase 3.e.
La 3.e détecte les IOCs **mentionnés** dans un fichier (avant
exécution). La 3.f détecte les IOCs **effectivement contactés** par
des processus en cours d'exécution.

#### Architecture (volontairement simple et cross-platform)

- **Pas de pcap** : libpcap est lourde et root-only sur la plupart des
  OS. Pas de capture promiscuous. Pas d'eBPF (Linux-only).
- **Polling `psutil.net_connections('inet')`** : déjà une dépendance
  BioCybe, marche identique sur Linux/Windows/macOS, polling 1-5 s
  configurable. Trade-off assumé : on peut manquer une connexion de
  100 ms, mais le coût/bénéfice est bon pour un SOC qui veut un
  signal stable et déployable partout.
- **Privilege detection** : root/admin pour voir TOUS les processus.
  Sans, on ne voit que ceux de l'utilisateur courant. Warning explicite
  au démarrage.

#### Nouveau module

- **`biocybe.network_monitor.NetworkMonitor`** :
  - `snapshot()` — one-shot, retourne `list[ConnectionRecord]` avec
    PID, process name/exe, raddr, status, reverse-DNS optionnel, hit
    IOC si match
  - `start()` / `stop()` — surveillance continue dans thread daemon,
    callback `on_match(record)` pour chaque IOC détecté
  - Rate-limit anti-storm : max N alertes par `(pid, remote_ip)` par
    heure (défaut 6). Une connexion qui rouvre 1000x en 1 min ne
    spamme pas le NotifierManager.
  - Filtre auto : loopback, link-local, multicast, unspecified — pas
    d'IOC plausible là, pas de match inutile
  - `AccessDenied` géré proprement (log + return [], pas de crash)

- **`biocybe.network_monitor.HostsBlocker`** :
  - Sinkhole DNS : ajoute des entrées `0.0.0.0 <hostname>` dans le
    fichier hosts (`/etc/hosts` ou
    `C:\Windows\System32\drivers\etc\hosts`)
  - Section délimitée par marqueurs (`# BIOCYBE-IOC-BLOCK START/END`)
    pour retrait propre — n'écrase JAMAIS le reste du fichier
  - Backup automatique avant la 1re mutation (`hosts.biocybe.bak`)
  - **Écriture atomique** : tempfile + `os.replace` — pas de hosts
    cassé en cas d'interruption
  - Validation stricte des hostnames : refus de wildcards, newlines
    (injection), labels mono, localhost, leading/trailing dot
  - Cap `MAX_HOSTS_ENTRIES = 50_000` — anti-DoS du fichier hosts
  - `apply(list)` / `clear()` / `list_blocked()` / `status()`

#### CLI

  - `biocybe netmon scan [--all] [--reverse-dns] [--json]` —
    snapshot ponctuel. Exit 1 si au moins un IOC trouvé.
  - `biocybe netmon watch [--interval 5] [--reverse-dns]` —
    surveillance continue. Ctrl+C / SIGTERM → arrêt propre.
  - `biocybe netmon block apply --yes [--min-confidence 75]` —
    sinkhole tous les hostnames du lookup avec confidence ≥ seuil.
    Refus si `--yes` absent (mutation système irréversible sans
    consentement explicite).
  - `biocybe netmon block clear --yes` — retire la section.
  - `biocybe netmon block status [--json]` — état actuel.

#### Tests (`tests/test_network_monitor.py`, 21 tests)

  - Snapshot : match IOC connu, ignore loopback/link-local/multicast,
    ignore sockets LISTEN, AccessDenied → pas de crash
  - Rate-limit anti-storm : `_should_alert` bloque après N
  - Thread continu : callback `on_match` invoqué pour les hits
  - HostsBlocker : apply/clear/list/status, idempotent, backup créé,
    validation rejette wildcards/newlines/localhost/mono-label, apply
    vide retire la section, écrasement n'affecte pas le reste du
    fichier
  - CLI : exit codes 0/1/2 corrects, JSON parseable, `--yes` requis
    pour les mutations

#### Quand l'utiliser

  - **`netmon scan` planifié toutes les 5 min** via cron/k8s CronJob,
    avec sortie JSON consommée par votre SIEM (Splunk, Wazuh, ELK).
    Donne une visibilité passive sur les processus qui parlent à des
    IOCs connus, sans modifier le réseau.
  - **`netmon watch` dans le daemon BioCybe** pour réagir en
    temps-réel : on_match wired vers NotifierManager → Slack/syslog.
  - **`netmon block apply` en EDR-light** sur postes utilisateurs :
    sinkhole DNS coupe l'accès aux C2 connus avant même que le
    malware tente de résoudre le hostname. Réversible, traçable
    (backup), borné (50k entries cap).

### Phase 3.e : sentinelle réseau IOC-aware

Exploite les feeds de la Phase 3.d (URLhaus + ThreatFox) pour détecter
les **IOCs réseau référencés dans le contenu des fichiers**. Couvre un
angle d'attaque que YARA + hash signature ne traite pas : un script
PowerShell téléchargé contient l'URL du payload — on la détecte AVANT
exécution. Un dump mémoire / log / config contient l'IP du C2 — alerte
immédiate.

#### Nouveaux modules

- **`biocybe.intel.ioc_lookup.IOCLookup`** — moteur en mémoire qui
  agrège tous les feeds locaux (MalwareBazaar `hashes/signatures.json`,
  URLhaus `urlhaus/{urls,hostnames}.json`, ThreatFox
  `threatfox/by_type/{hash,domain,ip}.json`). Lookup O(1) par dict,
  avec :
  - **fallback parent domain** : un sous-domaine `foo.bar.evil-c2.test`
    matche si `evil-c2.test` est indexé (renvoie `matched_parent_domain`
    dans `metadata`)
  - **merge keep-best** : si un hash est dans plusieurs feeds, on garde
    la source de plus haute confidence
  - **fail-safe** : fichiers absents/corrompus → instance vide, pas de
    crash. Permet un déploiement neuf sans pré-requis
  - `lookup_auto(value)` : détecte le type (hex 32/40/64 → hash, scheme
    → url, `ipaddress`-parseable → ip, sinon hostname)
  - `reload()` idempotent — rafraîchit après un `intel update` sans
    redémarrer le processus

- **`biocybe.network_sentinel.NetworkSentinel`** — extracteur + matcher
  d'IOCs depuis le contenu d'un fichier :
  - regex ASCII (flag `re.ASCII`) pour `\b` robuste sur **fichiers
    binaires** (latin-1 fallback ne pollue plus les frontières de mots)
  - **denylist** de 30+ hostnames courants (`github.com`,
    `googleapis.com`, `microsoft.com`, etc.) pour éviter les FP sur du
    code source / doc / manifestes
  - **dédup** par `(ioc_type, value)` — un IOC répété N fois n'apparaît
    qu'une seule fois
  - cap `DEFAULT_MAX_BYTES = 50 MB` — protection OOM, fichiers tronqués
    signalés via `result.truncated`
  - extraction simultanée URLs/IPs/hosts/hashes, comptage stocké dans
    `extracted_counts` pour observabilité

#### Intégration scanner

`scanner.scan_path(..., network_scan=True)` ajoute un `NetworkScanResult`
à chaque `FileVerdict`. Si des IOCs sont trouvés, le verdict devient
malveillant (logique OR avec les signatures YARA/hash). En mode
`--quarantine`, le `reason` inclut les top-3 IOCs réseau.

`format_report` affiche désormais chaque IOC réseau trouvé :

    - IOC réseau : url = http://evil.example.org/x (abuse.ch/URLhaus, malware=unknown, conf=75)
    - IOC réseau : ip = 10.20.30.40:8080 (abuse.ch/ThreatFox, malware=Cobalt Strike, conf=100)

#### CLI

  - `biocybe intel lookup <value>` — query directe (type auto-détecté
    ou forcé via `--type {hash,hostname,url,ip}`). Exit 0 si match,
    1 si miss, 2 si base vide. Sortie texte ou `--json`.
  - `biocybe intel stats` — compteurs par type (hashes/hostnames/urls/ips).
  - `biocybe scan <path> --network-scan` — active la sentinelle.

#### Tests (`tests/test_ioc_lookup.py` + `tests/test_network_sentinel.py`, 23 tests)

  - Lookup : tous les types, case-insensitive, parent domain fallback,
    base vide / JSON corrompu fail-safe, reload idempotent, merge
    keep-best confidence
  - Sentinelle : extraction URL/IP/host/hash, denylist appliquée même
    via fallback `lookup_url`, dédup, truncation, decode binaire safe
    avec octets > 127, scan d'un dossier mixte (sain + IOC) via
    `scanner.scan_path`
  - CLI : `intel stats`, `intel lookup` hit / miss / base vide

#### Pourquoi c'est utile concrètement

Avant Phase 3.e, BioCybe détectait :
  - ce que le fichier **est** (YARA pattern, hash signature)
  - le comportement du système (TCell ML)

Phase 3.e ajoute : ce dont le fichier **parle**. C'est ce qui permet
de bloquer un loader 0-day dont le binaire est inconnu mais qui pointe
vers un domaine C2 déjà brûlé. C'est la couche "threat hunting"
classique des SOC, désormais exploitable en CLI ou intégrée au
pipeline scan.

### Phase 3.d : threat intel multi-source — URLhaus + ThreatFox (abuse.ch)

Extension du module `biocybe.intel` au-delà de MalwareBazaar. Deux feeds
abuse.ch supplémentaires, complémentaires sur les types d'IOC, exploitables
par le scanner (hashes) et les futures cellules réseau (URLs/IPs/domains).

#### Nouveaux clients

- **`biocybe.intel.urlhaus.URLhausClient`** — feed CSV public
  `https://urlhaus.abuse.ch/downloads/csv_recent/` (24 dernières heures).
  Pas d'auth requise (la clé `ABUSECH_AUTH_KEY` augmente le rate limit
  si fournie). Parse les lignes `#`-commentées correctement, garde-fou
  anti-CSV-bombe (refus si > 50 MB).
- **`biocybe.intel.threatfox.ThreatFoxClient`** — API JSON
  `https://threatfox-api.abuse.ch/api/v1/` (POST `get_iocs` jusqu'à 7j).
  Auth-Key abuse.ch obligatoire. Couvre **tous types d'IOC** : hashes
  (sha256/md5/sha1), URLs, domaines, `ip:port`, avec famille malware et
  confidence score 0-100.

#### Stockage et index

`db/signatures/urlhaus/` :
  - `urls.json` — liste complète des entrées (URL, hostname, status, threat, tags, reporter)
  - `hostnames.json` — index `hostname → [URLs]` pour lookup O(1)
  - `last_update.txt` — horodatage ISO

`db/signatures/threatfox/` :
  - `iocs.json` — dump brut typé
  - `by_type/{hash,url,domain,ip,other}.json` — index par catégorie logique
    (les types granulaires abuse.ch `sha256_hash`/`md5_hash`/... sont
    regroupés sous `hash` pour lookup unifié)
  - `last_update.txt`

#### CLI : multi-source unifié

    biocybe intel update                        # = --source all
    biocybe intel update --source malwarebazaar
    biocybe intel update --source urlhaus
    biocybe intel update --source threatfox --threatfox-days 7
    biocybe intel update --source all           # les 3 enchaînés

Sémantique multi-source : exit `1` si **au moins une** source en
erreur, sortie texte récapitulative ligne par ligne. Plus de
distinction code 2 (auth) / code 3 (API) — un échec partiel reste
un échec côté pipeline CI.

#### Tests (`tests/test_intel_urlhaus.py` + `tests/test_intel_threatfox.py`, 16 tests)

URLhaus :
  - Parsing CSV (incluant lignes commentées `#`)
  - Extraction `hostname` via `urllib.parse.urlparse`
  - Auth optionnelle (header `Auth-Key` seulement si présente)
  - Refus CSV > `MAX_CSV_SIZE_BYTES` (50 MB)
  - CSV vide → `AbuseChAPIError` clair
  - `update_urlhaus_iocs` écrit `urls.json` + `hostnames.json` + `last_update.txt`
  - Index hostname dédupliqué correctement

ThreatFox :
  - Parsing payload JSON (champs `malware_printable`/`malware` fallback,
    `confidence_level` int safe, `tags` liste safe)
  - Auth-Key envoyée en header, User-Agent BioCybe
  - `days` clampé à `[1, 7]` (limite abuse.ch)
  - `AbuseChAuthMissing` si pas de clé (message pointant `auth.abuse.ch`)
  - `query_status != "ok"` → `AbuseChAPIError`
  - `update_threatfox_iocs` génère les buckets `by_type/{hash,url,domain,ip}.json`
  - CLI `--source threatfox` route bien et compte les stats

Plus le test régression `test_cli_intel_update_auth_missing` mis à jour
(exit code 1 pour cohérence avec la sémantique multi-source).

#### Pourquoi c'est utile

  - **MalwareBazaar** alimente déjà les hashes pour le scanner. Mais
    les ransomware modernes changent de hash à chaque infection.
  - **URLhaus** donne les URLs distribuant ces malwares — c'est ce que
    surveillera la future cellule réseau (Phase 3.e+). Un proxy
    d'entreprise peut bloquer ces hostnames *avant* le téléchargement.
  - **ThreatFox** ajoute les **C2 servers, botnets, infrastructure** —
    indicateurs réseau actifs. Index `by_type/ip.json` directement
    consommable comme blocklist firewall.

Effet net : passage d'**1 feed** (hashes uniquement) à **3 feeds
corrélés** couvrant fichiers + URLs + infrastructure réseau. C'est ce
qu'attendent les SOC qui consomment du threat intel (vs un AV
classique).

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
