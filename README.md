![biocybe](https://github.com/user-attachments/assets/faabdc39-3e07-42f0-9ec8-55258e8a876d)


# BioCybe

Systeme de cyberdefense open-source bio-inspire, modulaire et explicable.

BioCybe s'inspire du systeme immunitaire pour fournir une defense en
profondeur : detecter, apprendre, neutraliser et **regenerer** apres une
attaque. Concu comme une alternative transparente et auditable aux EDR
commerciaux fermes, pour les SOC d'entreprise, MSSP et equipes securite.

Version 0.2.0 · Licence MIT · Python 3.10 a 3.13 · Linux / Windows / macOS

---

## Sommaire

- [Apercu](#apercu)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Architecture bio-inspiree](#architecture-bio-inspiree)
- [Deploiement](#deploiement)
- [Observabilite](#observabilite)
- [Etat des fonctionnalites](#etat-des-fonctionnalites)
- [Securite et conformite](#securite-et-conformite)
- [Tests et qualite](#tests-et-qualite)
- [Contribution](#contribution)
- [Licence](#licence)

---

## Apercu

BioCybe reproduit le cycle complet de la reponse immunitaire, de bout en
bout, dans un daemon unifie :

```
DETECTER  ->  APPRENDRE  ->  NEUTRALISER  ->  REGENERER
(signatures   (memoire,      (quarantaine,    (restauration
 YARA, ML,     reduction      cellules NK)      anti-ransomware)
 reseau)       des FP)
        + alerte (Slack/syslog/webhook) + audit immuable + metriques Prometheus
```

Principes directeurs :

- **Transparence** : code ouvert, regles lisibles, decisions tracables.
- **Reversibilite** : quarantaine, suspension de processus et restauration
  sont reversibles ; les actions destructives sont opt-in et en dry-run
  par defaut.
- **Production-ready** : pas de mode demonstration ; chaque capacite est
  testee en conditions reelles et deployable (systemd, Docker, Kubernetes).

---

## Installation

### Via pip (recommande)

```bash
git clone https://github.com/servais1983/biocybe.git
cd biocybe
pip install -e ".[soc]"     # profil SOC complet (ML + web + fileanalysis + network)
# ou : pip install -e .          # coeur seulement (scan + daemon)
# ou : pip install -e ".[all]"   # tout, y compris outils de dev
biocybe --help
```

Profils d'extras disponibles : `ml`, `web`, `fileanalysis`, `network`,
`soc`, `all`. L'API REST et le dashboard requierent l'extra `web`.

### Via Docker

```bash
docker build -t biocybe:latest .
docker run --rm -v "$PWD/samples:/samples:ro" biocybe:latest scan /samples
# daemon via compose :
docker compose up -d
```

Pour le deploiement de production (systemd, Compose durci, Kubernetes,
observabilite, sequence de mise en service), voir le
[guide de deploiement](docs/deployment.md).

### Sans installation globale (dev local)

```bash
pip install -e .
python -m biocybe scan ./un_dossier
python -m pytest tests/ -v
```

---

## Utilisation

### Scan a la demande et quarantaine

```bash
biocybe scan ./un_dossier                      # scan recursif, rapport texte
biocybe scan ./un_dossier --quarantine         # deplace les detections en quarantaine
biocybe scan ./un_dossier --quarantine --dry-run   # evaluation : detecte sans agir
biocybe scan ./un_dossier --json               # sortie machine-readable (SIEM)

biocybe quarantine list                        # affiche le manifeste
biocybe quarantine restore <id>                # restauration avec verification SHA-256
```

Exit code 1 si une menace est detectee (integrable en pipeline CI/CD). Les
fichiers en quarantaine sont indexes dans `quarantine/manifest.json` (chemin
original, SHA-256, regle declenchante, horodatage, cellule detectrice).

### Threat intelligence (abuse.ch)

```bash
export ABUSECH_AUTH_KEY="..."                  # cf. https://auth.abuse.ch
biocybe intel update                           # MalwareBazaar + URLhaus + ThreatFox
biocybe intel update --source threatfox --threatfox-days 7
biocybe intel age                              # fraicheur des feeds (exit 1 si perimes)
biocybe intel stats                            # IOCs charges localement
biocybe intel lookup evil.example.com          # recherche auto-typee (hash/host/url/ip)

# Regles YARA communautaires (opt-in)
biocybe intel rules update --source signature-base --yes --verify
```

### Detection comportementale (lymphocytes T)

```bash
pip install -e ".[ml]"
biocybe tcell train --duration 1800           # apprentissage en fonctionnement normal
biocybe tcell evaluate                         # score l'etat systeme courant
# Sortie : exit 1 + explication "cpu_percent z=+4.5sigma" si anomalie
```

### Surveillance reseau et IOCs

```bash
# IOCs dans le contenu des fichiers
biocybe scan ./dossier --network-scan

# Connexions sortantes vs feeds IOC
biocybe netmon scan                            # snapshot ponctuel
biocybe netmon watch --interval 5              # surveillance continue

# Sinkhole DNS (opt-in, reversible, root requis)
sudo biocybe netmon block apply --yes --min-confidence 75
sudo biocybe netmon block clear --yes
```

### Reponse active (cellules NK)

```bash
biocybe nk status --pid 1                      # le PID est-il protege ?
biocybe nk respond --pid 12345                 # dry-run par defaut : decrit sans agir
biocybe nk respond --pid 12345 --execute       # suspend (reversible)
biocybe nk resume --pid 12345                  # reveille un processus suspendu
biocybe nk respond --pid 12345 --action kill --allow-kill --execute
```

Garde-fous : desactivee et dry-run par defaut, liste de processus proteges
(init, systemd, lsass, svchost, BioCybe lui-meme), seuil de confiance,
anti-recyclage de PID, rate-limit, audit systematique.

### Memoire immunitaire (apprentissage cross-session)

```bash
biocybe memory stats
biocybe memory recall <hash|ip|hostname>
biocybe memory mark <hash> --type sha256 --as benign      # marque un faux positif
biocybe memory mark <hash> --type sha256 --as malicious   # confirme une menace
```

Reponse secondaire : un indicateur deja rencontre obtient un verdict
instantane, la confiance se renforce a chaque recurrence, les faux positifs
confirmes ne re-alertent plus (reduction du bruit SOC).

### Auto-regeneration (self-healing, anti-ransomware)

```bash
biocybe regen baseline /etc/nginx /var/www/html   # capture l'etat sain
biocybe regen drift                                # ecarts vs baseline (exit 1 si drift)
biocybe regen heal                                 # dry-run : montre ce qui serait restaure
biocybe regen heal --execute                       # restaure depuis le coffre integre
```

Cas ransomware : avec `regeneration.auto_heal` active, le daemon detecte une
modification de masse de fichiers proteges (signature ransomware) et restaure
automatiquement les fichiers chiffres, avec verification d'integrite et
ecriture atomique.

### Immunite collective (swarm)

```bash
export BIOCYBE_SWARM_KEY="secret-partage-du-swarm"   # signe/verifie les bundles
biocybe swarm export shared/$(hostname).json         # exporte les menaces confirmees
biocybe swarm import shared/                          # importe celles des pairs
```

Lorsqu'un noeud decouvre une menace, les autres l'apprennent sans l'avoir
rencontree (herd immunity). Bundles signes HMAC, transport-agnostique. Les
faux positifs ne sont jamais partages ; l'analyste local garde la priorite.

### API REST, dashboard et daemon

```bash
# API REST (integration SIEM/SOAR)
pip install -e ".[web]"
export BIOCYBE_API_TOKEN="$(openssl rand -hex 32)"
biocybe api serve --host 0.0.0.0 --port 8080
#   /healthz (liveness), /readyz (readiness), /api/v1/{scan,quarantine,info}, /metrics

# Dashboard SOC (lecture seule)
biocybe dashboard serve                              # http://127.0.0.1:8050

# Daemon complet : fichiers + reseau + regeneration + metriques
biocybe --watch /var/www --watch-quarantine --netmon --metrics-port 9091
```

### Quarantaine chiffree et audit immuable

```bash
export BIOCYBE_QUARANTINE_KEY="$(biocybe crypto generate-key)"   # AES-256-GCM
biocybe audit show --limit 50
biocybe audit verify                                 # verifie la chaine SHA-256
```

---

## Architecture bio-inspiree

L'architecture est composee de cellules specialisees qui collaborent via un
bus de messages interne. Chaque cellule est un module Python independant.

| Cellule | Role immunitaire | Implementation |
|---|---|---|
| Macrophages | Surveillance passive | Monitoring systeme (psutil) |
| Lymphocytes B | Identification par signature | YARA + empreintes SHA-256 |
| Lymphocytes T | Analyse comportementale | IsolationForest (scikit-learn), explication par z-scores |
| Cellules NK | Neutralisation | Suspension / arret de processus, isolation reseau |
| Memoire immunitaire | Apprentissage adaptatif | Store SQLite, reponse secondaire, suppression des faux positifs |
| Auto-regeneration | Regeneration tissulaire | Baseline d'integrite + restauration anti-ransomware |
| Immunite collective | Defense collaborative | Partage de renseignement signe entre noeuds (herd immunity) |

Capacites transverses : threat intelligence multi-source (abuse.ch), sentinelle
et moniteur reseau, API REST, dashboard SOC, notifications sortantes, journal
d'audit immuable, quarantaine chiffree.

---

## Deploiement

Trois cibles supportees, toutes durcies (voir [docs/deployment.md](docs/deployment.md)) :

- **systemd** (VM, bare-metal) : unite de service durcie + timer de refresh
  des feeds. Modeles dans `deploy/refresh/`.
- **Docker Compose** : configuration durcie (read-only, cap_drop ALL,
  no-new-privileges, limites CPU/memoire). Voir `docker-compose.yml`.
- **Kubernetes** : Deployment + Service + PVC + NetworkPolicy avec
  securityContext complet (runAsNonRoot, readOnlyRootFilesystem, seccomp,
  probes /healthz et /readyz). Voir `deploy/k8s/`.

Le refresh automatique des feeds threat intel (toutes les 6h) est fourni pour
les trois ordonnanceurs dans `deploy/refresh/`.

---

## Observabilite

Deux endpoints Prometheus complementaires :

- **API** (`/metrics` sur le port 8080) : scans, quarantaine, latence,
  fraicheur des feeds, memoire immunitaire.
- **Daemon** (`/metrics` sur le port configure via `--metrics-port`) :
  watcher temps-reel, cellules NK, moniteur reseau, regeneration, memoire,
  uptime.

Metriques cles : `biocybe_intel_feed_age_seconds`,
`biocybe_memory_disposition_total{disposition="confirmed_benign"}` (faux
positifs supprimes), `biocybe_watcher_regen_healed` (fichiers restaures).
Des regles Alertmanager d'exemple sont fournies dans `deploy/refresh/`.

Le dashboard SOC (`biocybe dashboard serve`) offre une vue de triage en
lecture seule : indicateurs cles, quarantaine, audit (verification de la
chaine SHA-256 en direct), threat intel et memoire.

---

## Etat des fonctionnalites

Toutes les capacites listees sont implementees, testees et integrees au
runtime. Voir [CHANGELOG.md](CHANGELOG.md) pour le detail par version.

| Domaine | Statut | Description |
|---|---|---|
| Distribution | Livre | pip, Docker multi-stage non-root, CI multi-OS x Python, pre-commit |
| Scan + quarantaine | Livre | CLI, YARA, hashes, dry-run, restauration verifiee SHA-256 |
| Real-time monitoring | Livre | Watcher cross-OS (watchdog), debouncing, anti-boucle |
| Threat intel | Livre | MalwareBazaar + URLhaus + ThreatFox, refresh auto, monitoring de fraicheur |
| Regles YARA communautaires | Livre | Import opt-in signature-base / YARA-Rules, anti zip-slip et zip-bomb |
| Lymphocytes T (ML) | Livre | IsolationForest sur 13 metriques, persistance, explication z-scores |
| Sentinelle reseau IOC | Livre | Extraction et lookup O(1) d'IOCs dans le contenu des fichiers |
| Moniteur reseau live | Livre | Connexions sortantes vs IOCs, sinkhole DNS reversible |
| Cellules NK | Livre | Suspend / terminate / kill avec garde-fous, audit |
| Memoire immunitaire | Livre | SQLite, reponse secondaire, suppression des faux positifs |
| Auto-regeneration | Livre | Baseline d'integrite + restauration anti-ransomware, auto-heal |
| Immunite collective | Livre | Partage de renseignement signe entre noeuds |
| API REST + Prometheus | Livre | Flask/waitress, Bearer token, /healthz /readyz /metrics |
| Dashboard SOC | Livre | UI de triage Dash, lecture seule |
| Notifications | Livre | Slack / syslog RFC 5424 / webhook, failover, rate-limit |
| Audit immuable | Livre | JSONL append-only + chaine SHA-256 tamper-evident |
| Quarantaine chiffree | Livre | AES-256-GCM (format BCE1), cle via env ou KMS |
| Supply chain | Livre | SBOM SPDX + CycloneDX (syft), scan grype, pip-audit |
| Cache YARA | Livre | Compilation mise en cache (demarrage ~200 ms) |
| Cache compilation | Livre | Pre-compilation au build Docker |
| Readiness K8s | Livre | /readyz avec 4 verifications reelles |
| Validation E2E | Livre | scripts/validate_*.py, pipeline intel valide en CI |

Modules historiques non integres au pipeline (conserves pour reference,
dependances optionnelles chargees a la demande) : `detection`,
`explainability`, `learning` (reinforcement learning / TensorFlow),
`swarm_intelligence` (colonies de fourmis). Le partage de renseignement de
production passe par le module `swarm`.

---

## Securite et conformite

- **Actions destructives opt-in et graduees** : `--dry-run`,
  `auto_heal: false`, `allow_kill: false` par defaut.
- **Quarantaine chiffree** AES-256-GCM ; sans la cle, les fichiers en
  quarantaine sont irrecuperables, y compris pour root.
- **Audit immuable** : journal append-only a chaine SHA-256, detection de
  toute modification, suppression ou permutation d'entree.
- **Supply chain** : SBOM (SPDX + CycloneDX) et scan de vulnerabilites
  generes a chaque build CI ; voir [SECURITY.md](SECURITY.md).
- **Conformite** : approche non-invasive, journal d'audit exploitable pour
  SOC 2 / ISO 27001, cadre ethique documente.
- **Secrets** : tokens et cles via variables d'environnement / secret
  manager, jamais en clair dans le code ou la configuration.

---

## Tests et qualite

```bash
python -m pytest tests/ -v          # suite complete
ruff check src tests                # lint
ruff format --check src tests       # format
```

- Suite de tests unitaires et d'integration etendue (Linux / Windows / macOS
  x Python 3.10 a 3.13).
- Validation end-to-end en conditions reelles : `scripts/validate_*.py`
  (scan, daemon, charge API, watcher en rafale, pipeline threat intel avec
  vraie connexion socket). Le pipeline intel tourne aussi en integration
  continue.
- Lint et format Ruff, audit de dependances pip-audit, SBOM et scan de
  vulnerabilites dans la CI.

---

## Contribution

Les contributions sont bienvenues :

1. Forker le projet.
2. Creer une branche (`git checkout -b feature/ma-cellule`).
3. Commiter les changements.
4. Pousser la branche et ouvrir une Pull Request.

Voir le [Guide de Contribution](CONTRIBUTING.md) et le
[Code de Conduite](CODE_OF_CONDUCT.md). L'architecture est detaillee dans
[docs/architecture.md](docs/architecture.md) ; le cadre ethique dans
[ETHICS.md](ETHICS.md).

---

## Licence

Projet distribue sous licence [MIT](LICENSE).
