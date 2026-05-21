![biocybe](https://github.com/user-attachments/assets/faabdc39-3e07-42f0-9ec8-55258e8a876d)


# BioCybe

## 🔬 Système de cybersécurité bio-inspiré, modulaire et explicable

BioCybe est un système de cybersécurité open-source inspiré du système immunitaire biologique, offrant une alternative transparente, modulaire et éthique aux solutions commerciales fermées.

---

## 🚀 Quickstart

> **Statut** : alpha utilisable. Scan one-shot YARA + quarantaine fonctionnels, daemon avec macrophages + lymphocytes B. Cibles déployables : SOC, MSSP, équipes sécurité qui veulent une alternative open-source aux EDR commerciaux.
> Cellules T (ML anomalies), NK, mémoire immunitaire, API REST, dashboard : voir [Roadmap](#-roadmap).

### Installation (3 options)

**Option A — via pip (recommandé)**
```bash
git clone https://github.com/servais1983/biocybe.git
cd biocybe
pip install -e ".[soc]"     # profil SOC complet (ML + web + fileanalysis + network)
# ou : pip install -e .     # core seulement (scan + daemon, < 30 s)
# ou : pip install -e ".[all]"   # tout, y compris dev tools
biocybe --help
```

**Option B — via Docker**
```bash
docker build -t biocybe:latest .
docker run --rm -v "$PWD/samples:/samples:ro" biocybe:latest scan /samples
# ou avec compose pour le daemon :
docker compose up -d
```

**Option C — sans installer (dev local)**
```bash
pip install -e .            # nécessaire au moins une fois
python -m biocybe scan ./un_dossier
python -m pytest tests/ -v
```

### Usage

```bash
# --- Scan one-shot ---
biocybe scan ./un_dossier                  # scan récursif, rapport texte
biocybe scan ./un_dossier --quarantine     # + déplacer les détections en quarantaine
biocybe scan ./un_dossier --quarantine --dry-run   # éval prod : détecte sans agir
biocybe scan ./un_dossier --json           # sortie machine-readable pour SIEM
biocybe scan ./un_dossier --no-recursive

# --- Gestion de la quarantaine ---
biocybe quarantine list                    # affiche le manifeste
biocybe quarantine list --json
biocybe quarantine restore <id>            # restauration avec vérification SHA-256
biocybe quarantine restore <id> --to /chemin/alternatif
biocybe quarantine restore <id> --keep-manifest    # garde l'audit trail

# --- Threat intel : abuse.ch (3 feeds gratuits) ---
export ABUSECH_AUTH_KEY="..."              # cf. https://auth.abuse.ch (URLhaus auth optionnelle)
biocybe intel update                       # = --source all : MalwareBazaar + URLhaus + ThreatFox
biocybe intel update --source malwarebazaar           # hashes de malwares (100 derniers)
biocybe intel update --source malwarebazaar --selector time  # derniers 60 min
biocybe intel update --source urlhaus                 # URLs malveillantes 24h (CSV public)
biocybe intel update --source threatfox --threatfox-days 7  # IOCs structurés (C2, payload, botnet, max 7j)
# → db/signatures/{hashes,urlhaus,threatfox}/ alimentés pour le scanner & cellules réseau

# --- Fraîcheur des feeds (Phase 3.g) ---
biocybe intel age                          # tableau age/staleness, exit 1 si un feed stale
biocybe intel age --json --stale-after 86400   # parsing machine, seuil 24h
# Refresh auto : voir deploy/refresh/ (systemd timer, k8s CronJob, crontab)
# Prometheus : biocybe_intel_feed_age_seconds{source=...} exposé sur /metrics

# --- Sentinelle réseau IOC-aware (Phase 3.e) ---
biocybe intel stats                        # combien d'IOCs chargés depuis les feeds locaux ?
biocybe intel lookup evil.example.com      # lookup auto-typé (hash/host/url/ip détecté)
biocybe intel lookup 1.2.3.4:443 --json    # lookup IP avec port
biocybe intel lookup $(sha256sum file.exe | awk '{print $1}')   # hash d'un fichier

# Scan + détection IOCs réseau dans le contenu des fichiers
biocybe scan ./dossier --network-scan                  # signale URLs/IPs/hashes connus malveillants
biocybe scan ./dossier --network-scan --quarantine     # + quarantine si IOC trouvé
biocybe scan ./email.eml --network-scan --json         # parse les liens d'un mail suspicieux

# --- Surveillance live des connexions sortantes (Phase 3.f) ---
biocybe netmon scan                        # snapshot one-shot : connexions actives vs IOCs
biocybe netmon scan --all --json           # toutes les connexions (mode debug)
biocybe netmon scan --reverse-dns          # + résolution PTR pour enrichir
biocybe netmon watch --interval 5          # surveillance continue, Ctrl+C pour stopper
# → root/admin pour voir TOUS les processus ; sinon seulement les vôtres

# --- Sinkhole DNS via fichier hosts (Phase 3.f, opt-in) ---
sudo biocybe netmon block status           # voir si une section BioCybe est active
sudo biocybe netmon block apply --yes --min-confidence 75   # sinkhole tous les hostnames conf≥75
sudo biocybe netmon block clear --yes                       # retire la section, restaure le hosts
# → écriture atomique, backup automatique (.biocybe.bak), section délimitée, réversible

# --- Règles YARA communautaires (opt-in) ---
biocybe intel rules list                   # voir les sources disponibles
biocybe intel rules update --source signature-base --yes --verify
# → +733 règles Florian Roth/Neo23x0 actives (APT, ransomware, webshells)
biocybe intel rules update --yes           # toutes les sources
biocybe intel rules verify signature-base  # quelles règles compilent ?

# --- Lymphocyte T : détection comportementale (anomalies sans signature) ---
pip install -e ".[ml]"                     # une fois : numpy + sklearn + joblib
biocybe tcell train --duration 1800        # 30 min d'apprentissage en prod normale
biocybe tcell status                       # info sur le modèle persisté
biocybe tcell evaluate                     # score l'état système actuel
# → exit 1 + explication "cpu_percent z=+4.5σ" si anomalie détectée

# --- Quarantaine chiffrée AES-256-GCM (Phase 2.4.b) ---
# Génère une clé une fois et stocke-la dans ton secret manager
export BIOCYBE_QUARANTINE_KEY="$(biocybe crypto generate-key)"
# Active dans config/biocybe.yaml :
#   quarantine:
#     encrypt: true
# Désormais tout fichier en quarantaine est chiffré au repos.
# Format .quarantine.enc : magic "BCE1" + nonce + tag GCM + ciphertext.
# Le déchiffrement à la restauration vérifie le tag (anti-tampering).
# Sans la clé, les fichiers en quarantaine sont irrécupérables —
# y compris pour root sur la machine !

# --- Audit log immuable (compliance SOC2 / ISO 27001) ---
# Active dans config/biocybe.yaml :
#   audit:
#     enabled: true
#     path: logs/audit.jsonl
biocybe audit show --limit 50           # 50 dernières entrées
biocybe audit show --action quarantine_created --json
biocybe audit verify                    # vérifie la chaîne SHA-256
# → "AUDIT LOG ALTÉRÉ : seq=2 self_hash invalide" si tampering détecté

# --- Notifications sortantes (Slack / syslog / webhook) ---
# Configure dans config/biocybe.yaml :
#   notify:
#     slack:
#       webhook_url: https://hooks.slack.com/services/...
#       min_severity: warning
#     syslog:
#       host: siem.local
#       port: 514
#       protocol: udp
#       min_severity: info
biocybe notify list                        # liste les notifiers configurés
biocybe notify test --severity warning     # envoie un event de test
# Au runtime : tout `quarantine_file()`, alerte temps-réel watcher,
# alerte comportementale TCell est automatiquement notifiée.

# --- API REST pour intégration SIEM/SOAR ---
pip install -e ".[web]"                                # une fois : Flask + waitress + Prometheus client
export BIOCYBE_API_TOKEN="$(openssl rand -hex 32)"     # token Bearer obligatoire en prod
biocybe api serve --host 0.0.0.0 --port 8080           # waitress (Windows) ou gunicorn (Linux)

# Depuis un client (curl, SIEM, SOAR...) :
curl http://server:8080/healthz                                       # liveness, pas d'auth
curl -H "Authorization: Bearer $TOKEN" http://server:8080/api/v1/info
curl -H "Authorization: Bearer $TOKEN" -X POST \
     -H "Content-Type: application/json" \
     -d '{"path": "/uploads", "quarantine": true, "dry_run": false}' \
     http://server:8080/api/v1/scan
curl -H "Authorization: Bearer $TOKEN" http://server:8080/api/v1/quarantine
curl -H "Authorization: Bearer $TOKEN" -X POST \
     http://server:8080/api/v1/quarantine/<id>/restore
curl http://server:8080/metrics                                       # Prometheus exposition

# --- Dashboard SOC (Phase 2.3.c) ---
pip install -e ".[web]"                                # Dash + Bootstrap + Plotly
biocybe dashboard serve                                # http://127.0.0.1:8050 (lecture seule)
biocybe dashboard serve --host 0.0.0.0 --port 8050 --refresh-seconds 30
# → cartes KPI + onglets Quarantaine / Audit (vérif chaîne SHA-256 live) / Threat Intel
# → triage uniquement ; la remédiation (restore/purge) reste en CLI/API avec audit trail
# → derrière un reverse-proxy authentifié ou réseau d'admin isolé (pas d'auth applicative)

# --- Daemon avec real-time monitoring ---
biocybe --watch /var/log --watch /tmp                      # alert-only
biocybe --watch /var/log --watch-quarantine                # auto-quarantine
biocybe --watch /var/log --watch-quarantine --watch-dry-run  # simulation
```

Exit code 1 si menace détectée — intégrable dans un pipeline CI/CD.
Les fichiers en quarantaine sont indexés dans `quarantine/manifest.json` (chemin
original, hash SHA-256, règle déclenchante, horodatage, cellule détectrice).
La restauration vérifie le SHA-256 contre la valeur enregistrée (anti-tampering).

## 🗺 Roadmap

| Phase | Statut | Livrable |
|---|---|---|
| **0** Déverrouillage | ✅ | Le système démarre sans erreur ; 8 smoke tests verts |
| **1** MVP démontrable | ✅ | CLI `scan` + détection YARA + quarantaine + tests EICAR end-to-end |
| **2.1** Distribution sans friction | ✅ | `pip install`, Docker, CI multi-OS/Python, pre-commit |
| **2.2.a** Real-time monitoring | ✅ | `--watch` + watchdog + débouncing + anti-boucle |
| **2.2.b** Threat intel (MalwareBazaar) | ✅ | Hashes malwares depuis abuse.ch, signatures.json idempotent |
| **2.2.c** Règles YARA communautaires | ✅ | Import opt-in Neo23x0/signature-base (~3000), YARA-Rules/rules (~5000) avec anti zip-slip + anti zip-bomb |
| **2.2.d** Lymphocyte T (ML anomalies) | ✅ | IsolationForest sur 13 métriques psutil, persistence joblib, explication z-scores top-features, intégration bus pour scan signature ciblé |
| **2.2.e** `--dry-run` + restore | ✅ | Réversibilité totale, exigence SOC pour éval prod |
| **2.2.f** Fix règles ransomware | ✅ | `math.entropy` au lieu de `pe.entropy`, 6 règles actives |
| **2.3.a** API REST + Prometheus | ✅ | Flask + waitress/gunicorn, Bearer token auth, `/healthz` `/api/v1/{scan,quarantine,info}` `/metrics`, 20 tests d'intégration |
| **2.3.b** Webhooks Slack/syslog/HTTP | ✅ | NotifierManager avec failover, retry exp backoff, rate limit anti-storm, hook automatique sur quarantaine/détection RT/anomalie TCell, RFC 5424 syslog, 19 tests |
| **2.3.c** Dashboard Dash | ✅ | UI triage SOC (Dash + Bootstrap dark), lecture seule : cartes KPI + onglets Quarantaine/Audit/Threat Intel, charts répartition + fraicheur feeds, vérif intégrité chaîne audit en live, auto-refresh, servi via waitress. Couche données découplée et testable. `biocybe dashboard serve`. 11 tests |
| **2.4.a** Audit log immuable | ✅ | JSONL append-only + chaîne SHA-256 tamper-evident, `audit show/verify`, intégré quarantine/restore, 12 tests (tampering, swap, suppression détectés) |
| **2.4.b** Quarantaine chiffrée AES-256-GCM | ✅ | Format BCE1 (magic+nonce+tag+ciphertext), AAD=SHA-256 du clair (double sécurité), clé via env `BIOCYBE_QUARANTINE_KEY` ou KMS, `biocybe crypto generate-key`, 17 tests (tampering ciphertext/header/aad/clé tous détectés) |
| **2.4.c** Supply chain hardening | ✅ | SBOM SPDX + CycloneDX via syft, scan vulnérabilités via grype, pip-audit strict, SECURITY.md, tous les artefacts archivés 30j par run CI |
| **3.a** Cache compilation YARA | ✅ | Cache `compiled.yarc` avec fingerprint SHA-256 des sources. Mesure réelle Windows + Defender + 748 règles : cold 311s → warm 0.19s (**speedup x1626**) |
| **3.b** Pré-compile cache au build | ✅ | CLI `biocybe intel rules build-cache` + intégration `Dockerfile` (build stage). Image Docker démarre en ~200 ms même au 1er run |
| **3.c** K8s readiness probe réel | ✅ | `/readyz` (no auth, K8s-compatible) fait 4 checks réels : `quarantine_dir` writable, `rules_yara_compilable` (cache ou sources), `metrics` (prometheus OK), `auth` (token configuré + ≥16 chars). Retourne 200 ou 503 avec diagnostic détaillé |
| **3.d** Threat intel multi-source (URLhaus + ThreatFox) | ✅ | Feeds abuse.ch supplémentaires : URLhaus (URLs malveillantes 24h, CSV public sans auth, hostname index) + ThreatFox (IOCs structurés C2/payload/botnet, JSON Auth-Key, index `by_type/{hash,url,domain,ip}.json` pour lookup O(1)). CLI `intel update --source {malwarebazaar,urlhaus,threatfox,all}`. 16 tests (8 par feed, mocks API complets) |
| **3.e** Sentinelle réseau IOC-aware | ✅ | `IOCLookup` charge les feeds en mémoire (lookup O(1) hash/host/url/ip avec fallback parent domain). `NetworkSentinel` extrait URLs/IPs/hosts/hashes du contenu fichier (regex ASCII anti-binaire, denylist 30+ TLDs courants anti-FP, dédup, cap 50MB). Intégré au scanner via `--network-scan`. CLI `biocybe intel lookup <value>` et `intel stats`. 23 tests |
| **3.f** Surveillance live + sinkhole DNS | ✅ | `NetworkMonitor` polling `psutil.net_connections('inet')` (cross-platform, pas de pcap/eBPF), match remote IP/host contre `IOCLookup`, callback `on_match`, rate-limit anti-storm (N alertes/clé/heure), filtre loopback/link-local/multicast, reverse DNS optionnel. `HostsBlocker` : sinkhole DNS via section marquée du fichier hosts (écriture atomique, backup auto, validation stricte hostnames, cap 50k entrées). CLI `biocybe netmon {scan,watch}` + `netmon block {apply,clear,status}`. 21 tests |
| **3.g** Refresh auto + monitoring fraîcheur | ✅ | `feed_age` lit les `last_update.txt` → âge/staleness/IOC count par source. CLI `biocybe intel age` (exit 0/1/2). Gauges Prometheus `biocybe_intel_feed_age_seconds` / `_iocs_total` / `_stale` peuplées au scrape `/metrics`. Check `/readyz` `intel_feeds_fresh` (non bloquant). Templates de déploiement systemd (.service+.timer), k8s CronJob, crontab avec règles Alertmanager. 11 tests |

Voir [CHANGELOG.md](CHANGELOG.md) pour le détail livré à chaque version.

---

## 🧬 Architecture bio-inspirée

BioCybe s'inspire du système immunitaire pour créer une défense en profondeur, adaptative et résiliente. Notre architecture modulaire est composée de "cellules" spécialisées qui travaillent ensemble pour détecter, identifier et neutraliser les menaces.

### 1. Macrophages (Détection passive)
- Surveillance continue de l'environnement
- Détection des anomalies et comportements suspects
- Analyse passive des fichiers, processus et trafic réseau
- Première ligne de défense non-intrusive

### 2. Lymphocytes B (Identification de signature)
- Base de données de signatures de malwares
- Détection basée sur YARA et empreintes cryptographiques
- Mise à jour communautaire des définitions de menaces

### 3. Lymphocytes T (Analyse comportementale)
- Détection d'anomalies par apprentissage machine
- Surveillance du comportement des processus
- Identification des actions suspectes sans signature connue

### 4. Cellules NK (Neutralisation)
- Isolation immédiate des processus suspects
- Quarantaine des fichiers potentiellement malveillants
- Actions automatisées ou semi-automatisées selon configuration

### 5. Mémoire Immunitaire (Historique adaptatif)
- Apprentissage continu et adaptation du système
- Base de connaissances des incidents passés
- Amélioration du taux de détection et réduction des faux positifs

### 6. Autres modules inspirés de la nature
- **Algorithmes de colonies de fourmis** pour la détection collaborative
- **Systèmes épigénétiques** pour l'adaptation aux environnements spécifiques
- **Simulateurs coévolutifs** pour l'entraînement défensif

## 🔧 Technologies utilisées
```
- Python           - TensorFlow/PyTorch
- Docker           - Kubernetes (orchestration)
- YARA Rules       - Elastic Stack
- Cuckoo Sandbox   - Suricata/Zeek
- Distributed DB   - XAI frameworks
- Web APIs         - P2P Communication
```

## 🧠 IA explicable et éthique

BioCybe se distingue par :

### 📊 Visualisation claire des décisions
- Interface intuitive de visualisation des alertes et détections
- Cartographie en temps réel des menaces et des réponses du système
- Tableaux de bord personnalisables avec niveaux de détail adaptatifs
- Représentation graphique des chemins d'attaque et vecteurs de menace

### 🔍 Modèles explicables (XAI)
- Utilisation systématique de frameworks d'IA explicable
- Documentation précise des paramètres et poids des modèles
- Mécanismes d'attention visualisables pour comprendre les focus d'analyse
- Explications en langage naturel des décisions algorithmiques
- Traçabilité complète du processus décisionnel

### 📝 Règles de sécurité lisibles par les humains
- Ensemble de règles claires et documentées
- Possibilité de créer et modifier manuellement les règles
- Traduction automatique des détections complexes en explications simples
- Documentation contextuelle intégrée à l'interface

### 🛡️ Cadre éthique open-source
- Conformité RGPD intégrée dès la conception
- Approche non-invasive respectant les données sensibles
- Paramètres granulaires de confidentialité
- Audits communautaires réguliers du code source
- Charte éthique pour l'IA en cybersécurité
- Mécanismes de consentement explicite pour la collecte de données

## 📊 Différenciation avec les solutions commerciales

Contrairement aux solutions commerciales comme Darktrace, BioCybe offre :
- **Transparence complète** : Code source ouvert et documentation détaillée
- **IA explicable** : Visualisation des décisions et processus de détection
- **Décentralisation** : Fonctionne sur edge et appareils à ressources limitées
- **Adaptabilité communautaire** : Extensible par des modules tiers
- **Éthique by design** : Respect de la vie privée et conformité RGPD intégrée
- **Accessibilité universelle** : Protège aussi bien les particuliers que les organisations

## 🔬 Laboratoire Vivant & Recherche

BioCybe est aussi une plateforme de recherche avec :
- **Publications scientifiques** : Papers et documentation de recherche
- **Modules expérimentaux** : Testables par la communauté via Docker/API
- **Notebooks Jupyter** : Pour expérimentation et pédagogie
- **Challenges de sécurité** : Pour renforcer et tester le système
- **API ouverte** : Permettant à d'autres chercheurs de créer leurs propres "cellules"

## 💡 Cas d'usage

- **Protection personnelle** : Ordinateurs, maisons connectées, smartphones
- **Organisations à budget limité** : ONG, journalistes, petites entreprises
- **Infrastructure critique légère** : Systèmes médicaux, services municipaux
- **Éducation** : Formation en cybersécurité par analogie biologique
- **R&D en IA** : Plateforme d'expérimentation pour chercheurs

## 📚 Documentation & Communauté

Le dossier "docs" contient :
- Documentation technique complète
- Guides d'implémentation par module
- Explications des analogies biologiques
- Tutoriels et cas d'étude
- Publications et papiers de recherche

## 👥 Contributions

BioCybe encourage les contributions de la communauté :
1. Forker le projet
2. Créer une branche (`git checkout -b feature/nouvelleCellule`)
3. Commiter vos changements (`git commit -m 'Ajout d'un nouveau type de cellule'`)
4. Pusher sur la branche (`git push origin feature/nouvelleCellule`)
5. Ouvrir une Pull Request

Consultez notre [Guide de Contribution](CONTRIBUTING.md) et notre [Code de Conduite](CODE_OF_CONDUCT.md) pour plus d'informations.

Rejoignez notre communauté sur GitHub Discussions et Discord pour partager vos idées !

## 🧩 Architecture modulaire et extensible

BioCybe est conçu pour être facilement extensible. Notre architecture modulaire permet à chacun de créer ses propres "cellules" de défense et de les intégrer au système. Consultez notre [Documentation d'Architecture](docs/architecture.md) pour comprendre comment étendre le système.

## 🔒 Principes éthiques

Nous croyons fermement que la cybersécurité doit respecter des principes éthiques stricts. Notre [Cadre Éthique](ETHICS.md) détaille notre engagement envers la transparence, le respect de la vie privée, la non-discrimination et le consentement éclairé.

## 📄 Licence

Ce projet est sous licence [MIT](LICENSE).

## 📞 Contact

Pour toute question ou suggestion, n'hésitez pas à me contacter.
