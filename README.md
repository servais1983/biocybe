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
biocybe scan ./un_dossier                  # scan récursif, rapport texte
biocybe scan ./un_dossier --quarantine     # + déplacer les détections en quarantaine
biocybe scan ./un_dossier --json           # sortie machine-readable pour SIEM
biocybe scan ./un_dossier --no-recursive   # uniquement les fichiers à plat
biocybe                                    # daemon : surveillance continue (Ctrl+C stop)
```

Exit code 1 si au moins une menace est détectée — intégrable dans un pipeline CI.
Les fichiers en quarantaine sont indexés dans `quarantine/manifest.json` (chemin
original, hash SHA-256, règle déclenchante, horodatage, cellule détectrice).

## 🗺 Roadmap

| Phase | Statut | Livrable |
|---|---|---|
| **0** Déverrouillage | ✅ | Le système démarre sans erreur ; 8 smoke tests verts |
| **1** MVP démontrable | ✅ | CLI `scan` + détection YARA + quarantaine + tests EICAR end-to-end |
| **2.1** Distribution sans friction | ✅ | `pip install`, Docker, CI multi-OS/Python, pre-commit |
| **2.2** Détection sérieuse | ⏳ | Real-time `watchdog`, feeds IOC abuse.ch, +10k règles YARA communautaires, Lymphocyte T (IsolationForest), `--dry-run`, restore quarantaine |
| **2.3** Observabilité & intégration | ⏳ | REST API (Flask), webhooks Slack/syslog, dashboard Dash, Prometheus `/metrics`, SHAP/LIME |
| **2.4** Hardening production | ⏳ | Quarantaine chiffrée, image distroless + SBOM, limites ressources, benchmark MalwareBazaar |

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
