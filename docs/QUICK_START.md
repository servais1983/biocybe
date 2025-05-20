# Guide de Démarrage Rapide BioCybe

Ce document explique comment démarrer et utiliser le système BioCybe, votre système immunitaire numérique bio-inspiré, modulaire et explicable.

## 🚀 Installation

### Prérequis

- Python 3.8 ou supérieur
- Bibliothèques Python requises (voir `requirements.txt`)
- Système d'exploitation Linux, macOS ou Windows (Linux recommandé)
- Droits administrateur pour certaines fonctionnalités (optionnel)

### Installation des dépendances

```bash
# Créer un environnement virtuel (recommandé)
python -m venv biocybe-env
source biocybe-env/bin/activate  # Linux/macOS
# ou
biocybe-env\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt
```

## 🏃‍♂️ Démarrage

### Démarrage basique

```bash
# Démarrer avec la configuration par défaut
python biocybe.py

# Mode debug avec plus de journalisation
python biocybe.py --debug

# Utiliser une configuration spécifique
python biocybe.py -c chemin/vers/ma-config.yaml
```

### Démarrage en tant que service (Linux)

Vous pouvez configurer BioCybe pour s'exécuter en tant que service systemd:

```bash
# Créer un fichier de service
sudo nano /etc/systemd/system/biocybe.service

# Contenu du fichier
[Unit]
Description=BioCybe Immune System
After=network.target

[Service]
User=biocybe
Group=biocybe
WorkingDirectory=/chemin/vers/biocybe
ExecStart=/chemin/vers/biocybe-env/bin/python biocybe.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target

# Activer et démarrer le service
sudo systemctl enable biocybe
sudo systemctl start biocybe
```

## 📊 Tableau de bord Web

BioCybe inclut un tableau de bord web pour visualiser l'état du système, les menaces détectées et les actions effectuées.

1. Assurez-vous que `dashboard_enabled: true` est défini dans votre configuration
2. Accédez au tableau de bord via: http://localhost:8080 (ou le port configuré)
3. Connectez-vous avec les identifiants définis dans votre configuration

## 🔬 Comprendre les Modules Cellulaires

BioCybe est composé de plusieurs modules cellulaires bio-inspirés, chacun avec un rôle spécifique:

### Macrophages (Détection Passive)

Les cellules Macrophages surveillent en continu le système à la recherche d'activités suspectes:
- Surveillance des processus
- Monitoring réseau
- Modification de fichiers
- Utilisation des ressources système

### Lymphocytes B (Détection par Signatures)

Les cellules Lymphocytes B identifient les menaces connues grâce à des signatures:
- Empreintes de fichiers (hashes)
- Règles YARA
- Signatures de malware connues

### Lymphocytes T (Analyse Comportementale)

Les cellules Lymphocytes T détectent les comportements anormaux:
- Détection d'anomalies par apprentissage machine
- Analyse de séquences d'actions suspectes
- Identification de malwares inconnus (zero-day)

### Cellules NK (Neutralisation)

Les cellules NK interviennent pour neutraliser les menaces:
- Isolation de processus malveillants
- Mise en quarantaine de fichiers
- Blocage d'activités réseau suspectes

### Mémoire Immunitaire (Apprentissage)

La mémoire immunitaire permet au système d'apprendre et de s'améliorer:
- Stockage des signatures et comportements malveillants
- Adaptation aux nouvelles menaces
- Partage communautaire (optionnel)

### Barrière Épithéliale (Protection de Périmètre)

La barrière protège les points d'entrée du système:
- Règles de pare-feu adaptatives
- Filtrage des communications
- Protection proactive

## 🛠️ Configuration

Le fichier de configuration principal (`config/biocybe.yaml`) permet de personnaliser le comportement du système. Les sections principales sont:

- `core`: Configuration du noyau du système
- `cells`: Configuration des différents types de cellules
- `modules`: Configuration des modules spéciaux (XAI, API, etc.)
- `response`: Configuration des réponses automatiques
- `storage`: Configuration du stockage et des données
- `system`: Configuration de l'intégration avec le système d'exploitation

Consultez les commentaires dans le fichier de configuration pour plus de détails sur chaque option.

## 🧩 Extension du Système

BioCybe est conçu pour être modulaire et extensible:

1. **Création de nouvelles cellules**: Créez des sous-classes de `BiologicalCell` dans le dossier approprié
2. **Ajout de règles YARA**: Placez vos règles dans `db/signatures/yara/`
3. **Intégration d'outils tiers**: Configurez les intégrations dans votre fichier de configuration

## 📝 Journalisation

Les journaux se trouvent dans le fichier `biocybe.log`. Vous pouvez configurer le niveau de journalisation dans le fichier de configuration:

```yaml
core:
  log_level: "INFO"  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
```

## 🚧 Dépannage

### Problèmes courants

1. **Permissions insuffisantes**:
   ```
   Erreur: Permission denied
   ```
   Solution: Exécutez BioCybe avec des droits d'administrateur ou ajustez les permissions.

2. **Dépendances manquantes**:
   ```
   ImportError: No module named 'yara'
   ```
   Solution: Vérifiez que toutes les dépendances sont installées: `pip install -r requirements.txt`

3. **Configuration incorrecte**:
   ```
   Erreur lors du chargement de la configuration
   ```
   Solution: Vérifiez la syntaxe YAML de votre fichier de configuration.

### Support

Si vous rencontrez des problèmes, consultez:
- La documentation complète dans le dossier `docs/`
- Le forum de la communauté: [forum.biocybe.org](https://forum.biocybe.org)
- Le canal Discord: [discord.gg/biocybe](https://discord.gg/biocybe)

## 📖 Pour aller plus loin

- [Documentation complète](docs/README.md)
- [Tutoriels avancés](docs/tutorials/README.md)
- [API de référence](docs/api/README.md)
- [Guide du développeur](docs/developer/README.md)
