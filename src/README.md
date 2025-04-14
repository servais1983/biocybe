# Code Source BioCybe

Ce dossier contient le code source du projet BioCybe, organisé en modules correspondant à l'architecture définie.

## Structure

- **detection/** - Module de détection des menaces
- **isolation/** - Module d'isolation et confinement
- **neutralization/** - Module de neutralisation et réparation
- **learning/** - Module d'apprentissage et mémoire
- **utils/** - Utilitaires et fonctions communes
- **api/** - Interface API REST
- **ui/** - Interface utilisateur
- **config/** - Fichiers de configuration

## Environnement de développement

```bash
# Création de l'environnement virtuel
python -m venv venv

# Activation de l'environnement (Linux/macOS)
source venv/bin/activate

# Activation de l'environnement (Windows)
venv\Scripts\activate

# Installation des dépendances
pip install -r requirements.txt
```

## Tests

```bash
# Exécution des tests unitaires
python -m pytest tests/

# Exécution des tests d'intégration
python -m pytest tests/integration/
```

## Contribution

Veuillez consulter le fichier CONTRIBUTING.md à la racine du projet pour les directives de contribution.