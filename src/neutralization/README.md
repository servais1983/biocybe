# Module de Neutralisation

Ce module est responsable de l'élimination des menaces et de la réparation du système affecté, agissant comme les mécanismes d'élimination des pathogènes du système immunitaire.

## Composants

- **threat_removal.py** - Suppression sécurisée des fichiers malveillants
- **system_repair.py** - Réparation des fichiers et paramètres altérés
- **registry_cleaner.py** - Nettoyage du registre (Windows)
- **backup_manager.py** - Gestion des sauvegardes et restaurations
- **patch_manager.py** - Application de correctifs pour vulnérabilités

## Fonctionnalités

- Élimination sécurisée des menaces
- Restauration des fichiers endommagés via sauvegarde
- Correction des paramètres système altérés
- Application de correctifs ciblés
- Analyse post-incident et rapport

## Analogie biologique

Ce module représente principalement :
- Les **phagocytes** (élimination des menaces)
- Les **cellules réparatrices** (restauration des fichiers)
- La **cicatrisation** (renforcement des zones vulnérables)

## Technologies utilisées

- Systèmes de restauration de points de sauvegarde
- Vérification d'intégrité cryptographique
- Techniques de récupération de données
- Injection de correctifs en temps réel

## Utilisation

```python
from neutralization.core import NeutralizationEngine

# Initialisation du moteur de neutralisation
neutralizer = NeutralizationEngine(config_path='config/neutralization.yaml')

# Suppression d'une menace
neutralizer.remove_threat('path/to/quarantined_file')

# Réparation du système
repair_report = neutralizer.repair_system()

# Restauration depuis sauvegarde
neutralizer.restore_from_backup(file_path='path/to/corrupted_file')

# Application de correctifs
neutralizer.apply_patches(vulnerability_id='CVE-2025-1234')
```

## Stratégies de neutralisation

Le module emploie plusieurs stratégies selon le type de menace :

1. **Suppression directe** : Pour les fichiers clairement malveillants
2. **Nettoyage sélectif** : Pour les fichiers légitimes infectés
3. **Restauration** : Pour les fichiers endommagés/corrompus
4. **Correction de configuration** : Pour les modifications système malveillantes

La stratégie est sélectionnée automatiquement en fonction de l'analyse du module de détection et des recommandations du module d'apprentissage, minimisant les perturbations sur le système.