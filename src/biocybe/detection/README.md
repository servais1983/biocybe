# Module de Détection

Ce module est responsable de l'identification des menaces, combinant des approches statiques et dynamiques inspirées du système immunitaire humain.

## Composants

### Analyse Statique

- **signature_detector.py** - Détection basée sur les signatures YARA
- **static_ml_detector.py** - Détection par machine learning sur les caractéristiques statiques
- **pe_analyzer.py** - Analyse spécifique des fichiers PE (Windows)
- **elf_analyzer.py** - Analyse spécifique des fichiers ELF (Linux)

### Analyse Dynamique

- **sandbox_manager.py** - Gestion de l'environnement sandbox
- **behavior_analyzer.py** - Analyse des comportements durant l'exécution
- **anomaly_detector.py** - Détection d'anomalies comportementales
- **network_monitor.py** - Surveillance des communications réseau

## Modèles ML

- **models/** - Modèles pré-entraînés
  - **cnn_model.h5** - Modèle CNN pour l'analyse d'images de malware
  - **transformer_model.h5** - Modèle transformer pour les séquences d'API
  - **anomaly_model.pkl** - Modèle de détection d'anomalies

## Analogie biologique

Ce module représente principalement :
- Les **anticorps** (détection de signatures)
- Les **cellules dendritiques** (analyse et présentation des menaces)
- Les **cellules T** (reconnaissance de comportements anormaux)

## Utilisation

```python
from detection.core import DetectionEngine

# Initialisation du moteur de détection
detector = DetectionEngine(config_path='config/detection.yaml')

# Analyse d'un fichier
result = detector.analyze_file('path/to/suspicious_file')

# Affichage des résultats
print(f"Malveillant: {result.is_malicious}")
print(f"Score de confiance: {result.confidence_score}")
print(f"Menaces détectées: {result.threats}")
```