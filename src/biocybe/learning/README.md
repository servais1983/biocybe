# Module d'Apprentissage

Ce module représente la "mémoire immunitaire" du système, permettant l'apprentissage continu et l'adaptation aux nouvelles menaces.

## Composants

- **reinforcement_learning.py** - Apprentissage par renforcement pour les décisions
- **federated_learning.py** - Apprentissage fédéré pour le partage de connaissances
- **threat_intelligence.py** - Gestion de la base de connaissances sur les menaces
- **model_trainer.py** - Entraînement et mise à jour des modèles
- **feedback_analyzer.py** - Analyse des retours d'expérience

## Modèles

- **rl_models/** - Modèles d'apprentissage par renforcement
- **classifiers/** - Classifieurs de malwares mis à jour
- **anomaly_models/** - Détecteurs d'anomalies adaptés

## Analogie biologique

Ce module représente principalement :
- La **mémoire immunitaire** (apprentissage des rencontres précédentes)
- La **maturation d'affinité** (amélioration continue des détecteurs)
- L'**immunité collective** (partage d'information entre systèmes)

## Technologies utilisées

- TensorFlow/PyTorch pour l'apprentissage profond
- Ray pour l'apprentissage distribué
- Neo4j pour la base de connaissances des menaces
- Méthodes de RL avancées (PPO, A2C, SAC)

## Implémentation du Reinforcement Learning

Le cœur du module utilise un agent RL qui optimise les stratégies de défense :

```python
# État: combinaison de signaux de danger
state = {
    'cpu_usage': 0.87,  # Usage CPU anormal
    'file_entropy': 7.9,  # Entropie élevée (possible chiffrement)
    'network_anomaly': 0.92,  # Communications suspectes
    'syscall_pattern': 0.76,  # Patterns d'appels système suspects
    'file_operations': 0.95  # Opérations fichiers intensives
}

# Actions possibles
actions = [
    'monitor',  # Surveiller seulement
    'isolate_process',  # Isoler le processus
    'quarantine_file',  # Mettre en quarantaine
    'terminate_process',  # Tuer le processus
    'restore_from_backup'  # Restaurer les fichiers
]

# Récompenses
rewards = {
    'threat_neutralized': +10.0,  # Menace éliminée
    'false_positive': -5.0,  # Fausse alerte
    'system_damage': -8.0,  # Dommage au système
    'missed_detection': -10.0  # Menace non détectée
}
```

## Apprentissage fédéré

Le système utilise l'apprentissage fédéré pour partager l'expérience sans compromettre les données sensibles :

1. Les modèles locaux apprennent des incidents spécifiques
2. Seuls les paramètres des modèles sont partagés (pas les données)
3. Un modèle global agrège les connaissances
4. Les modèles locaux sont mis à jour avec les paramètres améliorés

## Utilisation

```python
from learning.core import LearningEngine

# Initialisation du moteur d'apprentissage
learner = LearningEngine(config_path='config/learning.yaml')

# Enregistrement d'une expérience (action et résultat)
learner.record_experience({
    'threat_type': 'ransomware',
    'action_taken': 'isolate_and_remove',
    'success': True,
    'context': {'cpu_usage': 0.92, 'file_entropy': 7.8, 'network_anomaly': 0.88}
})

# Mise à jour des modèles
learner.update_models()

# Partage des connaissances (anonymisé)
learner.share_intelligence()
```

## Impact sur les autres modules

Le module d'apprentissage influence continuellement les autres modules :

- **Détection** : Mise à jour des règles et modèles de détection
- **Isolation** : Adaptation des stratégies d'isolation selon l'efficacité
- **Neutralisation** : Optimisation des méthodes de nettoyage et réparation

Cette boucle de rétroaction permet au système BioCybe d'évoluer et de s'adapter aux nouvelles menaces, tout comme le système immunitaire s'adapte aux nouveaux pathogènes.