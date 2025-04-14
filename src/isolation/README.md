# Module d'Isolation

Ce module est responsable du confinement des menaces détectées pour empêcher leur propagation, fonctionnant comme la réponse inflammatoire du système immunitaire.

## Composants

- **quarantine_manager.py** - Gestion de la zone de quarantaine
- **container_manager.py** - Gestion des conteneurs d'isolation
- **network_isolation.py** - Isolation réseau des systèmes compromis
- **process_isolation.py** - Isolation et suspension des processus suspects

## Fonctionnalités

- Création d'environnements isolés pour l'exécution sécurisée
- Restriction des accès fichiers et réseau
- Quarantaine temporaire ou permanente
- Surveillance des tentatives d'évasion

## Analogie biologique

Ce module représente principalement :
- La **réponse inflammatoire** (confinement des menaces)
- Les **barrières physiques** (isolation réseau)
- Les **cellules NK** (blocage rapide des processus dangereux)

## Technologies utilisées

- Docker pour la conteneurisation
- Cgroups pour la limitation des ressources
- Namespaces Linux pour l'isolation
- Règles de firewall pour le blocage réseau

## Utilisation

```python
from isolation.core import IsolationEngine

# Initialisation du moteur d'isolation
isolator = IsolationEngine(config_path='config/isolation.yaml')

# Mise en quarantaine d'un fichier
isolator.quarantine_file('path/to/malicious_file')

# Isolation d'un processus
isolator.isolate_process(pid=1234)

# Isolation réseau
isolator.restrict_network_access(ip_address='192.168.1.100')
```

## Stratégies d'isolation

Le module utilise une approche progressive pour l'isolation :

1. **Isolation légère** : Surveillance accrue, restrictions minimales
2. **Isolation modérée** : Restrictions des accès, limitation des ressources
3. **Isolation stricte** : Quarantaine complète, blocage réseau, suspension

Le niveau d'isolation est déterminé par la gravité de la menace, évaluée par le module de détection et les recommandations du module d'apprentissage.