# Contribuer à Biocybe

Biocybe est un projet open-source qui vise à créer un système de cybersécurité bio-inspiré, modulaire et explicable. Nous accueillons chaleureusement les contributions de la communauté, qu'il s'agisse de code, de documentation, de recherche ou de retours d'expérience.

## Comment contribuer

### 1. Rejoindre la communauté

Avant de commencer à contribuer, nous vous encourageons à :
- Rejoindre notre serveur Discord pour discuter avec l'équipe et les autres contributeurs
- Parcourir les issues GitHub existantes pour voir les problèmes en cours et les fonctionnalités demandées
- Lire la documentation pour comprendre l'architecture et les principes du projet

### 2. Trouver un sujet de contribution

Vous pouvez contribuer de plusieurs façons :
- **Code** : Développer de nouvelles fonctionnalités, corriger des bugs, améliorer les performances
- **Documentation** : Améliorer les guides, ajouter des exemples, traduire le contenu
- **Recherche** : Proposer de nouvelles approches bio-inspirées, évaluer les performances des algorithmes
- **Tests** : Créer des scénarios de test, signaler des bugs, améliorer la couverture des tests
- **Design** : Améliorer l'interface utilisateur, créer des visualisations, concevoir des logos

### 3. Processus de contribution

1. **Forker le projet** sur GitHub
2. **Créer une branche** pour votre contribution (`git checkout -b feature/ma-fonctionnalite`)
3. **Développer** votre contribution en suivant les conventions de code
4. **Tester** vos modifications pour vous assurer qu'elles fonctionnent correctement
5. **Documenter** vos changements dans le code et dans la documentation
6. **Commiter** vos changements avec des messages clairs (`git commit -m 'Ajout de la fonctionnalité X'`)
7. **Pousser** votre branche sur votre fork (`git push origin feature/ma-fonctionnalite`)
8. **Créer une Pull Request** vers la branche principale du projet

## Conventions de code

- **Python** : Suivre PEP 8 pour le style de code
- **Documentation** : Utiliser des docstrings pour toutes les fonctions et classes
- **Tests** : Écrire des tests unitaires pour toutes les nouvelles fonctionnalités
- **Commits** : Utiliser des messages de commit clairs et descriptifs
- **Branches** : Nommer les branches selon leur objectif (feature/, bugfix/, docs/, etc.)

## Structure du projet

Biocybe est organisé selon une architecture modulaire inspirée du système immunitaire :

- **src/biocybe_core** : Noyau du système
- **src/macrophages** : Modules de détection passive
- **src/lymphocytes_b** : Modules d'identification de signatures
- **src/lymphocytes_t** : Modules d'analyse comportementale
- **src/neutralization** : Modules de neutralisation des menaces
- **src/learning** : Modules d'apprentissage et de mémoire immunitaire
- **src/explainability** : Modules d'explicabilité des décisions
- **src/experimental** : Modules expérimentaux en développement
- **src/epigenetics** : Modules d'adaptation aux environnements
- **src/swarm_intelligence** : Modules de détection collective
- **src/coevolution** : Modules de simulation d'attaques et défenses

## Créer de nouvelles "cellules"

Biocybe permet de créer de nouvelles "cellules" (modules) pour étendre ses capacités. Pour créer une nouvelle cellule :

1. Identifiez le type de cellule approprié (macrophage, lymphocyte B, etc.)
2. Créez une nouvelle classe qui hérite de la classe de base correspondante
3. Implémentez les méthodes requises (detect, analyze, respond, etc.)
4. Ajoutez des tests pour votre cellule
5. Documentez le fonctionnement et l'utilisation de votre cellule

Exemple de structure pour une nouvelle cellule :

```python
from src.macrophages.base import BaseMacrophage

class MyCustomMacrophage(BaseMacrophage):
    """
    Une cellule macrophage personnalisée qui détecte X.
    
    Cette cellule utilise l'algorithme Y pour détecter les menaces de type Z.
    """
    
    def __init__(self, config=None):
        super().__init__(config)
        # Initialisation spécifique
        
    def detect(self, target):
        """
        Détecte les menaces dans la cible.
        
        Args:
            target: La cible à analyser
            
        Returns:
            dict: Résultats de la détection
        """
        # Logique de détection
        return results
```

## Soumettre des recherches

Si vous souhaitez contribuer à la recherche sur Biocybe :

1. Créez un notebook Jupyter dans le dossier `docs/research`
2. Documentez votre approche, vos hypothèses et vos résultats
3. Incluez des visualisations et des exemples concrets
4. Proposez des applications pratiques pour le projet

## Processus de revue

Toutes les contributions sont soumises à un processus de revue :

1. Un mainteneur du projet examinera votre Pull Request
2. Des commentaires ou des demandes de modifications peuvent être formulés
3. Une fois les modifications approuvées, votre contribution sera fusionnée
4. Votre nom sera ajouté à la liste des contributeurs

## Code de conduite

Veuillez consulter notre [Code de Conduite](CODE_OF_CONDUCT.md) pour connaître les règles de comportement au sein de notre communauté.

## Questions et support

Si vous avez des questions ou besoin d'aide, n'hésitez pas à :
- Ouvrir une issue sur GitHub
- Poser votre question sur notre serveur Discord
- Contacter directement l'équipe de maintenance

Merci de contribuer à Biocybe et de nous aider à construire un système de cybersécurité bio-inspiré, ouvert et innovant !
