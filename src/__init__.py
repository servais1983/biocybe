"""
BioCybe - Système de défense informatique bio-inspiré
----------------------------------------------------

BioCybe est une solution de cybersécurité inspirée du système immunitaire humain,
capable de détecter, isoler et neutraliser les menaces de manière autonome et adaptative.

Sous-packages disponibles (état actuel) :
- biocybe_core       : noyau, bus de messages, classes de base               [implémenté]
- macrophages        : surveillance passive (psutil)                         [implémenté]
- lymphocytes_b      : détection par signatures (YARA + hashes)              [implémenté]
- detection          : détecteurs de signatures bas niveau                   [implémenté]
- explainability     : SHAP/LIME et cadre éthique                            [implémenté]
- learning           : apprentissage par renforcement                        [implémenté]
- swarm_intelligence : intelligence collective                               [implémenté]
- isolation          : confinement des menaces                               [stub]
- neutralization     : élimination des menaces                               [stub]

Auteur : BioCybe Team
Licence : MIT
"""

__version__ = "0.1.0"
__author__ = "BioCybe Team"

# Aucun import eager au niveau du package : chaque sous-module doit être
# importé explicitement par l'appelant. Cela évite qu'un module non
# implémenté ou avec une dépendance manquante (TensorFlow, yara, etc.)
# ne casse l'ensemble du système au moment de `import src`.
