"""
BioCybe - Système de défense informatique bio-inspiré
----------------------------------------------------

BioCybe est une solution de cybersécurité inspirée du système immunitaire humain,
capable de détecter, isoler et neutraliser les menaces de manière autonome et adaptative.

Sous-packages disponibles (état actuel) :
- biocybe_core       : noyau, bus de messages, classes de base               [implémenté]
- macrophages        : surveillance passive (psutil)                         [implémenté]
- lymphocytes_b      : détection par signatures (YARA + hashes)              [implémenté]
- lymphocytes_t      : détection comportementale ML (IsolationForest)        [implémenté]
- nk_cells           : réponse active (suspend/kill processus)               [implémenté]
- memory             : mémoire immunitaire persistante (apprentissage)       [implémenté]
- regeneration       : auto-régénération / self-healing (anti-ransomware)    [implémenté]
- swarm              : immunité collective entre nœuds (bundles signés)      [implémenté]
- intel              : threat intel (MalwareBazaar/URLhaus/ThreatFox)        [implémenté]
- network_sentinel   : IOCs réseau dans le contenu des fichiers              [implémenté]
- network_monitor    : surveillance live connexions + sinkhole DNS           [implémenté]
- api                : API REST (Flask) + métriques Prometheus               [implémenté]
- dashboard          : console SOC (Dash)                                    [implémenté]
- audit              : journal immuable (chaîne SHA-256)                      [implémenté]
- crypto             : quarantaine chiffrée AES-256-GCM                       [implémenté]
- notify             : notifications sortantes (Slack/syslog/webhook)        [implémenté]
- detection          : détecteurs de signatures bas niveau                   [héritage non-intégré]
- explainability     : SHAP/LIME et cadre éthique                            [héritage non-intégré]
- learning           : apprentissage par renforcement (TensorFlow)           [héritage non-intégré]
- swarm_intelligence : colonies de fourmis (numpy/networkx)                  [héritage non-intégré]
- neutralization     : élimination des menaces                               [stub]

Auteur : BioCybe Team
Licence : MIT
"""

__version__ = "0.2.0"
__author__ = "BioCybe Team"

# Aucun import eager au niveau du package : chaque sous-module doit être
# importé explicitement par l'appelant. Cela évite qu'un module non
# implémenté ou avec une dépendance manquante (TensorFlow, yara, etc.)
# ne casse l'ensemble du système au moment de `import src`.
