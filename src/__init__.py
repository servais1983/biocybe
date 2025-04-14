"""
BioCybe - Système de défense informatique bio-inspiré
----------------------------------------------------

BioCybe est une solution de cybersécurité inspirée du système immunitaire humain,
capable de détecter, isoler et neutraliser les menaces de manière autonome et adaptative.

Ce package contient les quatre modules principaux qui constituent le système :
- detection : Identification des menaces (anticorps/lymphocytes)
- isolation : Confinement des menaces (réponse inflammatoire)
- neutralization : Élimination des menaces (phagocytes)
- learning : Apprentissage et adaptation (mémoire immunitaire)

Auteur: BioCybe Team
Licence: MIT
Version: 0.1.0
"""

__version__ = '0.1.0'
__author__ = 'BioCybe Team'

from . import detection
from . import isolation
from . import neutralization
from . import learning
from . import utils

# Points d'entrée principaux
def scan(path):
    """Analyse un fichier ou un dossier pour détecter des menaces"""
    return detection.scan(path)

def isolate(target, isolation_level="medium"):
    """Isole une menace identifiée"""
    return isolation.isolate(target, level=isolation_level)

def neutralize(threat_id):
    """Neutralise une menace identifiée"""
    return neutralization.neutralize(threat_id)

def monitor_system():
    """Lance la surveillance du système"""
    return detection.monitor_system()
