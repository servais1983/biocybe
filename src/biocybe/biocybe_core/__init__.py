"""
BioCybe Core - Noyau du système immunitaire numérique.

Ce package fournit le cœur du système BioCybe, ainsi que les interfaces
communes pour tous les modules cellulaires.
"""

from .core import BioCybeCore, BiologicalCell, CellMessage

__version__ = "0.1.0"
__author__ = "BioCybe Team"

# Exporter les classes principales pour faciliter l'importation
__all__ = ['BioCybeCore', 'BiologicalCell', 'CellMessage']
