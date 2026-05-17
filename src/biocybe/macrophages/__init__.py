"""
Module Macrophages pour BioCybe.

Ce package implémente les cellules de type "Macrophage" qui assurent 
la détection passive et la surveillance continue du système pour 
repérer les premiers signes d'activité malveillante.
"""

from .macrophage import MacrophageCell, SystemMonitor, create_cells

__version__ = "0.1.0"

# Exporter les classes principales pour faciliter l'importation
__all__ = ['MacrophageCell', 'SystemMonitor', 'create_cells']
