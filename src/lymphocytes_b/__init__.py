"""
Module Lymphocytes B pour BioCybe.

Ce package implémente les cellules de type "Lymphocyte B" qui assurent
la détection des menaces basée sur des signatures connues, similaire aux
anticorps du système immunitaire biologique.
"""

from .b_cell import BCell, SignatureDatabase, ScanResult, create_cells

__version__ = "0.1.0"

# Exporter les classes principales pour faciliter l'importation
__all__ = ['BCell', 'SignatureDatabase', 'ScanResult', 'create_cells']
