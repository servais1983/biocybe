"""Cellules NK (Natural Killer) — réponse active sur processus malveillants.

Le seul module BioCybe qui pose des actions destructives. Conçu
ultra-conservateur : désactivé + dry-run par défaut, liste de process
protégés, seuil de confiance, kill opt-in séparé, rate-limit, audit
systématique. Voir `nk_cell.py` pour le détail des garde-fous.
"""

from .nk_cell import NKAction, NKCell, NKConfig, NKDecision

__all__ = [
    "NKAction",
    "NKCell",
    "NKConfig",
    "NKDecision",
]
