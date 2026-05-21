"""Auto-régénération (self-healing) — restaure un système après attaque.

Capacité phare bio-inspirée : après élimination du pathogène, le tissu
se régénère. BioCybe restaure les fichiers critiques endommagés (ex.
chiffrés par un ransomware) depuis une baseline d'intégrité protégée.
Voir `healer.py`.
"""

from .healer import (
    BaselineEntry,
    BaselineStats,
    DriftItem,
    DriftStatus,
    HealAction,
    HealResult,
    SelfHealer,
)

__all__ = [
    "BaselineEntry",
    "BaselineStats",
    "DriftItem",
    "DriftStatus",
    "HealAction",
    "HealResult",
    "SelfHealer",
]
