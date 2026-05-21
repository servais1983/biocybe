"""Immunité collective — partage de renseignement entre nœuds BioCybe.

Quand un nœud découvre une menace, les autres gagnent l'immunité sans
l'avoir rencontrée (herd immunity). Transport-agnostique : bundles
signés HMAC partageables par n'importe quel canal. Voir `swarm_sync.py`.

NB : module distinct du legacy `swarm_intelligence/` (non intégré).
"""

from .swarm_sync import BUNDLE_VERSION, SWARM_KEY_ENV, ImportStats, SwarmSync

__all__ = [
    "BUNDLE_VERSION",
    "SWARM_KEY_ENV",
    "ImportStats",
    "SwarmSync",
]
