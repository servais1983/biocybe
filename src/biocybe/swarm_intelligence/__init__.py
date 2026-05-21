"""Intelligence collective héritage (colonies de fourmis) — NON intégré.

⚠️ Code historique, non branché au pipeline. Conservé pour référence /
recyclage futur. Nécessite `numpy` + `networkx` (non déclarés en deps
core). Le contenu réel est dans `legacy_swarm.py`.

**Pour le partage de renseignement production-ready (immunité collective
entre nœuds), utilise `biocybe.swarm`** — module propre, testé, signé HMAC.

Ce `__init__.py` est volontairement léger : importer
`biocybe.swarm_intelligence` ne charge plus eagerly numpy/networkx (qui
faisaient crasher l'import). Les classes sont chargées à la demande via
PEP 562 ; un message clair est levé si les deps manquent.
"""

from __future__ import annotations

__all__ = ["AntColonyDetector", "SwarmNode", "create_cells"]


def __getattr__(name: str):
    # PEP 562 : import paresseux des classes héritage.
    if name in __all__:
        try:
            from . import legacy_swarm
        except ImportError as exc:
            raise ImportError(
                "biocybe.swarm_intelligence (héritage colonies de fourmis) "
                "nécessite numpy + networkx : `pip install numpy networkx`. "
                "Pour le partage de renseignement entre nœuds production-ready, "
                "utilise `biocybe.swarm` (immunité collective, signée HMAC)."
            ) from exc
        return getattr(legacy_swarm, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
