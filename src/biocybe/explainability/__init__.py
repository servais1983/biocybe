"""Explicabilité et cadre éthique BioCybe — partiellement héritage.

`ethical_framework` (EthicalFramework, DataProcessingActivity) est pur
stdlib et toujours importable. `explainer` (ExplainableDecision,
DecisionVisualizer) repose sur des dépendances lourdes (lime, shap,
captum, matplotlib) NON déclarées en core — importé en lazy pour ne pas
faire crasher `import biocybe.explainability`.

Note : ce module est historique (XAI non branché au pipeline actif). La
détection comportementale en production passe par `biocybe.lymphocytes_t`
(IsolationForest) qui fournit déjà une explication par z-scores.
"""

from __future__ import annotations

# Classes légères (stdlib) — import direct sûr.
from .ethical_framework import DataProcessingActivity, EthicalFramework

__all__ = [
    "DataProcessingActivity",
    "DecisionVisualizer",
    "EthicalFramework",
    "ExplainableDecision",
]

# Classes XAI lourdes — chargées à la demande (PEP 562).
_LAZY = {"ExplainableDecision", "DecisionVisualizer"}


def __getattr__(name: str):
    if name in _LAZY:
        try:
            from . import explainer
        except ImportError as exc:
            raise ImportError(
                "biocybe.explainability.explainer (XAI héritage) nécessite "
                "lime + shap + captum + matplotlib : `pip install lime shap "
                "captum matplotlib`. NB : la détection comportementale active "
                "de BioCybe est expliquée par z-scores via `biocybe tcell`."
            ) from exc
        return getattr(explainer, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
