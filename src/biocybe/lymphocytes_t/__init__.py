"""Module Lymphocytes T pour BioCybe.

Cellule de détection comportementale par apprentissage non-supervisé
(IsolationForest). Détecte les anomalies système sans signature
préalable, complémentaire des Lymphocytes B (basés signatures).

Voir `t_cell.py` pour les détails d'implémentation.
"""

from .t_cell import (
    DEFAULT_MODEL_DIR,
    METRIC_FEATURES,
    AnomalyExplanation,
    MetricsCollector,
    TCell,
    TCellModel,
    create_cells,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_MODEL_DIR",
    "METRIC_FEATURES",
    "AnomalyExplanation",
    "MetricsCollector",
    "TCell",
    "TCellModel",
    "create_cells",
]
