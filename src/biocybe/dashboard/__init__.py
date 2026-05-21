"""Dashboard SOC BioCybe (Phase 2.3.c).

Couche données (`data.py`) découplée de Dash + UI Dash (`app.py`).
La couche données est toujours importable ; l'UI nécessite l'extra
`[web]` (dash, plotly, dash-bootstrap-components).
"""

from .data import DashboardConfig, DashboardData

__all__ = [
    "DashboardConfig",
    "DashboardData",
]
