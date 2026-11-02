"""Système inflammatoire BioCybe — corrélation des signaux de danger.

Relie les détections isolées des cellules (watcher, netmon, régénération,
lymphocytes T, macrophages) en incidents corrélés, explicables et mappés
MITRE ATT&CK, avec escalade locale → systémique et résolution
automatique. Voir `engine.py` pour le modèle.
"""

from .engine import (
    LEVEL_CALM,
    LEVEL_LOCAL,
    LEVEL_SYSTEMIC,
    STATUS_MERGED,
    STATUS_OPEN,
    STATUS_RESOLVED,
    TRANSITION_ESCALATED,
    TRANSITION_OPENED,
    TRANSITION_RESOLVED,
    DangerSignal,
    Incident,
    IncidentStore,
    InflammationConfig,
    InflammationEngine,
    dir_entity,
    file_entity,
    host_entity,
)
from .signals import (
    from_cell_message,
    from_connection_record,
    from_process_match,
    from_regen_event,
    from_watch_event,
)

__all__ = [
    "LEVEL_CALM",
    "LEVEL_LOCAL",
    "LEVEL_SYSTEMIC",
    "STATUS_MERGED",
    "STATUS_OPEN",
    "STATUS_RESOLVED",
    "TRANSITION_ESCALATED",
    "TRANSITION_OPENED",
    "TRANSITION_RESOLVED",
    "DangerSignal",
    "Incident",
    "IncidentStore",
    "InflammationCell",
    "InflammationConfig",
    "InflammationEngine",
    "dir_entity",
    "file_entity",
    "from_cell_message",
    "from_connection_record",
    "from_process_match",
    "from_regen_event",
    "from_watch_event",
    "host_entity",
]


def __getattr__(name):
    # InflammationCell importe biocybe_core (qui configure le logging
    # fichier à l'import) : chargé à la demande seulement.
    if name == "InflammationCell":
        from .bus_cell import InflammationCell

        return InflammationCell
    raise AttributeError(name)
