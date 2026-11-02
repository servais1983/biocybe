"""Cellule d'écoute du bus : relaie les alertes des cellules d'analyse
(lymphocytes T, macrophages) vers le moteur inflammatoire."""

from __future__ import annotations

from ..biocybe_core.core import BiologicalCell, CellMessage
from .engine import InflammationEngine
from .signals import from_cell_message

_LISTENED = frozenset({"alert_anomaly"})


class InflammationCell(BiologicalCell):
    """Cellule passive : n'émet rien sur le bus, ne fait qu'écouter."""

    def __init__(self, engine: InflammationEngine, name: str = "inflammation"):
        super().__init__(name, "inflammation", {"tick_interval": 5.0})
        self.engine = engine

    def handle_message(self, message: CellMessage) -> bool:
        # Surcharge : on écoute tout le broadcast mais on ignore SILENCIEUSEMENT
        # les types non pertinents (le parent loggue un warning par message).
        if message.msg_type not in _LISTENED:
            return False
        self.stats["messages_received"] += 1
        for signal in from_cell_message(message.msg_type, message.payload, message.source):
            self.engine.ingest(signal)
        return True

    def _process_cycle(self) -> None:  # pas de travail périodique propre
        return None
