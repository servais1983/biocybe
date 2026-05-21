"""Mémoire immunitaire persistante (apprentissage cross-session).

Conserve la trace des pathogènes rencontrés pour une réponse secondaire
plus rapide et plus forte : recall instantané, suppression des faux
positifs confirmés, renforcement de confiance sur menaces récurrentes.
Voir `immune_memory.py`.
"""

from .immune_memory import (
    DISPOSITION_CONFIRMED_BENIGN,
    DISPOSITION_CONFIRMED_MALICIOUS,
    DISPOSITION_UNREVIEWED,
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    ImmuneMemory,
    MemoryRecord,
)

__all__ = [
    "DISPOSITION_CONFIRMED_BENIGN",
    "DISPOSITION_CONFIRMED_MALICIOUS",
    "DISPOSITION_UNREVIEWED",
    "VERDICT_BENIGN",
    "VERDICT_MALICIOUS",
    "VERDICT_SUSPICIOUS",
    "ImmuneMemory",
    "MemoryRecord",
]
