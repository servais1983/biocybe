"""Apprentissage à partir des incidents clos — tolérance immunitaire.

Biologie : la **tolérance périphérique** apprend au système immunitaire à
ne plus attaquer un antigène reconnu comme inoffensif, sans affaiblir la
réponse contre le reste. La **mémoire** renforce la réponse contre un
agresseur déjà rencontré.

Ici : l'analyste qualifie un incident (``biocybe incidents mark``) en
**faux positif** ou **vrai positif**. Chaque signal de l'incident a une
*signature* stable (type + entités durables : chemin d'exe, IOC, dossier ;
jamais un PID). Le moteur applique ensuite un facteur sur le poids des
signaux de même signature :

  - faux positif confirmé n fois -> ``0.5 ** n`` (plancher ``floor``,
    défaut 0.1 : jamais une suppression totale) ;
  - vrai positif confirmé n fois -> ``1 + 0.25 * n`` (max ``max_boost``) ;
    un vrai positif **l'emporte** sur des faux positifs (sécurité d'abord).

Garde-fous anti-abus :
  - pas de tolérance pour un signal sans entité stable (anomalie hôte) :
    impossible de rendre « toute anomalie CPU » inoffensive d'un coup ;
  - la signature inclut l'entité exacte : tolérer ``/opt/backup/agent``
    ne tolère pas le même comportement depuis ``/tmp/agent`` ;
  - chaque qualification est auditée (CLI) et le facteur appliqué apparaît
    dans la chronologie de l'incident (« xN tolérance »).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.inflammation.feedback")

VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_TRUE_POSITIVE = "true_positive"
VERDICTS = (VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE)

FEEDBACK_FILENAME = "dispositions.jsonl"


def signal_signature(kind: str, entities: Iterable[str]) -> str:
    """Signature stable d'un signal ("" si aucune entité durable).

    Exclut les PID (recyclés, éphémères) et l'agrégat hôte.
    """
    stable = sorted(
        e for e in entities if e and not e.startswith("pid:") and not e.startswith("host:")
    )
    if not stable:
        return ""
    return f"{kind}|{'|'.join(stable)}"


def feedback_path_for(incidents_path: str | os.PathLike) -> Path:
    """Le journal des qualifications vit à côté du journal d'incidents."""
    return Path(incidents_path).parent / FEEDBACK_FILENAME


class FeedbackStore:
    """Journal JSONL append-only des qualifications analyste."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._lock = threading.Lock()

    def mark(
        self, incident_id: str, verdict: str, *, analyst: str = "", notes: str = ""
    ) -> dict[str, Any]:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict invalide {verdict!r} (attendu : {', '.join(VERDICTS)})")
        rec = {
            "ts": time.time(),
            "incident_id": incident_id,
            "verdict": verdict,
            "analyst": analyst,
            "notes": notes,
        }
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def load(self) -> dict[str, dict[str, Any]]:
        """``{incident_id: dernière qualification}`` (la plus récente fait foi)."""
        latest: dict[str, dict[str, Any]] = {}
        if not self.path.exists():
            return latest
        with self.path.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                try:
                    rec = json.loads(raw)
                    if rec.get("verdict") in VERDICTS and rec.get("incident_id"):
                        latest[rec["incident_id"]] = rec
                except (json.JSONDecodeError, AttributeError):
                    continue
        return latest

    def mtime(self) -> float:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return 0.0


@dataclass
class ToleranceModel:
    """Facteurs appris par signature de signal."""

    fp_counts: Counter = field(default_factory=Counter)
    tp_counts: Counter = field(default_factory=Counter)
    floor: float = 0.1
    max_boost: float = 1.5

    def factor(self, kind: str, entities: Iterable[str]) -> float:
        sig = signal_signature(kind, entities)
        if not sig:
            return 1.0
        tp = self.tp_counts.get(sig, 0)
        if tp:
            return min(self.max_boost, 1.0 + 0.25 * tp)
        fp = self.fp_counts.get(sig, 0)
        if fp:
            return max(self.floor, 0.5**fp)
        return 1.0

    def entries(self) -> list[dict[str, Any]]:
        sigs = set(self.fp_counts) | set(self.tp_counts)
        out = []
        for sig in sorted(sigs):
            kind, _, ents = sig.partition("|")
            out.append(
                {
                    "signature": sig,
                    "kind": kind,
                    "entities": ents.split("|") if ents else [],
                    "false_positives": self.fp_counts.get(sig, 0),
                    "true_positives": self.tp_counts.get(sig, 0),
                    "factor": round(self.factor(kind, ents.split("|")), 3),
                }
            )
        return out

    @classmethod
    def build(
        cls,
        incidents: dict[str, dict[str, Any]],
        feedback: dict[str, dict[str, Any]],
        *,
        floor: float = 0.1,
        max_boost: float = 1.5,
    ) -> ToleranceModel:
        """Construit le modèle depuis les snapshots d'incidents + qualifications."""
        model = cls(floor=floor, max_boost=max_boost)
        for inc_id, rec in feedback.items():
            inc = incidents.get(inc_id)
            if inc is None:
                continue
            target = (
                model.fp_counts if rec["verdict"] == VERDICT_FALSE_POSITIVE else model.tp_counts
            )
            # Une signature compte au plus une fois par incident
            sigs = {
                signal_signature(s.get("kind", ""), s.get("entities") or [])
                for s in inc.get("signals") or []
            }
            for sig in sigs:
                if sig:
                    target[sig] += 1
        return model

    @classmethod
    def from_paths(
        cls, incidents_path: str | os.PathLike, *, floor: float = 0.1, max_boost: float = 1.5
    ) -> ToleranceModel:
        from .engine import IncidentStore

        incidents = IncidentStore(incidents_path).load_latest()
        feedback = FeedbackStore(feedback_path_for(incidents_path)).load()
        return cls.build(incidents, feedback, floor=floor, max_boost=max_boost)
