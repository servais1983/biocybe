"""Immunité collective — partage de renseignement entre nœuds BioCybe.

Interprétation production-ready de l'intelligence en essaim (swarm) :
quand un nœud découvre une menace, les autres gagnent l'**immunité**
sans l'avoir rencontrée. C'est l'immunité de groupe (herd immunity)
appliquée à la cyberdéfense.

Conception **transport-agnostique** (pas de P2P fragile) : chaque nœud
exporte sa connaissance à haute confiance dans un **bundle signé**
(JSON + HMAC). Le partage du bundle se fait par n'importe quel canal
(volume partagé NFS/S3, pull HTTP, rsync…). À l'import, un nœud fusionne
les bundles des pairs dans sa mémoire immunitaire locale.

GARDE-FOUS :
  - **On ne partage que les menaces confirmées / haute confiance** —
    jamais les faux positifs (décision locale propre à l'environnement).
  - **Signature HMAC-SHA256** (clé `BIOCYBE_SWARM_KEY`) : un nœud
    n'importe que les bundles d'un pair qui partage la clé du swarm.
    Sans clé : bundles non signés acceptés en mode dev, avec warning.
  - **L'analyste local garde la priorité** : un indicateur marqué
    faux-positif localement n'est PAS réintroduit par un pair.
  - **Provenance** : chaque indicateur importé est tagué `swarm:<node>`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..memory import (
    DISPOSITION_CONFIRMED_MALICIOUS,
    VERDICT_MALICIOUS,
    ImmuneMemory,
)

logger = logging.getLogger("biocybe.swarm")

BUNDLE_VERSION = 1
SWARM_KEY_ENV = "BIOCYBE_SWARM_KEY"  # nom d'env, pas un secret


@dataclass
class ImportStats:
    imported: int = 0
    updated: int = 0
    skipped_local_fp: int = 0  # respecté car FP confirmé localement
    skipped_own: int = 0  # vient de notre propre nœud
    signature_failed: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "imported": self.imported,
            "updated": self.updated,
            "skipped_local_fp": self.skipped_local_fp,
            "skipped_own": self.skipped_own,
            "signature_failed": self.signature_failed,
            "errors": self.errors,
        }


class SwarmSync:
    """Export / import de renseignement pour l'immunité collective.

    Usage :
        sync = SwarmSync(ImmuneMemory("db/memory/immune_memory.db"))
        sync.write_bundle("shared/node-a.json")     # export
        sync.import_dir("shared/")                   # import des pairs
    """

    def __init__(
        self,
        memory: ImmuneMemory,
        *,
        node_id: str | None = None,
        swarm_key: str | None = None,
    ):
        self.memory = memory
        self.node_id = node_id or socket.gethostname()
        self.swarm_key = swarm_key or os.environ.get(SWARM_KEY_ENV)

    # ------------------------------------------------------------------
    # Signature
    # ------------------------------------------------------------------

    def _sign(self, canonical: bytes) -> str | None:
        if not self.swarm_key:
            return None
        return hmac.new(self.swarm_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> bytes:
        # Hash stable sur le contenu hors champ de signature
        body = {k: v for k, v in payload.items() if k != "hmac"}
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_bundle(self, *, min_confidence: int = 80) -> dict[str, Any]:
        """Construit un bundle des indicateurs partageables (signé si clé)."""
        records = self.memory.iter_shareable(min_confidence=min_confidence)
        indicators = [
            {
                "indicator": r.indicator,
                "indicator_type": r.indicator_type,
                "verdict": r.verdict,
                "family": r.family,
                "confidence": r.confidence,
                "disposition": r.disposition,
            }
            for r in records
        ]
        payload: dict[str, Any] = {
            "version": BUNDLE_VERSION,
            "node_id": self.node_id,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "count": len(indicators),
            "indicators": indicators,
        }
        sig = self._sign(self._canonical(payload))
        payload["hmac"] = sig  # None si pas de clé (mode dev)
        return payload

    def write_bundle(self, path: str | Path, *, min_confidence: int = 80) -> int:
        """Écrit le bundle sur disque. Retourne le nombre d'indicateurs."""
        bundle = self.export_bundle(min_confidence=min_confidence)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Swarm : bundle exporté (%d indicateurs) -> %s", bundle["count"], p)
        return bundle["count"]

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def _verify(self, payload: dict[str, Any]) -> bool:
        """Vérifie la signature HMAC. True si OK ou si pas de clé configurée."""
        provided = payload.get("hmac")
        if not self.swarm_key:
            if provided:
                logger.warning(
                    "Swarm : bundle signé mais aucune clé locale (%s) — signature non vérifiée",
                    SWARM_KEY_ENV,
                )
            return True  # mode dev : pas de clé = pas de vérif
        if not provided:
            logger.warning("Swarm : bundle non signé refusé (clé locale configurée)")
            return False
        expected = self._sign(self._canonical(payload))
        ok = hmac.compare_digest(provided, expected or "")
        if not ok:
            logger.warning("Swarm : signature HMAC invalide — bundle rejeté")
        return ok

    def import_bundle(self, payload: dict[str, Any]) -> ImportStats:
        """Fusionne un bundle pair dans la mémoire locale (immunité collective)."""
        stats = ImportStats()

        if not isinstance(payload, dict) or payload.get("version") != BUNDLE_VERSION:
            stats.errors.append("format de bundle invalide ou version incompatible")
            return stats

        if not self._verify(payload):
            stats.signature_failed = True
            return stats

        origin = str(payload.get("node_id", "unknown"))
        if origin == self.node_id:
            # C'est notre propre bundle — rien à apprendre
            stats.skipped_own = len(payload.get("indicators", []))
            return stats

        for item in payload.get("indicators", []):
            try:
                self._merge_one(item, origin, stats)
            except Exception as exc:
                stats.errors.append(str(exc))

        logger.info(
            "Swarm : import depuis '%s' — %d nouveaux, %d mis à jour, %d FP locaux respectés",
            origin,
            stats.imported,
            stats.updated,
            stats.skipped_local_fp,
        )
        return stats

    def _merge_one(self, item: dict[str, Any], origin: str, stats: ImportStats) -> None:
        indicator = item.get("indicator")
        itype = item.get("indicator_type")
        if not indicator or not itype:
            return

        # L'analyste local garde la priorité : ne pas réintroduire un FP local
        if self.memory.is_known_benign(indicator, itype):
            stats.skipped_local_fp += 1
            return

        existed = self.memory.recall(indicator, itype) is not None
        self.memory.remember(
            indicator,
            indicator_type=itype,
            verdict=item.get("verdict", VERDICT_MALICIOUS),
            confidence=int(item.get("confidence", 0) or 0),
            family=item.get("family"),
            source=f"swarm:{origin}",
        )
        # Si le pair l'avait confirmé malveillant, propager la confirmation
        # (immunité collective renforcée) — sauf si déjà disposé localement.
        if item.get("disposition") == DISPOSITION_CONFIRMED_MALICIOUS:
            rec = self.memory.recall(indicator, itype)
            if rec is not None and rec.disposition not in (DISPOSITION_CONFIRMED_MALICIOUS,):
                self.memory.set_disposition(
                    indicator,
                    itype,
                    DISPOSITION_CONFIRMED_MALICIOUS,
                    notes=f"confirmé par swarm:{origin}",
                )
        if existed:
            stats.updated += 1
        else:
            stats.imported += 1

    def read_and_import(self, path: str | Path) -> ImportStats:
        p = Path(path)
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            s = ImportStats()
            s.errors.append(f"lecture {p}: {exc}")
            return s
        return self.import_bundle(payload)

    def import_dir(self, directory: str | Path, *, pattern: str = "*.json") -> ImportStats:
        """Importe tous les bundles d'un dossier (sauf le nôtre). Agrège."""
        total = ImportStats()
        for f in sorted(Path(directory).glob(pattern)):
            s = self.read_and_import(f)
            total.imported += s.imported
            total.updated += s.updated
            total.skipped_local_fp += s.skipped_local_fp
            total.skipped_own += s.skipped_own
            total.errors.extend(s.errors)
            if s.signature_failed:
                total.signature_failed = True
        return total


__all__ = [
    "BUNDLE_VERSION",
    "SWARM_KEY_ENV",
    "ImportStats",
    "SwarmSync",
]
