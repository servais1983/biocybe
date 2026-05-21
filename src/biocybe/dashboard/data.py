"""Couche données du dashboard SOC (Phase 2.3.c).

Volontairement **découplée de Dash** : ces fonctions lisent les
artefacts BioCybe sur disque (manifeste de quarantaine, audit log,
feeds threat intel) et renvoient des structures Python simples. Elles
sont testables sans navigateur ni serveur web, et réutilisables par
n'importe quelle UI (Dash aujourd'hui, autre chose demain) ou export.

Aucune écriture, aucune action destructive : le dashboard est en
lecture seule. La remédiation (restore, purge) reste dans la CLI/API
avec audit trail — un opérateur SOC ne supprime pas une preuve d'un
clic sans traçabilité.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.dashboard.data")


@dataclass
class DashboardConfig:
    """Chemins des sources de données du dashboard."""

    quarantine_dir: str = "quarantine"
    audit_path: str = "logs/audit.jsonl"
    signatures_db_path: str = "db/signatures"
    memory_db_path: str = "db/memory/immune_memory.db"
    # Combien d'entrées récentes afficher dans les tables
    recent_limit: int = 200
    # Seuil staleness des feeds (s) — repris de la Phase 3.g
    feed_stale_threshold_s: int = 48 * 3600


@dataclass
class DashboardData:
    """Snapshot agrégé pour le rendu du dashboard."""

    config: DashboardConfig = field(default_factory=DashboardConfig)

    # ------------------------------------------------------------------
    # Quarantaine
    # ------------------------------------------------------------------

    def quarantine_summary(self) -> dict[str, Any]:
        """Agrège le manifeste de quarantaine."""
        from ..isolation import list_quarantine

        try:
            entries = list_quarantine(self.config.quarantine_dir)
        except Exception as exc:  # défense : manifeste corrompu/absent
            logger.warning("dashboard: quarantine illisible: %s", exc)
            entries = []

        by_family: Counter[str] = Counter()
        by_severity: Counter[str] = Counter()
        by_detector: Counter[str] = Counter()
        total_size = 0
        encrypted_count = 0

        for e in entries:
            extra = e.get("extra") or {}
            family = extra.get("family") or "inconnue"
            severity = extra.get("severity") or "inconnue"
            detector = e.get("detected_by") or "inconnu"
            by_family[str(family)] += 1
            by_severity[str(severity)] += 1
            by_detector[str(detector)] += 1
            total_size += int(e.get("size_bytes", 0) or 0)
            if e.get("encrypted"):
                encrypted_count += 1

        # Table : on garde les champs utiles au triage, triés par date desc
        rows = sorted(
            entries,
            key=lambda e: e.get("quarantined_at", ""),
            reverse=True,
        )[: self.config.recent_limit]
        table = [
            {
                "id": e.get("quarantine_id", ""),
                "quarantined_at": e.get("quarantined_at", ""),
                "original_path": e.get("original_path", ""),
                "family": (e.get("extra") or {}).get("family") or "inconnue",
                "severity": (e.get("extra") or {}).get("severity") or "inconnue",
                "detected_by": e.get("detected_by") or "inconnu",
                "reason": e.get("reason", ""),
                "size_bytes": int(e.get("size_bytes", 0) or 0),
                "encrypted": bool(e.get("encrypted")),
            }
            for e in rows
        ]

        return {
            "total": len(entries),
            "total_size_bytes": total_size,
            "encrypted_count": encrypted_count,
            "by_family": dict(by_family.most_common()),
            "by_severity": dict(by_severity.most_common()),
            "by_detector": dict(by_detector.most_common()),
            "table": table,
        }

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def audit_summary(self) -> dict[str, Any]:
        """Lit l'audit log, vérifie l'intégrité de la chaîne, agrège."""
        from ..audit import AuditLog

        path = Path(self.config.audit_path)
        if not path.exists():
            return {
                "exists": False,
                "total": 0,
                "chain_ok": None,
                "chain_errors": [],
                "by_action": {},
                "by_outcome": {},
                "table": [],
            }

        try:
            log = AuditLog(path)
            entries = log.read_all()
            chain_ok, chain_errors = log.verify()
        except Exception as exc:
            logger.warning("dashboard: audit illisible: %s", exc)
            return {
                "exists": True,
                "total": 0,
                "chain_ok": False,
                "chain_errors": [f"read_error: {exc}"],
                "by_action": {},
                "by_outcome": {},
                "table": [],
            }

        by_action: Counter[str] = Counter()
        by_outcome: Counter[str] = Counter()
        for e in entries:
            by_action[e.action] += 1
            by_outcome[e.outcome] += 1

        recent = sorted(entries, key=lambda e: e.seq, reverse=True)[: self.config.recent_limit]
        table = [
            {
                "seq": e.seq,
                "ts": e.ts,
                "actor": e.actor,
                "action": e.action,
                "outcome": e.outcome,
                "details": _truncate_details(e.details),
            }
            for e in recent
        ]

        return {
            "exists": True,
            "total": len(entries),
            "chain_ok": chain_ok,
            "chain_errors": chain_errors,
            "by_action": dict(by_action.most_common()),
            "by_outcome": dict(by_outcome.most_common()),
            "table": table,
        }

    # ------------------------------------------------------------------
    # Threat intel
    # ------------------------------------------------------------------

    def intel_summary(self) -> dict[str, Any]:
        """Combine feed_age (fraicheur) + IOCLookup (compteurs chargés)."""
        from ..intel.feed_age import read_feed_ages
        from ..intel.ioc_lookup import IOCLookup

        report = read_feed_ages(
            self.config.signatures_db_path,
            stale_threshold_s=self.config.feed_stale_threshold_s,
        )

        try:
            lookup = IOCLookup.from_db(self.config.signatures_db_path)
            lookup_stats = lookup.stats()
            lookup_total = lookup.total
        except Exception as exc:
            logger.warning("dashboard: IOCLookup illisible: %s", exc)
            lookup_stats = {}
            lookup_total = 0

        feeds_table = []
        for f in report.feeds:
            d = f.to_dict()
            feeds_table.append(
                {
                    "source": d["source"],
                    "label": d["label"],
                    "last_update": d["last_update"] or "—",
                    "age_human": d["age_human"],
                    "age_seconds": d["age_seconds"],
                    "ioc_count": d["ioc_count"],
                    "stale": d["stale"],
                }
            )

        return {
            "any_stale": report.any_stale,
            "all_missing": report.all_missing,
            "feeds": feeds_table,
            "lookup_total": lookup_total,
            "lookup_by_type": lookup_stats,
        }

    # ------------------------------------------------------------------
    # Mémoire immunitaire
    # ------------------------------------------------------------------

    def memory_summary(self) -> dict[str, Any]:
        """Agrège la mémoire immunitaire (apprentissage cross-session)."""
        from pathlib import Path as _Path

        if not _Path(self.config.memory_db_path).exists():
            return {
                "exists": False,
                "total": 0,
                "by_verdict": {},
                "by_disposition": {},
                "top_families": [],
                "table": [],
            }
        try:
            from ..memory import ImmuneMemory

            mem = ImmuneMemory(self.config.memory_db_path)
            stats = mem.stats()
            families = mem.top_families(10)
            recent = mem.most_seen(self.config.recent_limit)
            mem.close()
        except Exception as exc:
            logger.warning("dashboard: mémoire illisible: %s", exc)
            return {
                "exists": True,
                "total": 0,
                "by_verdict": {},
                "by_disposition": {},
                "top_families": [],
                "table": [],
            }

        table = [
            {
                "indicator": r.indicator[:60],
                "type": r.indicator_type,
                "verdict": r.verdict,
                "family": r.family or "—",
                "times_seen": r.times_seen,
                "confidence": r.confidence,
                "disposition": r.disposition,
                "last_seen": r.last_seen,
            }
            for r in recent
        ]
        return {
            "exists": True,
            "total": stats["total"],
            "by_verdict": stats["by_verdict"],
            "by_disposition": stats["by_disposition"],
            "top_families": families,
            "table": table,
        }

    # ------------------------------------------------------------------
    # KPIs d'overview
    # ------------------------------------------------------------------

    def overview(self) -> dict[str, Any]:
        """Chiffres-clés pour les cartes en haut du dashboard."""
        q = self.quarantine_summary()
        a = self.audit_summary()
        i = self.intel_summary()

        # Sévérité dominante en quarantaine (pour pastille de couleur)
        worst_severity = "none"
        for sev in ("critical", "high", "medium", "low"):
            if sev in q["by_severity"]:
                worst_severity = sev
                break

        return {
            "quarantine_total": q["total"],
            "quarantine_worst_severity": worst_severity,
            "audit_total": a["total"],
            "audit_chain_ok": a["chain_ok"],
            "intel_total_iocs": i["lookup_total"],
            "intel_any_stale": i["any_stale"],
            "intel_all_missing": i["all_missing"],
        }

    def snapshot(self) -> dict[str, Any]:
        """Snapshot complet en un appel (utile pour export JSON / tests)."""
        return {
            "overview": self.overview(),
            "quarantine": self.quarantine_summary(),
            "audit": self.audit_summary(),
            "intel": self.intel_summary(),
            "memory": self.memory_summary(),
        }


def _truncate_details(details: dict[str, Any], max_len: int = 160) -> str:
    """Représente le dict details en chaîne courte pour la table."""
    import json

    try:
        s = json.dumps(details, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        s = str(details)
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


__all__ = [
    "DashboardConfig",
    "DashboardData",
]
