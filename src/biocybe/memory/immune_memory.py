"""Mémoire immunitaire persistante (apprentissage cross-session).

Dans le système immunitaire, les cellules mémoire B/T conservent la
trace des pathogènes rencontrés : la **réponse secondaire** (2e
exposition) est plus rapide et plus forte que la réponse primaire.
BioCybe reproduit ce mécanisme.

Ce que la mémoire apporte concrètement à un SOC :

  1. **Recall instantané** : un hash/IOC déjà vu malveillant obtient un
     verdict immédiat sans relancer YARA/ML (réponse secondaire rapide).
  2. **Suppression des faux positifs** : un analyste marque un fichier
     bénin UNE fois → il n'alerte plus jamais (réduction du bruit, la
     plaie n°1 des SOC).
  3. **Réponse renforcée** : plus un indicateur est revu malveillant,
     plus la confiance monte (réponse secondaire forte).
  4. **Historique forensique** : first_seen / last_seen / times_seen par
     indicateur, exploitable pour le threat hunting et les rapports.

Stockage : SQLite (atomique, requêtable, concurrent-safe en WAL). Mode
opt-in — BioCybe fonctionne sans, la mémoire enrichit quand activée.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.memory")

# Dispositions analyste (feedback humain)
DISPOSITION_UNREVIEWED = "unreviewed"
DISPOSITION_CONFIRMED_MALICIOUS = "confirmed_malicious"
DISPOSITION_CONFIRMED_BENIGN = "confirmed_benign"  # = faux positif

VERDICT_MALICIOUS = "malicious"
VERDICT_BENIGN = "benign"
VERDICT_SUSPICIOUS = "suspicious"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    family          TEXT,
    confidence      INTEGER DEFAULT 0,
    times_seen      INTEGER DEFAULT 1,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    source          TEXT,
    disposition     TEXT NOT NULL DEFAULT 'unreviewed',
    notes           TEXT,
    PRIMARY KEY (indicator, indicator_type)
);
CREATE INDEX IF NOT EXISTS idx_memory_disposition ON memory(disposition);
CREATE INDEX IF NOT EXISTS idx_memory_family ON memory(family);
CREATE INDEX IF NOT EXISTS idx_memory_last_seen ON memory(last_seen);
"""


@dataclass
class MemoryRecord:
    """Une entrée de mémoire immunitaire."""

    indicator: str
    indicator_type: str  # "sha256" | "md5" | "ip" | "hostname" | "url" | "path" | "family"
    verdict: str
    family: str | None
    confidence: int
    times_seen: int
    first_seen: str
    last_seen: str
    source: str | None
    disposition: str
    notes: str | None = None

    @property
    def is_confirmed_benign(self) -> bool:
        return self.disposition == DISPOSITION_CONFIRMED_BENIGN

    @property
    def is_confirmed_malicious(self) -> bool:
        return self.disposition == DISPOSITION_CONFIRMED_MALICIOUS

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> MemoryRecord:
        return cls(
            indicator=row["indicator"],
            indicator_type=row["indicator_type"],
            verdict=row["verdict"],
            family=row["family"],
            confidence=int(row["confidence"]),
            times_seen=int(row["times_seen"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            source=row["source"],
            disposition=row["disposition"],
            notes=row["notes"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "verdict": self.verdict,
            "family": self.family,
            "confidence": self.confidence,
            "times_seen": self.times_seen,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
            "disposition": self.disposition,
            "notes": self.notes,
        }


class ImmuneMemory:
    """Mémoire immunitaire persistante adossée à SQLite.

    Thread-safe : un lock protège les écritures (le daemon, l'API et le
    watcher peuvent écrire en parallèle). WAL activé pour la concurrence
    lecture/écriture.
    """

    def __init__(self, db_path: str | Path = "db/memory/immune_memory.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=10.0
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Écriture : apprentissage
    # ------------------------------------------------------------------

    def remember(
        self,
        indicator: str,
        *,
        indicator_type: str,
        verdict: str,
        confidence: int = 0,
        family: str | None = None,
        source: str | None = None,
    ) -> MemoryRecord:
        """Enregistre/met à jour une observation.

        Si l'indicateur est déjà connu : incrémente `times_seen`, met à
        jour `last_seen`, garde la confiance MAX (réponse secondaire
        renforcée), et ne dégrade jamais une disposition analyste.
        """
        now = datetime.now().isoformat(timespec="seconds")
        indicator = indicator.strip()
        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM memory WHERE indicator=? AND indicator_type=?",
                (indicator, indicator_type),
            ).fetchone()

            if existing is None:
                self._conn.execute(
                    "INSERT INTO memory (indicator, indicator_type, verdict, family, "
                    "confidence, times_seen, first_seen, last_seen, source, disposition) "
                    "VALUES (?,?,?,?,?,1,?,?,?,?)",
                    (
                        indicator,
                        indicator_type,
                        verdict,
                        family,
                        int(confidence),
                        now,
                        now,
                        source,
                        DISPOSITION_UNREVIEWED,
                    ),
                )
            else:
                new_conf = max(int(existing["confidence"]), int(confidence))
                # Le verdict ne régresse pas vers benign si déjà malicious,
                # sauf disposition analyste (gérée séparément).
                new_verdict = existing["verdict"]
                if existing["verdict"] != VERDICT_MALICIOUS and verdict == VERDICT_MALICIOUS:
                    new_verdict = VERDICT_MALICIOUS
                self._conn.execute(
                    "UPDATE memory SET times_seen=times_seen+1, last_seen=?, "
                    "confidence=?, verdict=?, family=COALESCE(?, family), "
                    "source=COALESCE(?, source) "
                    "WHERE indicator=? AND indicator_type=?",
                    (now, new_conf, new_verdict, family, source, indicator, indicator_type),
                )
            self._conn.commit()
        rec = self.recall(indicator, indicator_type)
        assert rec is not None
        return rec

    def set_disposition(
        self, indicator: str, indicator_type: str, disposition: str, *, notes: str | None = None
    ) -> bool:
        """Applique un feedback analyste (confirmed_malicious / _benign)."""
        if disposition not in (
            DISPOSITION_UNREVIEWED,
            DISPOSITION_CONFIRMED_MALICIOUS,
            DISPOSITION_CONFIRMED_BENIGN,
        ):
            raise ValueError(f"disposition invalide : {disposition}")
        with self._lock:
            cur = self._conn.execute(
                "UPDATE memory SET disposition=?, notes=COALESCE(?, notes) "
                "WHERE indicator=? AND indicator_type=?",
                (disposition, notes, indicator.strip(), indicator_type),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def forget(self, indicator: str, indicator_type: str) -> bool:
        """Supprime une entrée (ex. purge d'un faux positif corrigé)."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM memory WHERE indicator=? AND indicator_type=?",
                (indicator.strip(), indicator_type),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Lecture : recall (réponse secondaire)
    # ------------------------------------------------------------------

    def recall(self, indicator: str, indicator_type: str | None = None) -> MemoryRecord | None:
        """Retrouve une entrée. Si type non précisé, prend la 1re trouvée."""
        indicator = indicator.strip()
        if indicator_type is not None:
            row = self._conn.execute(
                "SELECT * FROM memory WHERE indicator=? AND indicator_type=?",
                (indicator, indicator_type),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM memory WHERE indicator=? ORDER BY last_seen DESC LIMIT 1",
                (indicator,),
            ).fetchone()
        return MemoryRecord.from_row(row) if row else None

    def is_known_benign(self, indicator: str, indicator_type: str | None = None) -> bool:
        """True si l'indicateur est un faux positif confirmé par un analyste."""
        rec = self.recall(indicator, indicator_type)
        return rec is not None and rec.is_confirmed_benign

    def adjust_confidence(
        self, indicator: str, base_confidence: int, indicator_type: str | None = None
    ) -> int:
        """Confiance ajustée par la mémoire immunitaire (réponse secondaire).

        Règles :
          - faux positif confirmé      → 0 (supprimé)
          - malveillant confirmé        → 100 (réponse maximale immédiate)
          - déjà vu malveillant N fois  → base + min(N, 10) (renforcement
            progressif, plafonné à 100)
          - inconnu                     → base inchangée
        """
        rec = self.recall(indicator, indicator_type)
        if rec is None:
            return int(base_confidence)
        if rec.is_confirmed_benign:
            return 0
        if rec.is_confirmed_malicious:
            return 100
        if rec.verdict == VERDICT_MALICIOUS:
            return min(100, int(base_confidence) + min(rec.times_seen, 10))
        return int(base_confidence)

    # ------------------------------------------------------------------
    # Statistiques / requêtes
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        c = self._conn
        total = c.execute("SELECT COUNT(*) FROM memory").fetchone()[0]
        by_verdict = {
            row["verdict"]: row["n"]
            for row in c.execute(
                "SELECT verdict, COUNT(*) AS n FROM memory GROUP BY verdict"
            ).fetchall()
        }
        by_disposition = {
            row["disposition"]: row["n"]
            for row in c.execute(
                "SELECT disposition, COUNT(*) AS n FROM memory GROUP BY disposition"
            ).fetchall()
        }
        return {
            "total": total,
            "by_verdict": by_verdict,
            "by_disposition": by_disposition,
            "db_path": str(self.db_path),
        }

    def top_families(self, limit: int = 10) -> list[tuple[str, int]]:
        rows = self._conn.execute(
            "SELECT family, COUNT(*) AS n FROM memory "
            "WHERE family IS NOT NULL AND family != '' "
            "GROUP BY family ORDER BY n DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [(r["family"], r["n"]) for r in rows]

    def recent(self, limit: int = 50) -> list[MemoryRecord]:
        rows = self._conn.execute(
            "SELECT * FROM memory ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [MemoryRecord.from_row(r) for r in rows]

    def iter_shareable(self, min_confidence: int = 80) -> list[MemoryRecord]:
        """Indicateurs partageables avec le swarm (immunité collective).

        Critère : menaces confirmées par un analyste OU malveillantes à
        haute confiance. On NE partage JAMAIS les faux positifs confirmés
        (décision locale, propre à l'environnement de ce nœud).
        """
        rows = self._conn.execute(
            "SELECT * FROM memory WHERE "
            "(disposition = ? OR (verdict = ? AND confidence >= ?)) "
            "AND disposition != ?",
            (
                DISPOSITION_CONFIRMED_MALICIOUS,
                VERDICT_MALICIOUS,
                int(min_confidence),
                DISPOSITION_CONFIRMED_BENIGN,
            ),
        ).fetchall()
        return [MemoryRecord.from_row(r) for r in rows]

    def most_seen(self, limit: int = 50) -> list[MemoryRecord]:
        rows = self._conn.execute(
            "SELECT * FROM memory ORDER BY times_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [MemoryRecord.from_row(r) for r in rows]


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
