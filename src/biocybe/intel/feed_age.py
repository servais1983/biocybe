"""Mesure l'âge des feeds threat intel (Phase 3.g).

Chaque updater (`update_signatures_from_malwarebazaar`,
`update_urlhaus_iocs`, `update_threatfox_iocs`) écrit un fichier
`last_update.txt` (ISO 8601) au moment du refresh. Ce module lit
ces timestamps et expose :

  - l'âge en secondes par source
  - un drapeau `stale` si > seuil configurable (défaut 48h)
  - un compteur d'IOCs par source pour mesurer la fraicheur "utile"

Utilisé par :
  - `biocybe intel age` (CLI, exit non-zero si stale)
  - `/readyz` (check K8s : warning si feeds stale)
  - `/metrics` (Gauges Prometheus `biocybe_intel_feed_age_seconds`
    + `biocybe_intel_feed_iocs_total`)

Pourquoi c'est nécessaire pour un SOC :
  - Threat intel = denrée périssable. Un domaine flaggé il y a 6 mois
    a probablement été repris par un service légitime ou nettoyé.
  - Sans monitoring de l'âge, un cron qui casse silencieusement
    transforme BioCybe en passoire sans alerte. La Gauge Prometheus
    permet d'alerter via Grafana/Alertmanager dès que `feed_age > 86400`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.intel.feed_age")

# Sources connues : (clé logique, sous-dossier db/signatures/, label affichable).
KNOWN_FEEDS: tuple[tuple[str, str, str], ...] = (
    ("malwarebazaar", "hashes", "abuse.ch/MalwareBazaar"),
    ("urlhaus", "urlhaus", "abuse.ch/URLhaus"),
    ("threatfox", "threatfox", "abuse.ch/ThreatFox"),
)

# Seuil par défaut : 48 h. abuse.ch publie en continu donc 24 h est ok
# mais on garde 48 h pour tolérer une panne ponctuelle du cron.
DEFAULT_STALE_THRESHOLD_S = 48 * 3600


@dataclass
class FeedAge:
    """État d'un feed sur disque."""

    source: str  # clé logique
    label: str  # label affichable
    path: Path  # chemin db/signatures/<source>/
    last_update_file: Path  # last_update.txt
    last_update: datetime | None = None  # None si jamais récupéré
    age_seconds: float | None = None  # None si pas de timestamp
    ioc_count: int = 0  # estimation à partir des fichiers index
    stale_threshold_s: float = DEFAULT_STALE_THRESHOLD_S
    error: str | None = None

    @property
    def exists(self) -> bool:
        return self.last_update is not None

    @property
    def stale(self) -> bool:
        """True si le feed n'a jamais été récupéré ou est trop vieux."""
        if self.age_seconds is None:
            return True
        return self.age_seconds > self.stale_threshold_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "label": self.label,
            "path": str(self.path),
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "age_seconds": (round(self.age_seconds, 2) if self.age_seconds is not None else None),
            "age_human": _human_age(self.age_seconds),
            "ioc_count": self.ioc_count,
            "stale": self.stale,
            "stale_threshold_s": self.stale_threshold_s,
            "error": self.error,
        }


@dataclass
class FeedAgeReport:
    """Rapport global sur tous les feeds connus."""

    feeds: list[FeedAge] = field(default_factory=list)
    stale_threshold_s: float = DEFAULT_STALE_THRESHOLD_S
    db_path: Path = field(default_factory=lambda: Path("db/signatures"))

    @property
    def any_stale(self) -> bool:
        return any(f.stale for f in self.feeds)

    @property
    def all_missing(self) -> bool:
        return all(not f.exists for f in self.feeds)

    @property
    def freshest(self) -> FeedAge | None:
        candidates = [f for f in self.feeds if f.age_seconds is not None]
        if not candidates:
            return None
        return min(candidates, key=lambda f: f.age_seconds)

    @property
    def oldest(self) -> FeedAge | None:
        candidates = [f for f in self.feeds if f.age_seconds is not None]
        if not candidates:
            return None
        return max(candidates, key=lambda f: f.age_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "db_path": str(self.db_path),
            "stale_threshold_s": self.stale_threshold_s,
            "any_stale": self.any_stale,
            "all_missing": self.all_missing,
            "feeds": [f.to_dict() for f in self.feeds],
        }


def read_feed_ages(
    db_path: str | Path = "db/signatures",
    *,
    stale_threshold_s: float = DEFAULT_STALE_THRESHOLD_S,
    now: datetime | None = None,
) -> FeedAgeReport:
    """Lit les `last_update.txt` de tous les feeds connus.

    Args:
        db_path: racine où sont les sous-dossiers de feeds.
        stale_threshold_s: au-delà, marque le feed comme `stale`.
        now: utile en test pour un now déterministe. Sinon `datetime.now()`.

    Renvoie un `FeedAgeReport` même si certains feeds n'existent pas
    (sémantique fail-safe : un déploiement neuf ne crashe pas).
    """
    db_path = Path(db_path)
    now = now or datetime.now()

    report = FeedAgeReport(stale_threshold_s=stale_threshold_s, db_path=db_path)
    for source, subdir, label in KNOWN_FEEDS:
        fdir = db_path / subdir
        last_file = fdir / "last_update.txt"
        feed = FeedAge(
            source=source,
            label=label,
            path=fdir,
            last_update_file=last_file,
            stale_threshold_s=stale_threshold_s,
        )

        if last_file.exists():
            try:
                ts_raw = last_file.read_text(encoding="utf-8").strip()
                ts = datetime.fromisoformat(ts_raw)
                feed.last_update = ts
                feed.age_seconds = max(0.0, (now - ts).total_seconds())
            except (OSError, ValueError) as exc:
                feed.error = f"unreadable_timestamp: {exc}"
                logger.warning("feed_age : %s a un last_update.txt invalide : %s", source, exc)

        feed.ioc_count = _count_iocs_for(fdir, source)
        report.feeds.append(feed)

    return report


def _count_iocs_for(feed_dir: Path, source: str) -> int:
    """Estime le nombre d'IOCs dans les index d'un feed (sans charger)."""
    if not feed_dir.is_dir():
        return 0
    try:
        if source == "malwarebazaar":
            sigs = feed_dir / "signatures.json"
            return _json_keys_count(sigs)
        if source == "urlhaus":
            urls = feed_dir / "urls.json"
            return _json_list_count(urls)
        if source == "threatfox":
            iocs = feed_dir / "iocs.json"
            return _json_list_count(iocs)
    except Exception as exc:
        logger.debug("feed_age : count IOC %s erreur : %s", source, exc)
    return 0


def _json_keys_count(path: Path) -> int:
    """Compte le nombre de clés top-level d'un JSON object. 0 si absent/invalide."""
    if not path.exists():
        return 0
    import json

    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        return len(data) if isinstance(data, dict) else 0
    except (OSError, json.JSONDecodeError):
        return 0


def _json_list_count(path: Path) -> int:
    """Compte le nombre d'éléments d'un JSON array. 0 si absent/invalide."""
    if not path.exists():
        return 0
    import json

    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        return len(data) if isinstance(data, list) else 0
    except (OSError, json.JSONDecodeError):
        return 0


def _human_age(age_seconds: float | None) -> str:
    """Formate un âge en chaîne lisible (j/h/m)."""
    if age_seconds is None:
        return "never"
    if age_seconds < 60:
        return f"{int(age_seconds)}s"
    if age_seconds < 3600:
        return f"{int(age_seconds // 60)}m"
    if age_seconds < 86400:
        h = int(age_seconds // 3600)
        m = int((age_seconds % 3600) // 60)
        return f"{h}h{m:02d}m"
    d = int(age_seconds // 86400)
    h = int((age_seconds % 86400) // 3600)
    return f"{d}d{h:02d}h"


__all__ = [
    "DEFAULT_STALE_THRESHOLD_S",
    "KNOWN_FEEDS",
    "FeedAge",
    "FeedAgeReport",
    "read_feed_ages",
]
