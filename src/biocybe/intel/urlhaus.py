"""Client abuse.ch URLhaus pour BioCybe — feed d'URLs malveillantes.

URLhaus partage des **URLs activement utilisées par des malwares**
(payload delivery, C2, exfiltration, phishing). Format CSV gratuit
téléchargeable sans auth pour les feeds, JSON+auth pour l'API.

Cas d'usage BioCybe :
  - Détection d'IOC URLs dans des fichiers scannés (logs, configs, etc.)
  - Future intégration watcher réseau (Phase 3.e+) qui pourrait
    surveiller le trafic sortant et flagger les connexions vers ces URLs

Pour Phase 3.d on récupère le CSV "recent" (24 dernières heures) et on
en extrait les hostnames + URLs. Stocké dans
`db/signatures/urlhaus/recent.json` pour usage par les futures cellules
réseau.

Doc : https://urlhaus.abuse.ch/api/
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from .abusech import AbuseChAPIError, AbuseChAuthMissing  # réutilise les exceptions

logger = logging.getLogger("biocybe.intel.urlhaus")

DEFAULT_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
DEFAULT_TIMEOUT_S = 60
MAX_CSV_SIZE_BYTES = 50 * 1024 * 1024  # 50 Mo (URLhaus recent < 5 Mo normalement)


@dataclass
class URLHausEntry:
    """Une URL malveillante d'URLhaus (sous-ensemble utile)."""

    url_id: str
    url: str
    hostname: str
    date_added: str
    url_status: str  # "online" | "offline"
    threat: str  # ex. "malware_download"
    tags: list[str]
    reporter: str

    @classmethod
    def from_csv_row(cls, row: dict[str, str]) -> URLHausEntry:
        url = row.get("url", "")
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            hostname = ""
        tags_str = row.get("tags", "")
        tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []
        return cls(
            url_id=row.get("id", ""),
            url=url,
            hostname=hostname,
            date_added=row.get("dateadded", ""),
            url_status=row.get("url_status", ""),
            threat=row.get("threat", ""),
            tags=tags,
            reporter=row.get("reporter", ""),
        )


class URLhausClient:
    """Client minimal pour URLhaus (CSV feed public, pas d'auth requise)."""

    def __init__(
        self,
        feed_url: str = DEFAULT_FEED_URL,
        auth_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        session: requests.Session | None = None,
    ):
        # Auth-Key abuse.ch peut être passée pour limites de rate plus
        # élevées. Le CSV recent est accessible sans auth.
        self.feed_url = feed_url
        self.auth_key = auth_key or os.environ.get("ABUSECH_AUTH_KEY")
        self.timeout = timeout
        self.session = session or requests.Session()

    def _headers(self) -> dict[str, str]:
        h = {
            "User-Agent": "BioCybe/0.2 (+https://github.com/servais1983/biocybe)",
            "Accept": "text/csv,application/csv",
        }
        if self.auth_key:
            h["Auth-Key"] = self.auth_key
        return h

    def fetch_recent(self) -> list[URLHausEntry]:
        """Télécharge le CSV recent (24h) et parse les entrées."""
        resp = self.session.get(self.feed_url, headers=self._headers(), timeout=self.timeout)
        resp.raise_for_status()
        content = resp.content
        if len(content) > MAX_CSV_SIZE_BYTES:
            raise ValueError(
                f"URLhaus CSV anormalement gros ({len(content)} octets > "
                f"{MAX_CSV_SIZE_BYTES}). Refus par défense."
            )

        # Le CSV URLhaus a un header commenté (# ...) puis le vrai CSV.
        # On filtre les lignes commençant par '#'.
        text = content.decode("utf-8", errors="replace")
        # Recherche manuelle de la ligne d'entêtes (commence par "id,")
        data_lines = []
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            data_lines.append(line)
        if not data_lines:
            raise AbuseChAPIError("URLhaus a renvoyé un CSV vide.")

        csv_text = "\n".join(data_lines)
        reader = csv.DictReader(
            io.StringIO(csv_text),
            fieldnames=[
                "id",
                "dateadded",
                "url",
                "url_status",
                "last_online",
                "threat",
                "tags",
                "urlhaus_link",
                "reporter",
            ],
        )
        entries = [URLHausEntry.from_csv_row(row) for row in reader]
        logger.info("URLhaus : %d URLs récupérées du feed recent", len(entries))
        return entries


def update_urlhaus_iocs(
    db_path: str | Path = "db/signatures",
    *,
    auth_key: str | None = None,
    client: URLhausClient | None = None,
) -> dict[str, int]:
    """Met à jour `db/signatures/urlhaus/recent.json` depuis URLhaus.

    Stocke :
      - `urlhaus_urls.json` : liste complète des entrées
      - `urlhaus_hostnames.json` : index hostname → [URLs] pour lookup rapide

    Returns:
        Compteurs : {"fetched", "unique_hostnames", "online"}.

    Raises:
        AbuseChAPIError, requests.HTTPError, ValueError.
    """
    client = client or URLhausClient(auth_key=auth_key)
    entries = client.fetch_recent()

    db_path = Path(db_path)
    urlhaus_dir = db_path / "urlhaus"
    urlhaus_dir.mkdir(parents=True, exist_ok=True)

    urls_file = urlhaus_dir / "urls.json"
    hosts_file = urlhaus_dir / "hostnames.json"

    # Sérialisation
    serialized = [asdict(e) for e in entries]
    with urls_file.open("w", encoding="utf-8") as f:
        json.dump(serialized, f, indent=2, ensure_ascii=False)

    # Index hostname → URL[]
    hosts_index: dict[str, list[str]] = {}
    for e in entries:
        if e.hostname:
            hosts_index.setdefault(e.hostname, []).append(e.url)
    with hosts_file.open("w", encoding="utf-8") as f:
        json.dump(hosts_index, f, indent=2, ensure_ascii=False, sort_keys=True)

    (urlhaus_dir / "last_update.txt").write_text(datetime.now().isoformat(), encoding="utf-8")

    stats = {
        "fetched": len(entries),
        "unique_hostnames": len(hosts_index),
        "online": sum(1 for e in entries if e.url_status == "online"),
    }
    logger.info(
        "URLhaus update : %d URLs (%d uniques hosts, %d online).",
        stats["fetched"],
        stats["unique_hostnames"],
        stats["online"],
    )
    return stats


__all__ = [
    "AbuseChAPIError",
    "AbuseChAuthMissing",
    "URLHausEntry",
    "URLhausClient",
    "update_urlhaus_iocs",
]
